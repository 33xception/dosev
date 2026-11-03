# dosev/server.py – with HTTP/3, health checks, and rate limiting per transport

import asyncio
import base64
import logging
import os
import signal
import ssl
import sys
import urllib.parse
from typing import Dict, Set, Tuple, Optional, Any, List

from aiohttp import web

_DEFAULT_LOG_DIR = os.path.join(os.getenv('LOCALAPPDATA') or os.path.expanduser('~'), 'dosev', 'logs') if os.name == 'nt' else '/var/log/dosev'
MAX_PENDING_UDP_QUERIES = 1024
MAX_ACTIVE_TCP_CONNECTIONS = 1024
MAX_ACTIVE_DOH_REQUESTS = 1024
MAX_ACTIVE_HTTP3_REQUESTS = 1024
MAX_HTTP3_ACTIVE_REQUESTS = 128
MAX_HTTP3_DNS_BODY = 65535

from .resolver import DNSResolver, RateLimiter, MAX_UDP_PAYLOAD
from .utils import fetch_blocklists

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import dns.rcode
import dns.resolver

# HTTP/3 imports
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent


class ResolverHolder:
    def __init__(self, resolver: DNSResolver) -> None:
        self.resolver: DNSResolver = resolver
        self.tcp_tasks: Set[asyncio.Task] = set()
        self.doh_tasks: Set[asyncio.Task] = set()
        self.http3_tasks: Set[asyncio.Task] = set()
        self.http3_protocols: Set[Any] = set()


class UDPResolverProtocol(asyncio.DatagramProtocol):
    def __init__(self, holder: ResolverHolder) -> None:
        self.holder: ResolverHolder = holder
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._tasks: Set[asyncio.Task] = set()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        logging.debug("UDP listener started")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if len(self._tasks) >= MAX_PENDING_UDP_QUERIES:
            logging.warning("Dropping UDP DNS query because the handler limit is full")
            return
        logging.debug(f"Received UDP DNS query from {addr}")
        task = asyncio.create_task(self._handle(data, addr))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def shutdown(self) -> None:
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()

    async def _handle(self, data: bytes, addr: Tuple[str, int]) -> None:
        resolver = self.holder.resolver
        client_ip = addr[0]

        if not await resolver._check_rate_limit(client_ip):
            logging.debug("Rate‑limited UDP query from %s", client_ip)
            return

        try:
            qname: Optional[str] = None
            request_msg: Optional[dns.message.Message] = None
            qtype: Optional[int] = None
            try:
                request_msg = dns.message.from_wire(data)
                if request_msg.question:
                    qname = str(request_msg.question[0].name).rstrip('.')
                    qtype = request_msg.question[0].rdtype
            except Exception:
                qname = None

            if resolver.disable_ipv6 and qtype == dns.rdatatype.AAAA:
                resp_wire = resolver.build_block_response(data, action='NXDOMAIN')
                if self.transport:
                    self.transport.sendto(resp_wire, addr)
                logging.debug(f"Blocked AAAA query for {qname} due to disable_ipv6")
                try:
                    resolver.log_dns_event('Blocked (internal)', qname, f"{addr[0]}:{addr[1]}", 'Disabled IPv6')
                except Exception:
                    pass
                return

            if qname and await resolver.is_blocked(qname):
                action = resolver.get_block_action()
                resp_wire = resolver.build_block_response(data, action=action)
                if self.transport:
                    self.transport.sendto(resp_wire, addr)
                logging.debug(f"Blocked UDP DNS query for {qname} -> action {action}")
                try:
                    resolver.log_dns_event('Blocked (internal)', qname, f"{addr[0]}:{addr[1]}", f"Action={action}")
                except Exception:
                    pass
                return

            response = await resolver.forward_dns_query(
                data, client_ip=client_ip, rate_limit_checked=True
            )

            client_payload = 512
            try:
                req_msg = dns.message.from_wire(data)
                if req_msg.opt:
                    client_payload = max(512, req_msg.payload)
            except Exception:
                pass
            if len(response) > client_payload:
                response = resolver._set_tc_bit(response, client_payload)

            if resolver.strip_ipv6_records:
                response = resolver._strip_ipv6_records(response)

            if self.transport:
                self.transport.sendto(response, addr)
            logging.debug(f"Sent UDP DNS response to {addr}")
            try:
                resolver.log_dns_event('Processed', qname, f"{addr[0]}:{addr[1]}")
            except Exception:
                pass
        except Exception as e:
            logging.error(f"Error handling UDP DNS query from {addr}: {e}")


async def _tcp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       holder: ResolverHolder) -> None:
    if len(holder.tcp_tasks) >= MAX_ACTIVE_TCP_CONNECTIONS:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return
    peer = writer.get_extra_info('peername')
    logging.debug(f"Accepted TCP connection from {peer}")
    resolver = holder.resolver
    client_ip = peer[0] if peer else "unknown"
    handler_task = asyncio.current_task()
    if handler_task is not None:
        holder.tcp_tasks.add(handler_task)
    try:
        while True:
            try:
                length_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=30.0)
                length = int.from_bytes(length_bytes, 'big')
                if length < 12:
                    logging.debug("Invalid TCP DNS message length %d from %s", length, peer)
                    break
                data = await asyncio.wait_for(reader.readexactly(length), timeout=30.0)
            except asyncio.IncompleteReadError:
                break
            except asyncio.TimeoutError:
                logging.debug("TCP read timeout from %s", peer)
                break

            if not await resolver._check_rate_limit(client_ip):
                logging.debug("Rate-limited TCP query from %s", client_ip)
                break

            qname: Optional[str] = None
            qtype: Optional[int] = None
            try:
                request_msg = dns.message.from_wire(data)
                if request_msg.question:
                    qname = str(request_msg.question[0].name).rstrip('.')
                    qtype = request_msg.question[0].rdtype
            except Exception:
                pass

            client_address = f"{client_ip}:{peer[1]}" if peer else client_ip
            if resolver.disable_ipv6 and qtype == dns.rdatatype.AAAA:
                response = resolver.build_block_response(data, action='NXDOMAIN')
                try:
                    resolver.log_dns_event('Blocked (internal)', qname, client_address, 'Disabled IPv6')
                except Exception:
                    pass
            elif qname and await resolver.is_blocked(qname):
                action = resolver.get_block_action()
                response = resolver.build_block_response(data, action=action)
                try:
                    resolver.log_dns_event('Blocked (internal)', qname, client_address, f"Action={action}")
                except Exception:
                    pass
            else:
                response = await resolver.forward_dns_query(
                    data, client_ip=client_ip, rate_limit_checked=True
                )
                if resolver.strip_ipv6_records:
                    response = resolver._strip_ipv6_records(response)
                try:
                    resolver.log_dns_event('Processed', qname, client_address)
                except Exception:
                    pass

            writer.write(len(response).to_bytes(2, 'big') + response)
            await writer.drain()
            logging.debug("Sent TCP DNS response to %s", peer)
    except Exception as e:
        logging.error(f"Error handling TCP DNS query from {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        if handler_task is not None:
            holder.tcp_tasks.discard(handler_task)


async def reload_resolver(holder: ResolverHolder,
                          config: Dict[str, Any],
                          current_resolver: DNSResolver,
                          blocklists: Optional[Dict[str, Any]] = None) -> None:
    await current_resolver.update_config(
        verbose=config.get("verbose", False),
        disable_ipv6=config.get("disable_ipv6", False),
        strip_ipv6_records=config.get("strip_ipv6_records", False),
        udp_timeout=config.get("upstream_udp_timeout"),
        tcp_timeout=config.get("upstream_tcp_timeout"),
        doh_timeout=config.get("upstream_doh_timeout"),
        retries=config.get("upstream_retries"),
        initial_backoff=config.get("upstream_initial_backoff", 0.1),
        pinned_certs=config.get("dns_pinned_certs"),
        dnssec_enabled=config.get("dnssec_enabled", False),
        auto_update_trust_anchor=config.get("auto_update_trust_anchor", True),
        trust_anchors=config.get("trust_anchors_file"),
        dnssec_max_validations=config.get("dnssec_max_validations", 32),
        dnssec_max_dnskey_records=config.get("dnssec_max_dnskey_records", 8),
        dnssec_validation_timeout=config.get("dnssec_validation_timeout", 2.0),
        dnssec_chain_validation=config.get("dnssec_chain_validation", True),
        dnssec_max_iterations=config.get("dnssec_max_iterations", 100),
        scrub_unsolicited_ns=config.get("dns_scrub_unsolicited_ns", True),
        metrics_enabled=config.get("metrics_enabled", False),
        metrics_port=config.get("metrics_port", 8000),
        rate_limit_rps=config.get("rate_limit_rps"),
        rate_limit_burst=config.get("rate_limit_burst"),
        upstreams=config.get("upstreams"),
        optimistic_cache_enabled=config.get("optimistic_cache_enabled"),
        optimistic_stale_max_age=config.get("optimistic_stale_max_age"),
        optimistic_stale_response_ttl=config.get("optimistic_stale_response_ttl"),
        rebind_protection_enabled=config.get("dns_rebind_protection"),
        rebind_action=config.get("dns_rebind_action"),
        ecs_enabled=config.get("dns_ecs_enabled", True),
        max_edns_payload=config.get("dns_max_payload", MAX_UDP_PAYLOAD),
        pool_max_size=config.get("pool_max_size"),
        pool_idle_timeout=config.get("pool_idle_timeout"),
        doh_version=config.get("doh_version"),
        doh_auto_cache_ttl=config.get("doh_auto_cache_ttl"),
        load_balancing=config.get("load_balancing", "failover"),
        bootstrap=config.get("bootstrap"),
        tcp_fallback_enabled=config.get("tcp_fallback_enabled", True),
        health_config=config.get("health"),
        pqc_mode=config.get("pqc_mode", "auto"),
    )

    if blocklists:
        action = blocklists.get('action', 'NXDOMAIN')
        current_resolver.set_block_action(action)
        urls = blocklists.get('urls', []) or []
        local_dir = blocklists.get('local_blocklist_dir', 'blocklists')
        if urls:
            try:
                await fetch_blocklists(urls, destination_dir=local_dir)
                logging.info("Blocklists re‑fetched during config reload")
            except Exception as e:
                logging.warning("Blocklist fetch during reload failed: %s", e)
        try:
            exact_set, suffix_set, hosts_map = current_resolver.load_blocklists_from_dir(local_dir)
            domains = list(exact_set) + ['.' + s for s in suffix_set]
            async with current_resolver._config_lock:
                await current_resolver.set_blocklist(domains)
                await current_resolver.set_hosts_map(hosts_map)
            logging.info("Blocklists reloaded from %s", local_dir)
        except Exception as e:
            logging.warning("Blocklist reload during config update failed: %s", e)

    logging.info("Configuration reloaded successfully")


def _drop_dns_privileges(user: str, group: Optional[str] = None,
                         chroot_dir: Optional[str] = None) -> None:
    try:
        if os.geteuid() != 0:
            return
    except Exception:
        return
    try:
        import pwd, grp
        pw = pwd.getpwnam(user)
        gid = pw.pw_gid if group is None else grp.getgrnam(group).gr_gid
        if chroot_dir:
            try:
                os.chroot(chroot_dir)
                os.chdir('/')
                logging.info('chroot to %s successful', chroot_dir)
            except Exception as e:
                logging.warning('chroot failed: %s', e)
                raise
        try:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(pw.pw_uid)
        except Exception as e:
            logging.warning('Failed to drop privileges: %s', e)
            raise
    except Exception as e:
        logging.error('drop_privileges helper error: %s', e)
        raise


def _create_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    if not cert_file or not key_file:
        raise ValueError('TLS listener requires both cert_file and key_file')
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    try:
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:
        pass
    return ssl_ctx


def _get_client_address(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info('peername')
    return f'{peer[0]}:{peer[1]}' if peer else 'unknown'


async def _handle_doh_request(request: web.Request, holder: ResolverHolder) -> web.Response:
    resolver = holder.resolver
    client_ip = request.remote or 'unknown'

    if not await resolver._check_rate_limit(client_ip):
        return web.Response(status=429, text='Too Many Requests')

    qname: Optional[str] = None
    try:
        if request.method == 'GET':
            dns_param = request.rel_url.query.get('dns')
            if not dns_param:
                return web.Response(status=400, text='Missing dns parameter')
            try:
                padding = '=' * (-len(dns_param) % 4)
                raw_query = base64.urlsafe_b64decode(dns_param + padding)
            except Exception:
                return web.Response(status=400, text='Invalid dns parameter encoding')
        elif request.method == 'POST':
            raw_query = await request.read()
            if request.content_type != 'application/dns-message':
                return web.Response(status=415, text='Unsupported content type')
        else:
            return web.Response(status=405, text='Method Not Allowed')

        try:
            request_msg = dns.message.from_wire(raw_query)
            if request_msg.question:
                qname = str(request_msg.question[0].name).rstrip('.')
        except Exception:
            qname = None

        if resolver.disable_ipv6:
            try:
                request_msg = dns.message.from_wire(raw_query)
                if request_msg.question and request_msg.question[0].rdtype == dns.rdatatype.AAAA:
                    resp_wire = resolver.build_block_response(raw_query, action='NXDOMAIN')
                    return web.Response(body=resp_wire, content_type='application/dns-message')
            except Exception:
                pass

        if qname and await resolver.is_blocked(qname):
            action = resolver.get_block_action()
            resp_wire = resolver.build_block_response(raw_query, action=action)
            try:
                await resolver.log_dns_event('Blocked (internal)', qname, f'{client_ip}', f'Action={action}')
            except Exception:
                pass
            return web.Response(body=resp_wire, content_type='application/dns-message')

        response = await resolver.forward_dns_query(
            raw_query, client_ip=client_ip, rate_limit_checked=True
        )
        if resolver.strip_ipv6_records:
            response = resolver._strip_ipv6_records(response)

        try:
            if qname:
                await resolver.log_dns_event('Processed', qname, f'{client_ip}')
        except Exception:
            pass

        return web.Response(body=response, content_type='application/dns-message')
    except Exception as e:
        logging.error('DoH request handling failed: %s', e)
        return web.Response(status=500, text='Internal Server Error')


async def _start_doh_server(holder: ResolverHolder, listen_ip: str, listen_port: int,
                            doh_path: str, ssl_context: ssl.SSLContext) -> web.AppRunner:
    if not doh_path.startswith('/'):
        doh_path = '/' + doh_path
    @web.middleware
    async def limit_doh_requests(request: web.Request, handler):
        if len(holder.doh_tasks) >= MAX_ACTIVE_DOH_REQUESTS:
            return web.Response(status=503, text='Server Busy')
        task = asyncio.current_task()
        if task is not None:
            holder.doh_tasks.add(task)
        try:
            return await handler(request)
        finally:
            if task is not None:
                holder.doh_tasks.discard(task)

    app = web.Application(
        middlewares=[limit_doh_requests],
        client_max_size=MAX_HTTP3_DNS_BODY,
    )
    app.router.add_route('*', doh_path, lambda request: _handle_doh_request(request, holder))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, listen_ip, listen_port, ssl_context=ssl_context)
    await site.start()
    return runner


# ---------- HTTP/3 Server ----------
class Http3ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_data: Dict[int, bytearray] = {}
        self._request_headers: Dict[int, dict] = {}
        self._request_tasks: Dict[int, asyncio.Task] = {}
        self._rejected_streams: Set[int] = set()
        self._holder: Optional[ResolverHolder] = None
        self._client_ip: str = "unknown"

    def set_holder(self, holder: ResolverHolder) -> None:
        self._holder = holder

    def connection_lost(self, exc) -> None:
        for task in self._request_tasks.values():
            task.cancel()
        if self._holder is not None:
            self._holder.http3_protocols.discard(self)
        super().connection_lost(exc)

    async def shutdown(self) -> None:
        tasks = list(self._request_tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._request_tasks.clear()
        self._request_data.clear()
        self._request_headers.clear()
        self._rejected_streams.clear()

    def datagram_received(self, data: bytes, addr) -> None:
        if addr and isinstance(addr, tuple):
            self._client_ip = addr[0]
        else:
            self._client_ip = "unknown"
        super().datagram_received(data, addr)

    def quic_event_received(self, event: QuicEvent) -> None:
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                if (http_event.stream_id not in self._request_headers
                        and len(self._request_headers) + len(self._request_tasks)
                        >= MAX_HTTP3_ACTIVE_REQUESTS):
                    self._send_response_now(http_event.stream_id, 503, b"Server Busy")
                    if not http_event.stream_ended:
                        self._rejected_streams.add(http_event.stream_id)
                    continue
                headers = {k.decode(): v.decode() for k, v in http_event.headers}
                self._request_headers[http_event.stream_id] = headers
                if http_event.stream_ended:
                    self._schedule_request(http_event.stream_id)
            elif isinstance(http_event, DataReceived):
                if http_event.stream_id in self._rejected_streams:
                    if http_event.stream_ended:
                        self._rejected_streams.discard(http_event.stream_id)
                    continue
                if http_event.stream_id not in self._request_data:
                    self._request_data[http_event.stream_id] = bytearray()
                if len(self._request_data[http_event.stream_id]) + len(http_event.data) > MAX_HTTP3_DNS_BODY:
                    self._request_data.pop(http_event.stream_id, None)
                    self._request_headers.pop(http_event.stream_id, None)
                    self._send_response_now(http_event.stream_id, 413, b"DNS message too large")
                    if not http_event.stream_ended:
                        self._rejected_streams.add(http_event.stream_id)
                    continue
                self._request_data[http_event.stream_id].extend(http_event.data)
                if http_event.stream_ended:
                    self._schedule_request(http_event.stream_id)

    def _schedule_request(self, stream_id: int) -> None:
        if stream_id in self._request_tasks:
            return
        if self._holder is not None and len(self._holder.http3_tasks) >= MAX_ACTIVE_HTTP3_REQUESTS:
            self._request_headers.pop(stream_id, None)
            self._request_data.pop(stream_id, None)
            self._send_response_now(stream_id, 503, b"Server Busy")
            return
        task = asyncio.create_task(self._handle_request(stream_id))
        self._request_tasks[stream_id] = task
        if self._holder is not None:
            self._holder.http3_tasks.add(task)

        def finish(completed: asyncio.Task) -> None:
            self._request_tasks.pop(stream_id, None)
            if self._holder is not None:
                self._holder.http3_tasks.discard(completed)
            if not completed.cancelled() and completed.exception() is not None:
                logging.error("HTTP/3 request task failed", exc_info=completed.exception())

        task.add_done_callback(finish)

    async def _handle_request(self, stream_id: int):
        headers = self._request_headers.get(stream_id, {})
        body = bytes(self._request_data.get(stream_id, b""))
        self._request_headers.pop(stream_id, None)
        self._request_data.pop(stream_id, None)

        if not self._holder:
            return

        resolver = self._holder.resolver
        client_ip = getattr(self, "_client_ip", "unknown")

        if not await resolver._check_rate_limit(client_ip):
            await self._send_response(stream_id, 429, b"Too Many Requests")
            return

        method = headers.get(":method", "GET")
        path = headers.get(":path", "/dns-query")

        raw_query = None
        if method == "GET":
            parsed = urllib.parse.urlparse(path)
            query_params = urllib.parse.parse_qs(parsed.query)
            dns_param = query_params.get("dns", [None])[0]
            if dns_param:
                try:
                    padding = '=' * (-len(dns_param) % 4)
                    raw_query = base64.urlsafe_b64decode(dns_param + padding)
                except Exception:
                    await self._send_response(stream_id, 400, b"Invalid dns parameter")
                    return
        elif method == "POST":
            content_type = headers.get("content-type", "")
            if content_type != "application/dns-message":
                await self._send_response(stream_id, 415, b"Unsupported content type")
                return
            raw_query = body

        if raw_query is None:
            await self._send_response(stream_id, 400, b"Missing dns query")
            return

        try:
            response = await resolver.forward_dns_query(
                raw_query, client_ip=client_ip, rate_limit_checked=True
            )
            if resolver.strip_ipv6_records:
                response = resolver._strip_ipv6_records(response)
            await self._send_response(stream_id, 200, response, content_type="application/dns-message")
        except Exception as e:
            logging.error(f"HTTP/3 request failed: {e}")
            await self._send_response(stream_id, 500, b"Internal Server Error")

    async def _send_response(self, stream_id: int, status: int, body: bytes, content_type: str = "text/plain"):
        self._send_response_now(stream_id, status, body, content_type)

    def _send_response_now(self, stream_id: int, status: int, body: bytes,
                           content_type: str = "text/plain") -> None:
        headers = [
            (b":status", str(status).encode()),
            (b"content-type", content_type.encode()),
            (b"content-length", str(len(body)).encode()),
        ]
        self._http.send_headers(stream_id, headers, end_stream=False)
        if body:
            self._http.send_data(stream_id, body, end_stream=True)
        else:
            self._http.send_data(stream_id, b"", end_stream=True)
        self.transmit()

    def transmit(self):
        self._quic.transmit()


async def _start_http3_server(holder: ResolverHolder, listen_ip: str, listen_port: int,
                                cert_file: str, key_file: str, doh_path: str = "/dns-query") -> None:
    with open(cert_file, 'rb') as f:
        cert_data = f.read()
    with open(key_file, 'rb') as f:
        key_data = f.read()

    config = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
        certificate=cert_data,
        private_key=key_data,
    )

    def create_protocol(*args, **kwargs):
        proto = Http3ServerProtocol(*args, **kwargs)
        proto.set_holder(holder)
        holder.http3_protocols.add(proto)
        return proto

    await serve(host=listen_ip, port=listen_port, configuration=config,
                create_protocol=create_protocol)


# ---------- Main Server ----------
async def run_server(listen_ip: str, listen_port: int,
                     verbose: bool = False,
                     blocklists: Optional[Dict[str, Any]] = None,
                     disable_ipv6: bool = False,
                     strip_ipv6_records: bool = False,
                     dns_cache_ttl: int = 300,
                     dns_cache_max_size: int = 1024,
                     dns_negative_cache_ttl: int = 5,
                     dns_logging_enabled: bool = False,
                     dns_log_retention_days: int = 7,
                     dns_log_dir: str = _DEFAULT_LOG_DIR,
                     dns_log_prefix: str = 'dns-log',
                     dns_pinned_certs: Optional[Dict[str, str]] = None,
                     dnssec_enabled: bool = False,
                     auto_update_trust_anchor: bool = True,
                     trust_anchors_file: Optional[str] = None,
                     dnssec_max_validations: int = 32,
                     dnssec_max_dnskey_records: int = 8,
                     dnssec_validation_timeout: float = 2.0,
                     dnssec_chain_validation: bool = True,
                     dnssec_max_iterations: int = 100,
                     dns_scrub_unsolicited_ns: bool = True,
                     metrics_enabled: bool = False,
                     metrics_port: int = 8000,
                     uvloop_enable: bool = False,
                     upstream_retries: int = 2,
                     upstream_initial_backoff: float = 0.1,
                     upstream_udp_timeout: float = 2.0,
                     upstream_tcp_timeout: float = 5.0,
                     upstream_doh_timeout: float = 5.0,
                     rate_limit_rps: float = 0.0,
                     rate_limit_burst: float = 0.0,
                     upstreams: Optional[List[Dict[str, Any]]] = None,
                     optimistic_cache_enabled: bool = False,
                     optimistic_stale_max_age: int = 86400,
                     optimistic_stale_response_ttl: int = 30,
                     dns_privilege_drop_user: str = '',
                     dns_privilege_drop_group: str = '',
                     dns_chroot_dir: str = '',
                     dns_rebind_protection: bool = False,
                     dns_rebind_action: str = 'strip',
                     dns_ecs_enabled: bool = True,
                     dns_max_payload: int = MAX_UDP_PAYLOAD,
                     dns_enable_dot: bool = False,
                     dns_dot_port: int = 853,
                     dns_dot_cert_file: str = '',
                     dns_dot_key_file: str = '',
                     dns_enable_doh: bool = False,
                     dns_doh_port: int = 443,
                     dns_doh_cert_file: str = '',
                     dns_doh_key_file: str = '',
                     dns_doh_path: str = '/dns-query',
                     pool_max_size: int = 5,
                     pool_idle_timeout: float = 60.0,
                     doh_version: str = 'auto',
                     doh_auto_cache_ttl: int = 3600,
                     load_balancing: str = 'failover',
                     bootstrap: Optional[Dict[str, Any]] = None,
                     dns_enable_http3: bool = False,
                     tcp_fallback_enabled: bool = True,
                     health_config: Optional[Dict[str, Any]] = None,
                     pqc_mode: str = 'auto') -> None:

    logging.getLogger().setLevel(logging.DEBUG if verbose else logging.INFO)

    resolver = DNSResolver(
        upstreams=upstreams,
        verbose=verbose,
        disable_ipv6=disable_ipv6,
        strip_ipv6_records=strip_ipv6_records,
        pqc_mode=pqc_mode,
        cache_ttl=dns_cache_ttl,
        cache_max_size=dns_cache_max_size,
        negative_cache_ttl=dns_negative_cache_ttl,
        doh_timeout=upstream_doh_timeout,
        udp_timeout=upstream_udp_timeout,
        tcp_timeout=upstream_tcp_timeout,
        retries=upstream_retries,
        initial_backoff=upstream_initial_backoff,
        dns_logging_enabled=dns_logging_enabled,
        dns_log_dir=dns_log_dir,
        dns_log_prefix=dns_log_prefix,
        dns_log_retention_days=dns_log_retention_days,
        pinned_certs=dns_pinned_certs,
        dnssec_enabled=dnssec_enabled,
        auto_update_trust_anchor=auto_update_trust_anchor,
        trust_anchors=None if not trust_anchors_file else trust_anchors_file,
        dnssec_max_validations=dnssec_max_validations,
        dnssec_max_dnskey_records=dnssec_max_dnskey_records,
        dnssec_validation_timeout=dnssec_validation_timeout,
        dnssec_chain_validation=dnssec_chain_validation,
        dnssec_max_iterations=dnssec_max_iterations,
        scrub_unsolicited_ns=dns_scrub_unsolicited_ns,
        metrics_enabled=metrics_enabled,
        metrics_port=metrics_port,
        uvloop_enable=uvloop_enable,
        rate_limit_rps=rate_limit_rps,
        rate_limit_burst=rate_limit_burst,
        optimistic_cache_enabled=optimistic_cache_enabled,
        optimistic_stale_max_age=optimistic_stale_max_age,
        optimistic_stale_response_ttl=optimistic_stale_response_ttl,
        rebind_protection_enabled=dns_rebind_protection,
        rebind_action=dns_rebind_action,
        ecs_enabled=dns_ecs_enabled,
        max_edns_payload=dns_max_payload,
        pool_max_size=pool_max_size,
        pool_idle_timeout=pool_idle_timeout,
        doh_version=doh_version,
        doh_auto_cache_ttl=doh_auto_cache_ttl,
        load_balancing=load_balancing,
        bootstrap=bootstrap,
        tcp_fallback_enabled=tcp_fallback_enabled,
        health_config=health_config,
    )

    holder = ResolverHolder(resolver)
    loop = asyncio.get_running_loop()

    await resolver.start_background_tasks()

    if blocklists is None:
        blocklists = {}

    action = blocklists.get('action', 'NXDOMAIN')
    resolver.set_block_action(action)
    urls = blocklists.get('urls', []) or []
    local_dir = blocklists.get('local_blocklist_dir', 'blocklists')

    if urls:
        try:
            await fetch_blocklists(urls, destination_dir=local_dir)
            logging.info("Blocklists fetched on startup")
        except Exception as e:
            logging.warning("Blocklist fetch failed on startup: %s", e)
        try:
            exact_set, suffix_set, hosts_map = resolver.load_blocklists_from_dir(local_dir)
            domains = list(exact_set) + ['.' + s for s in suffix_set]
            async with resolver._config_lock:
                await resolver.set_blocklist(domains)
                await resolver.set_hosts_map(hosts_map)
            logging.info("Blocklists loaded from %s", local_dir)
        except Exception as e:
            logging.warning("Blocklist load failed on startup: %s", e)

    if blocklists.get('enabled') and urls:
        interval = blocklists.get('interval_seconds', 86400)
        async def periodic_reload() -> None:
            while True:
                await asyncio.sleep(interval)
                try:
                    await fetch_blocklists(urls, destination_dir=local_dir)
                    exact_set, suffix_set, hosts_map = resolver.load_blocklists_from_dir(local_dir)
                    domains = list(exact_set) + ['.' + s for s in suffix_set]
                    async with resolver._config_lock:
                        await resolver.set_blocklist(domains)
                        await resolver.set_hosts_map(hosts_map)
                    logging.debug("Blocklists reloaded")
                except Exception as e:
                    logging.warning("Periodic blocklist reload failed: %s", e)
        periodic_reload_task = loop.create_task(periodic_reload())
        logging.info("Scheduled periodic blocklist refresh every %s seconds", interval)
    else:
        periodic_reload_task = None

    udp_transport, udp_protocol = await loop.create_datagram_endpoint(
        lambda: UDPResolverProtocol(holder),
        local_addr=(listen_ip, listen_port)
    )
    logging.info(f"DNS UDP listener running on {listen_ip}:{listen_port}")

    server = await asyncio.start_server(
        lambda r, w: _tcp_handler(r, w, holder),
        listen_ip, listen_port
    )
    logging.info(f"DNS TCP listener running on {listen_ip}:{listen_port}")

    dot_server = None
    doh_runner = None
    http3_task = None

    if dns_enable_dot:
        dot_ssl = _create_ssl_context(dns_dot_cert_file, dns_dot_key_file)
        dot_server = await asyncio.start_server(
            lambda r, w: _tcp_handler(r, w, holder),
            listen_ip, dns_dot_port, ssl=dot_ssl
        )
        logging.info(f"DNS-over-TLS listener running on {listen_ip}:{dns_dot_port}")

    if dns_enable_doh:
        doh_ssl = _create_ssl_context(dns_doh_cert_file, dns_doh_key_file)
        doh_runner = await _start_doh_server(holder, listen_ip, dns_doh_port, dns_doh_path, doh_ssl)
        logging.info(f"DNS-over-HTTPS (HTTP/1.1 & HTTP/2) listener running on {listen_ip}:{dns_doh_port}{dns_doh_path}")

    if dns_enable_http3:
        if not dns_doh_cert_file or not dns_doh_key_file:
            logging.warning("HTTP/3 requires cert_file and key_file; skipping")
        else:
            http3_task = asyncio.create_task(
                _start_http3_server(holder, listen_ip, dns_doh_port, dns_doh_cert_file, dns_doh_key_file, dns_doh_path)
            )
            logging.info(f"DNS-over-HTTPS (HTTP/3) listener starting on {listen_ip}:{dns_doh_port}{dns_doh_path}")

    if dns_privilege_drop_user:
        _drop_dns_privileges(
            user=dns_privilege_drop_user,
            group=dns_privilege_drop_group or None,
            chroot_dir=dns_chroot_dir or None
        )

    shutdown_event = asyncio.Event()

    def handle_signal(signum, frame):
        logging.info("Received signal %s, shutting down...", signum)
        shutdown_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, handle_signal, signal.SIGINT, None)
        loop.add_signal_handler(signal.SIGTERM, handle_signal, signal.SIGTERM, None)
    except NotImplementedError:
        logging.warning("Signal handlers are not supported on this platform")

    serve_task = asyncio.create_task(server.serve_forever())
    shutdown_task = asyncio.create_task(shutdown_event.wait())

    try:
        await asyncio.wait([serve_task, shutdown_task], return_when=asyncio.FIRST_COMPLETED)
    except asyncio.CancelledError:
        pass
    finally:
        if not serve_task.done():
            serve_task.cancel()
        if not shutdown_task.done():
            shutdown_task.cancel()
        logging.info("Shutting down gracefully...")
        if periodic_reload_task is not None:
            periodic_reload_task.cancel()
            await asyncio.gather(periodic_reload_task, return_exceptions=True)
        udp_transport.close()
        if udp_protocol is not None:
            await udp_protocol.shutdown()
        if dot_server is not None:
            dot_server.close()
            await dot_server.wait_closed()
        server.close()
        await server.wait_closed()
        if doh_runner is not None:
            await doh_runner.cleanup()
        doh_tasks = list(holder.doh_tasks)
        for task in doh_tasks:
            task.cancel()
        if doh_tasks:
            await asyncio.gather(*doh_tasks, return_exceptions=True)
        tcp_tasks = list(holder.tcp_tasks)
        for task in tcp_tasks:
            task.cancel()
        if tcp_tasks:
            await asyncio.gather(*tcp_tasks, return_exceptions=True)
        if http3_task is not None:
            http3_task.cancel()
            await asyncio.gather(http3_task, return_exceptions=True)
        if holder.http3_protocols:
            await asyncio.gather(
                *(protocol.shutdown() for protocol in holder.http3_protocols),
                return_exceptions=True,
            )
            holder.http3_protocols.clear()
        await resolver.shutdown(stop_prometheus=True)
        await asyncio.gather(serve_task, shutdown_task, return_exceptions=True)
        logging.info("Shutdown complete.")


def run_server_sync(listen_ip: str, listen_port: int,
                    verbose: bool = False,
                    blocklists: Optional[Dict[str, Any]] = None,
                    disable_ipv6: bool = False,
                    strip_ipv6_records: bool = False,
                    dns_cache_ttl: int = 300,
                    dns_cache_max_size: int = 1024,
                    dns_negative_cache_ttl: int = 5,
                    dns_logging_enabled: bool = False,
                    dns_log_retention_days: int = 7,
                    dns_log_dir: str = _DEFAULT_LOG_DIR,
                    dns_log_prefix: str = 'dns-log',
                    dns_pinned_certs: Optional[Dict[str, str]] = None,
                    dnssec_enabled: bool = False,
                    auto_update_trust_anchor: bool = True,
                    trust_anchors_file: Optional[str] = None,
                    dnssec_max_validations: int = 32,
                    dnssec_max_dnskey_records: int = 8,
                    dnssec_validation_timeout: float = 2.0,
                    dnssec_chain_validation: bool = True,
                    dnssec_max_iterations: int = 100,
                    dns_scrub_unsolicited_ns: bool = True,
                    pqc_mode: str = 'auto',
                    metrics_enabled: bool = False,
                    metrics_port: int = 8000,
                    uvloop_enable: bool = False,
                    upstream_retries: int = 2,
                    upstream_initial_backoff: float = 0.1,
                    upstream_udp_timeout: float = 2.0,
                    upstream_tcp_timeout: float = 5.0,
                    upstream_doh_timeout: float = 5.0,
                    rate_limit_rps: float = 0.0,
                    rate_limit_burst: float = 0.0,
                    upstreams: Optional[List[Dict[str, Any]]] = None,
                    optimistic_cache_enabled: bool = False,
                    optimistic_stale_max_age: int = 86400,
                    optimistic_stale_response_ttl: int = 30,
                    dns_privilege_drop_user: str = '',
                    dns_privilege_drop_group: str = '',
                    dns_chroot_dir: str = '',
                    dns_rebind_protection: bool = False,
                    dns_rebind_action: str = 'strip',
                    dns_ecs_enabled: bool = True,
                    dns_max_payload: int = MAX_UDP_PAYLOAD,
                    dns_enable_dot: bool = False,
                    dns_dot_port: int = 853,
                    dns_dot_cert_file: str = '',
                    dns_dot_key_file: str = '',
                    dns_enable_doh: bool = False,
                    dns_doh_port: int = 443,
                    dns_doh_cert_file: str = '',
                    dns_doh_key_file: str = '',
                    dns_doh_path: str = '/dns-query',
                    pool_max_size: int = 5,
                    pool_idle_timeout: float = 60.0,
                    doh_version: str = 'auto',
                    doh_auto_cache_ttl: int = 3600,
                    load_balancing: str = 'failover',
                    bootstrap: Optional[Dict[str, Any]] = None,
                    dns_enable_http3: bool = False,
                    tcp_fallback_enabled: bool = True,
                    health_config: Optional[Dict[str, Any]] = None) -> None:
    asyncio.run(run_server(
        listen_ip, listen_port,
        verbose=verbose,
        blocklists=blocklists,
        disable_ipv6=disable_ipv6,
        strip_ipv6_records=strip_ipv6_records,
        dns_cache_ttl=dns_cache_ttl,
        dns_cache_max_size=dns_cache_max_size,
        dns_negative_cache_ttl=dns_negative_cache_ttl,
        dns_logging_enabled=dns_logging_enabled,
        dns_log_retention_days=dns_log_retention_days,
        dns_log_dir=dns_log_dir,
        dns_log_prefix=dns_log_prefix,
        dns_pinned_certs=dns_pinned_certs,
        dnssec_enabled=dnssec_enabled,
        auto_update_trust_anchor=auto_update_trust_anchor,
        trust_anchors_file=trust_anchors_file,
        dnssec_max_validations=dnssec_max_validations,
        dnssec_max_dnskey_records=dnssec_max_dnskey_records,
        dnssec_validation_timeout=dnssec_validation_timeout,
        dnssec_chain_validation=dnssec_chain_validation,
        dnssec_max_iterations=dnssec_max_iterations,
        dns_scrub_unsolicited_ns=dns_scrub_unsolicited_ns,
        metrics_enabled=metrics_enabled,
        metrics_port=metrics_port,
        uvloop_enable=uvloop_enable,
        upstream_retries=upstream_retries,
        upstream_initial_backoff=upstream_initial_backoff,
        upstream_udp_timeout=upstream_udp_timeout,
        upstream_tcp_timeout=upstream_tcp_timeout,
        upstream_doh_timeout=upstream_doh_timeout,
        rate_limit_rps=rate_limit_rps,
        rate_limit_burst=rate_limit_burst,
        upstreams=upstreams,
        optimistic_cache_enabled=optimistic_cache_enabled,
        optimistic_stale_max_age=optimistic_stale_max_age,
        optimistic_stale_response_ttl=optimistic_stale_response_ttl,
        dns_privilege_drop_user=dns_privilege_drop_user,
        dns_privilege_drop_group=dns_privilege_drop_group,
        dns_chroot_dir=dns_chroot_dir,
        dns_rebind_protection=dns_rebind_protection,
        dns_rebind_action=dns_rebind_action,
        dns_ecs_enabled=dns_ecs_enabled,
        dns_max_payload=dns_max_payload,
        dns_enable_dot=dns_enable_dot,
        dns_dot_port=dns_dot_port,
        dns_dot_cert_file=dns_dot_cert_file,
        dns_dot_key_file=dns_dot_key_file,
        dns_enable_doh=dns_enable_doh,
        dns_doh_port=dns_doh_port,
        dns_doh_cert_file=dns_doh_cert_file,
        dns_doh_key_file=dns_doh_key_file,
        dns_doh_path=dns_doh_path,
        pool_max_size=pool_max_size,
        pool_idle_timeout=pool_idle_timeout,
        doh_version=doh_version,
        doh_auto_cache_ttl=doh_auto_cache_ttl,
        load_balancing=load_balancing,
        bootstrap=bootstrap,
        dns_enable_http3=dns_enable_http3,
        tcp_fallback_enabled=tcp_fallback_enabled,
        health_config=health_config,
    ))