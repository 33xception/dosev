# dosev/utils.py – streaming fetch (same as before)

import asyncio
import os
import logging
import tempfile
from typing import List
from urllib.parse import unquote, urlsplit

import aiohttp
import aiohttp.client_exceptions

async def fetch_blocklists(urls: List[str], destination_dir: str = "blocklists") -> None:
    """
    Download each URL and save it as a file inside destination_dir.
    Filename is derived from the URL's last part (e.g., 'domainlist.txt').
    Uses streaming to avoid loading large files into memory.
    """
    os.makedirs(destination_dir, exist_ok=True)
    async with aiohttp.ClientSession() as session:
        for url in urls:
            if not url.strip():
                continue
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        logging.warning("Failed to fetch %s: HTTP %s", url, resp.status)
                        continue
                    filename = os.path.basename(unquote(urlsplit(url).path)) or 'blocklist.txt'
                    filepath = os.path.join(destination_dir, filename)
                    file_descriptor, temporary_path = tempfile.mkstemp(
                        dir=destination_dir, prefix=f'.{filename}.', suffix='.tmp'
                    )
                    try:
                        with os.fdopen(file_descriptor, 'w', encoding='utf-8') as f:
                            content = getattr(resp, 'content', None)
                            if content is None and hasattr(resp, 'text'):
                                await asyncio.to_thread(f.write, await resp.text())
                            elif hasattr(content, 'iter_chunked'):
                                async for chunk in content.iter_chunked(65536):
                                    if chunk:
                                        text = chunk.decode('utf-8', errors='ignore')
                                        await asyncio.to_thread(f.write, text)
                            else:
                                async for chunk, _ in content.iter_chunks():
                                    if chunk:
                                        text = chunk.decode('utf-8', errors='ignore')
                                        await asyncio.to_thread(f.write, text)
                        os.replace(temporary_path, filepath)
                        temporary_path = ''
                    finally:
                        if temporary_path and os.path.exists(temporary_path):
                            os.remove(temporary_path)
                    logging.debug("Saved blocklist %s -> %s", url, filepath)
            except asyncio.TimeoutError:
                logging.warning("Timeout fetching %s", url)
            except aiohttp.client_exceptions.ClientError as e:
                logging.warning("Client error fetching %s: %s", url, e)
            except Exception as e:
                logging.warning("Unexpected error fetching %s: %s", url, e)