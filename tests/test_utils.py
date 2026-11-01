"""
Consolidated utils tests.
Combines: test_utils.py, test_utils_extra.py
"""
import os
import asyncio
import aiohttp
import pytest
from dosev.utils import fetch_blocklists


@pytest.mark.asyncio
async def test_fetch_blocklists_creates_files(tmp_path, monkeypatch):
    called = {}

    class FakeChunkStream:
        async def iter_chunks(self):
            yield (b'example.com', False)

        async def iter_chunked(self, n):
            yield b'example.com'

    class FakeResponse:
        def __init__(self, text, status=200):
            self._text = text
            self.status = status
            self.content = FakeChunkStream()

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class FakeSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            called['url'] = url
            return FakeResponse('example.com')

    monkeypatch.setattr(aiohttp, 'ClientSession', FakeSession)

    destination = tmp_path / "blocklists"
    await fetch_blocklists(["https://example.com/list.txt"], destination_dir=str(destination))
    assert os.path.exists(destination / "list.txt")
    with open(destination / "list.txt", "r", encoding="utf-8") as f:
        assert f.read() == 'example.com'


@pytest.mark.asyncio
async def test_fetch_blocklists_skips_non_200_and_handles_errors(monkeypatch, tmp_path):
    destination = tmp_path / "blocklists"

    class FakeResponse:
        def __init__(self, status=200, text="ok"):
            self.status = status
            self._text = text

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def text(self):
            return self._text

    class FakeSession:
        def __init__(self):
            self.calls = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            self.calls.append(url)
            if url.endswith("bad"):
                return FakeResponse(status=404)
            if url.endswith("timeout"):
                raise asyncio.TimeoutError()
            if url.endswith("client"):
                raise aiohttp.ClientError("client")
            if url.endswith("oops"):
                raise RuntimeError("oops")
            return FakeResponse(text="content")

    monkeypatch.setattr(aiohttp, "ClientSession", FakeSession)
    await fetch_blocklists(
        [
            "https://example.com/good",
            "https://example.com/bad",
            "https://example.com/timeout",
            "https://example.com/client",
            "https://example.com/oops",
        ],
        destination_dir=str(destination),
    )

    assert (destination / "good").exists()
    assert not (destination / "bad").exists()


@pytest.mark.asyncio
async def test_failed_blocklist_download_preserves_existing_file(monkeypatch, tmp_path):
    destination = tmp_path / "blocklists"
    destination.mkdir()
    existing = destination / "list.txt"
    existing.write_text("previous list", encoding="utf-8")

    class BrokenStream:
        async def iter_chunked(self, size):
            yield b"partial"
            raise RuntimeError("interrupted")

    class Response:
        status = 200
        content = BrokenStream()

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            return Response()

    monkeypatch.setattr(aiohttp, "ClientSession", Session)
    await fetch_blocklists(["https://example.com/list.txt?token=value"], str(destination))

    assert existing.read_text(encoding="utf-8") == "previous list"
    assert sorted(path.name for path in destination.iterdir()) == ["list.txt"]