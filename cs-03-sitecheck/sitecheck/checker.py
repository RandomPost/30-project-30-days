"""Async orchestration. Network pieces are injected so tests can mock them."""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable

import httpx

from .headers import analyze_headers
from .models import Issue, SiteResult, TlsInfo
from .scoring import score
from .tls import evaluate_tls, fetch_tls

TlsFetcher = Callable[[str, float], Awaitable[TlsInfo]]


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    for prefix in ("https://", "http://"):
        d = d.removeprefix(prefix)
    return d.split("/")[0]


async def _default_tls(domain: str, timeout: float) -> TlsInfo:
    return await fetch_tls(domain, timeout=timeout)


async def check_site(
    domain: str,
    client: httpx.AsyncClient,
    tls_fetcher: TlsFetcher = _default_tls,
    timeout: float = 10.0,
) -> SiteResult:
    result = SiteResult(domain)
    try:
        result.tls = await tls_fetcher(domain, timeout)
        result.issues += evaluate_tls(result.tls)
        resp = await client.get(f"https://{domain}/", timeout=timeout)
    except (OSError, asyncio.TimeoutError, httpx.HTTPError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.issues.append(
            Issue(
                "Reachability",
                100,
                f"Could not complete a verified HTTPS request ({result.error})",
                "Check DNS, that port 443 is open and that the certificate chain "
                "is valid.",
                fatal=True,
            )
        )
    else:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = resp.headers.get_list("set-cookie")
        result.issues += analyze_headers(headers, cookies)
    result.score, result.grade = score(result.issues)
    return result


async def check_all(
    domains: list[str],
    tls_fetcher: TlsFetcher = _default_tls,
    timeout: float = 10.0,
    concurrency: int = 10,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[SiteResult]:
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(
        transport=transport, follow_redirects=True, headers={"User-Agent": "sitecheck"}
    ) as client:

        async def one(d: str) -> SiteResult:
            async with sem:
                return await check_site(d, client, tls_fetcher, timeout)

        return list(await asyncio.gather(*(one(normalize_domain(d)) for d in domains)))
