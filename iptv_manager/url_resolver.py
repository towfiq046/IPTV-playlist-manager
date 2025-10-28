# iptv_manager/url_resolver.py

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import aiohttp
from tqdm import tqdm

from .config_loader import C, REPORTS_DIR

REDIRECT_CACHE_FILE = REPORTS_DIR / "redirect_cache.json"
CACHE_EXPIRY_HOURS = 24


def _load_redirect_cache() -> dict:
    """Loads the redirect cache from a file, if it exists."""
    if not REDIRECT_CACHE_FILE.exists():
        return {}
    try:
        return json.loads(REDIRECT_CACHE_FILE.read_text())
    except (json.JSONDecodeError, FileNotFoundError):
        return {}


def _save_redirect_cache(cache: dict):
    """Saves the redirect cache to a file."""
    REDIRECT_CACHE_FILE.write_text(json.dumps(cache, indent=2))


async def _resolve_one_url(session: aiohttp.ClientSession, url: str) -> list[str]:
    """
    Traces a single URL, following all redirects until the final destination.
    Returns the full chain of URLs.
    """
    chain = [url]
    current_url = url
    try:
        for _ in range(10):
            async with session.head(
                current_url,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if 300 <= response.status < 400 and "Location" in response.headers:
                    next_url = response.headers["Location"]
                    # Handle relative redirects
                    if not next_url.startswith("http"):
                        original_parsed = urlparse(current_url)
                        next_url = f"{original_parsed.scheme}://{original_parsed.netloc}{next_url}"
                    chain.append(next_url)
                    current_url = next_url
                else:
                    return chain  # Final destination found
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass  # Network error or timeout, return the chain we have so far
    return chain


async def resolve_and_map_urls(
    all_urls_from_playlists: set[str],
) -> tuple[dict, set, dict]:
    """
    Orchestrates the URL resolution workflow.
    - Uses a cache for performance.
    - Traces redirect chains for unknown URLs.
    - Builds the data structures needed for scanning and cleaning.
    """
    print(f"\n{C.BRIGHT}--- 🕵️  PHASE 1B: RESOLVING & MAPPING URLS ---{C.RESET}")
    cache = _load_redirect_cache()
    now = datetime.now(timezone.utc)
    redirect_map, urls_to_resolve = {}, set()

    # 1. Use cache for fresh entries, mark expired/new URLs for resolution
    for url in all_urls_from_playlists:
        if url in cache:
            cached_data = cache[url]
            last_checked = datetime.fromisoformat(cached_data.get("checked_on"))
            if now - last_checked < timedelta(hours=CACHE_EXPIRY_HOURS):
                redirect_map[url] = cached_data["chain"]
            else:
                urls_to_resolve.add(url)
        else:
            urls_to_resolve.add(url)

    logging.info(
        f"Found {len(redirect_map)} URLs in cache. Need to resolve {len(urls_to_resolve)} new or expired URLs."
    )

    # 2. Asynchronously resolve all new/expired URLs
    if urls_to_resolve:
        pbar = tqdm(
            total=len(urls_to_resolve),
            desc=f"{C.BLUE}🔎 Resolving Redirects{C.RESET}",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
        )
        headers = {"User-Agent": "VLC/3.0.20 (win32/x86_64)"}
        async with aiohttp.ClientSession(headers=headers) as session:
            tasks = [_resolve_one_url(session, url) for url in urls_to_resolve]
            for i, future in enumerate(asyncio.as_completed(tasks)):
                chain = await future
                original_url = list(urls_to_resolve)[i]
                redirect_map[original_url] = chain
                cache[original_url] = {
                    "chain": chain,
                    "checked_on": now.isoformat(),
                }
                pbar.update(1)
        pbar.close()
        _save_redirect_cache(cache)

    # 3. Build the final data structures for the main workflow
    master_domain_list, domain_to_rep_url = set(), {}
    for chain in redirect_map.values():
        for url_in_chain in chain:
            try:
                domain = urlparse(url_in_chain).netloc
                if domain:
                    master_domain_list.add(domain)
                    # The first URL we see for a domain becomes its representative
                    if domain not in domain_to_rep_url:
                        domain_to_rep_url[domain] = url_in_chain
            except (ValueError, AttributeError):
                continue

    print(
        f"Discovered {C.GREEN}{len(master_domain_list)}{C.RESET} total unique domains across all redirect chains."
    )
    return redirect_map, master_domain_list, domain_to_rep_url
