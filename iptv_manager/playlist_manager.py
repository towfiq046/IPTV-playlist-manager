import asyncio
import re
from datetime import datetime

import aiohttp
from tqdm import tqdm

from .config_loader import (
    INPUT_DIR,
    PLAYLIST_CONFIG_FILE,
    C,
    get_config,
    load_json_config,
)

CONFIG = get_config()


async def _fetch_and_save_playlist(session, filename, url):
    """Coroutine to fetch a single playlist and save it to the input directory."""
    save_path = INPUT_DIR / filename
    try:
        timeout = aiohttp.ClientTimeout(
            total=CONFIG["network_settings"].get("playlist_timeout_seconds", 30)
        )
        async with session.get(url, timeout=timeout) as response:
            response.raise_for_status()
            content = await response.text(encoding="utf-8", errors="ignore")
            # Run the synchronous file write operation in a separate thread
            await asyncio.to_thread(save_path.write_text, content, encoding="utf-8")
            return filename, "success"
    except (aiohttp.ClientError, asyncio.TimeoutError):
        if save_path.exists():
            last_mod_time = datetime.fromtimestamp(save_path.stat().st_mtime).strftime(
                "%Y-%m-%d"
            )
            return filename, f"fetch_failed_using_local_{last_mod_time}"
        else:
            return filename, "fetch_failed_no_local"
    except Exception as e:
        return filename, f"error_{e}"


async def _run_all_fetches(playlists_to_fetch: dict):
    """Manages the concurrent fetching of all remote playlists."""
    headers = {"User-Agent": "VLC/3.0.20 (win32/x86_64)"}
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [
            _fetch_and_save_playlist(session, filename, url)
            for filename, url in playlists_to_fetch.items()
        ]
        pbar = tqdm(
            total=len(tasks),
            desc=f"{C.GREEN}📥 Fetching Remotes{C.RESET}",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
        )
        for future in asyncio.as_completed(tasks):
            filename, status = await future
            if status == "success":
                pbar.set_description_str(
                    f"{C.GREEN}✅ Fetched {filename[:20]:<20}{C.RESET}"
                )
            elif "fetch_failed_using_local" in status:
                date_str = status.split("_")[-1]
                pbar.set_description_str(
                    f"{C.YELLOW}⚠️ Using local {filename[:20]:<20} (from {date_str}){C.RESET}"
                )
            else:
                pbar.set_description_str(
                    f"{C.RED}❌ FAILED {filename[:20]:<20}{C.RESET}"
                )
            pbar.update(1)
        pbar.close()


def fetch_playlists() -> dict:
    """
    Gathers all playlists by fetching remotes CONCURRENTLY and then scanning the input directory.
    Returns a dictionary of {filename: content}.
    """
    print(f"\n{C.BRIGHT}--- ⏯️  PHASE 1A: GATHERING & READING PLAYLISTS ---{C.RESET}")

    # --- Step 1: Concurrently fetch remote playlists defined in the config ---
    playlists_to_fetch = load_json_config(PLAYLIST_CONFIG_FILE, default={})
    if playlists_to_fetch:
        print(
            f"{C.BLUE}INFO: Fetching {len(playlists_to_fetch)} remote playlists from '{PLAYLIST_CONFIG_FILE.name}'...{C.RESET}"
        )
        asyncio.run(_run_all_fetches(playlists_to_fetch))
    else:
        print(
            f"{C.YELLOW}INFO: No remote playlists defined in '{PLAYLIST_CONFIG_FILE.name}'.{C.RESET}"
        )

    # --- Step 2: Scan the input directory and READ all .m3u and .m3u8 files ---
    print(
        f"{C.BLUE}INFO: Scanning and reading all playlists from '{INPUT_DIR.name}/'...{C.RESET}"
    )
    all_playlist_content = {}

    playlist_paths = sorted(INPUT_DIR.glob("*.m3u*"))
    for playlist_path in playlist_paths:
        if playlist_path.is_file():
            try:
                content = playlist_path.read_text(encoding="utf-8", errors="ignore")
                all_playlist_content[playlist_path.name] = content
            except Exception as e:
                print(
                    f"{C.RED}ERROR: Could not read file {playlist_path.name}: {e}{C.RESET}"
                )

    if not all_playlist_content:
        print(
            f"{C.RED}ERROR: No playlists found or could be read.{C.RESET} Place .m3u files in the '{INPUT_DIR.name}/' directory or define them in 'playlists.json'."
        )
        return {}

    found_count = len(all_playlist_content)
    print(
        f"Found and read {C.GREEN}{found_count}{C.RESET} total playlists into memory."
    )
    return all_playlist_content


async def check_link_health(session, url):
    """
    --- MODIFIED: Now checks status and Content-Type for a more accurate health check. ---
    A link is "live" if it returns a 2xx status AND a valid stream content type.
    """
    timeout = aiohttp.ClientTimeout(
        total=CONFIG["network_settings"].get("link_check_timeout_seconds", 10)
    )
    valid_content_types = CONFIG["network_settings"].get(
        "valid_stream_content_types", []
    )

    try:
        async with session.get(url, timeout=timeout, allow_redirects=True) as response:
            if 200 <= response.status < 300:
                content_type = response.headers.get("Content-Type", "").lower()
                if not valid_content_types or any(
                    content_type.startswith(valid) for valid in valid_content_types
                ):
                    return (
                        url,
                        "live",
                    )
                return (
                    url,
                    "dead_content_type",
                )
            return url, "dead_status"
    except (asyncio.TimeoutError, aiohttp.ClientError):
        return url, "error"


async def run_health_checks(playlists_with_content: dict) -> tuple[dict, set, int]:
    """This function now uses the enhanced link health check."""
    print(f"\n{C.BRIGHT}--- ❤️‍🩹  PHASE 1B: CHECKING LINK HEALTH ---{C.RESET}")
    health_reports, dead_links = {}, set()
    url_pattern = re.compile(r'https?://[^\s"\'`<>]+')
    all_urls, url_to_filename_map = set(), {}

    for filename, content in playlists_with_content.items():
        urls_in_file = set(url_pattern.findall(content))
        health_reports[filename] = {"total": len(urls_in_file), "live": 0, "dead": 0}
        all_urls.update(urls_in_file)
        for url in urls_in_file:
            url_to_filename_map[url] = filename

    total_links_to_check = len(all_urls)
    pbar = tqdm(
        total=total_links_to_check,
        desc=f"{C.YELLOW}🌡️ Checking Link Health{C.RESET}",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
    )
    headers = {"User-Agent": "VLC/3.0.20 (win32/x86_64)"}
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [check_link_health(session, url) for url in all_urls]
        for future in asyncio.as_completed(tasks):
            url, status = await future
            filename = url_to_filename_map.get(url)
            if filename:
                if status == "live":
                    health_reports[filename]["live"] += 1
                else:
                    health_reports[filename]["dead"] += 1
                    dead_links.add(url)
            pbar.update(1)
    pbar.close()
    return health_reports, dead_links, total_links_to_check
