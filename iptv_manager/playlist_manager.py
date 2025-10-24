import asyncio
import logging
import re
from datetime import datetime, timedelta

import aiohttp
from tqdm import tqdm

from .config_loader import (
    INPUT_DIR,
    PLAYLIST_CONFIG_FILE,
    C,
    get_config,
    load_json_config,
    save_playlist_config,
)

CONFIG = get_config()


async def _recheck_playlist_status(session, filename, url):
    """Performs a lightweight HEAD request to see if a disabled playlist is back online."""
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with session.head(url, timeout=timeout, allow_redirects=True) as response:
            if response.status == 200:
                return filename, "online"
            return filename, "offline"
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return filename, "offline"


def _handle_rechecking_disabled(playlist_config: dict) -> tuple[bool, list[str]]:
    """
    Checks for and re-enables disabled playlists.
    Returns a tuple: (was_config_modified, list_of_re_enabled_playlists).
    """
    re_enabled_playlists = []
    config_was_modified = False
    recheck_days = CONFIG.get("features", {}).get("recheck_disabled_after_days", 7)
    if not recheck_days or recheck_days <= 0:
        return False, []

    disabled_playlists = playlist_config.get("disabled_playlists", {})
    if not disabled_playlists:
        return False, []

    playlists_to_recheck = {}
    now = datetime.now()
    recheck_threshold = now - timedelta(days=recheck_days)

    for filename, data in disabled_playlists.items():
        if isinstance(data, str):
            disabled_playlists[filename] = {"url": data, "disabled_on": now.isoformat()}
            config_was_modified = True
            continue

        try:
            disabled_on_date = datetime.fromisoformat(data.get("disabled_on", ""))
            if disabled_on_date < recheck_threshold:
                playlists_to_recheck[filename] = data["url"]
        except (ValueError, TypeError):
            playlists_to_recheck[filename] = data["url"]

    if not playlists_to_recheck:
        return config_was_modified, []

    print(
        f"{C.BLUE}INFO: Re-checking {len(playlists_to_recheck)} disabled playlist(s)...{C.RESET}"
    )

    async def run_rechecks():
        results = []
        headers = {"User-Agent": "VLC/3.0.20 (win32/x86_64)"}
        async with aiohttp.ClientSession(headers=headers) as session:
            tasks = [
                _recheck_playlist_status(session, fn, url)
                for fn, url in playlists_to_recheck.items()
            ]
            for future in asyncio.as_completed(tasks):
                results.append(await future)
        return results

    recheck_results = asyncio.run(run_rechecks())

    for filename, status in recheck_results:
        config_was_modified = True
        if status == "online":
            playlist_data = disabled_playlists.pop(filename)
            playlist_config["playlists_to_fetch"][filename] = playlist_data["url"]
            re_enabled_playlists.append(filename)
            print(
                f"{C.GREEN}✅ SUCCESS: Disabled playlist '{filename}' is back online and re-enabled.{C.RESET}"
            )
        else:
            disabled_playlists[filename]["disabled_on"] = now.isoformat()
            logging.info(f"Disabled playlist '{filename}' is still offline.")

    return config_was_modified, re_enabled_playlists


def _handle_failed_playlists(
    permanently_dead: list[str], playlist_config: dict
) -> tuple[bool, list[str]]:
    """
    Moves failed playlists to the 'disabled_playlists' section in memory.
    Returns a tuple: (was_config_modified, list_of_newly_disabled_playlists).
    """
    newly_disabled = []
    if not permanently_dead:
        return False, []

    if "disabled_playlists" not in playlist_config:
        playlist_config["disabled_playlists"] = {}

    config_changed = False
    for filename in permanently_dead:
        if filename in playlist_config.get("playlists_to_fetch", {}):
            config_changed = True
            url = playlist_config["playlists_to_fetch"].pop(filename)
            playlist_config["disabled_playlists"][filename] = {
                "url": url,
                "disabled_on": datetime.now().isoformat(),
            }
            newly_disabled.append(filename)
            print(
                f"{C.RED}INFO: Playlist '{filename}' was moved to 'disabled_playlists'.{C.RESET}"
            )

    return config_changed, newly_disabled


async def _fetch_and_save_playlist(session, filename, url):
    """Coroutine to fetch a single playlist and save it to the input directory."""
    save_path = INPUT_DIR / filename
    try:
        timeout = aiohttp.ClientTimeout(
            total=CONFIG["network_settings"].get("playlist_timeout_seconds", 30)
        )
        async with session.get(url, timeout=timeout) as response:
            if response.status == 404:
                return (
                    filename,
                    "not_found_and_no_local"
                    if not save_path.exists()
                    else "fetch_failed_using_local",
                )
            response.raise_for_status()
            content = await response.text(encoding="utf-8", errors="ignore")
            await asyncio.to_thread(save_path.write_text, content, encoding="utf-8")
            return filename, "success"
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return (
            filename,
            "fetch_failed_no_local"
            if not save_path.exists()
            else "fetch_failed_using_local",
        )
    except Exception as e:
        return filename, f"error_{e}"


async def _run_all_fetches(playlists_to_fetch: dict) -> list[tuple[str, str]]:
    """Manages the concurrent fetching of all remote playlists and returns results."""
    # (This function is unchanged)
    results = []
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
            results.append(await future)
            pbar.update(1)
        pbar.close()
    return results


def fetch_playlists() -> tuple[dict, dict]:
    """
    Gathers playlists, managing active/disabled sources.
    Returns a tuple of (playlist_content_dict, playlist_actions_dict).
    """
    print(f"\n{C.BRIGHT}--- ⏯️  PHASE 1A: GATHERING & READING PLAYLISTS ---{C.RESET}")

    playlist_config = load_json_config(PLAYLIST_CONFIG_FILE)
    if playlist_config is None:
        print(
            f"{C.RED}FATAL: '{PLAYLIST_CONFIG_FILE.name}' is unreadable. Cannot proceed.{C.RESET}"
        )
        return {}, {}

    playlist_actions = {"re_enabled": [], "newly_disabled": []}
    config_was_modified = False

    modified, re_enabled = _handle_rechecking_disabled(playlist_config)
    if modified:
        config_was_modified = True
        playlist_actions["re_enabled"] = re_enabled

    if "playlists_to_fetch" not in playlist_config:
        print(
            f"{C.YELLOW}INFO: 'playlists.json' is using an outdated format. Upgrading...{C.RESET}"
        )
        playlist_config = {
            "playlists_to_fetch": playlist_config,
            "disabled_playlists": {},
        }
        config_was_modified = True

    playlists_to_fetch = playlist_config.get("playlists_to_fetch", {})
    if playlists_to_fetch:
        print(
            f"{C.BLUE}INFO: Fetching {len(playlists_to_fetch)} active remote playlists...{C.RESET}"
        )
        fetch_results = asyncio.run(_run_all_fetches(playlists_to_fetch))
        permanently_dead = [
            res[0] for res in fetch_results if res[1] == "not_found_and_no_local"
        ]
        modified, disabled = _handle_failed_playlists(permanently_dead, playlist_config)
        if modified:
            config_was_modified = True
            playlist_actions["newly_disabled"] = disabled
    else:
        print(f"{C.YELLOW}INFO: No active remote playlists defined.{C.RESET}")

    if config_was_modified:
        save_playlist_config(playlist_config)

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
        print(f"{C.RED}ERROR: No playlists found or could be read.{C.RESET}")
        return {}, {}

    for filename, content in all_playlist_content.items():
        if "#EXTINF" not in content.upper():
            print(
                f"{C.YELLOW}INFO: Playlist '{filename}' appears to be empty.{C.RESET}"
            )

    print(
        f"Found and read {C.GREEN}{len(all_playlist_content)}{C.RESET} total playlists into memory."
    )
    return all_playlist_content, playlist_actions


# --- Link Health Checking ---


async def check_link_health(session, url):
    """Checks the status and Content-Type for a more accurate health check."""
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
                    ct in content_type for ct in valid_content_types
                ):
                    return url, "live"
                return url, "dead_content_type"
            return url, "dead_status"
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return url, "error"


async def run_health_checks(playlists_with_content: dict) -> tuple[dict, set, int]:
    """Runs the asynchronous health check on all URLs."""
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
