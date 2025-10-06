import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import aiohttp
from dotenv import load_dotenv
from tqdm import tqdm

from .config_loader import (
    ENV_FILE,
    RESULTS_DB_FILE,
    SCAN_QUEUE_FILE,
    C,
    get_config,
    load_json_config,
)
from .utils import get_domain_from_url

CONFIG = get_config()
load_dotenv(dotenv_path=ENV_FILE)
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

QUOTA_EXHAUSTED = False
URLS_SUBMITTED_THIS_RUN = 0


# --- Helper and API Interaction Functions ---


async def handle_429_error(response):
    """Handles API rate limiting by pausing or aborting."""
    global QUOTA_EXHAUSTED
    try:
        data = await response.json()
        error_code = data.get("error", {}).get("code")
        if error_code == "QuotaExceededError":
            logging.critical(
                "Daily API quota has been exhausted. Aborting all further scans."
            )
            QUOTA_EXHAUSTED = True
            return True
        else:
            logging.warning(
                f"Per-minute rate limit hit ({error_code}). Waiting for 60 seconds..."
            )
            await asyncio.sleep(60)
            return False
    except json.JSONDecodeError:
        logging.warning(
            "Hit a 429 (Too Many Requests) error. Waiting for 60 seconds..."
        )
        await asyncio.sleep(60)
        return False


async def submit_url_for_analysis(session, url, headers):
    """Submits a URL to VirusTotal for scanning if it's not already known."""
    global URLS_SUBMITTED_THIS_RUN
    submit_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": url}
    try:
        async with session.post(submit_url, headers=headers, data=payload) as response:
            if response.status == 200:
                logging.info(
                    f"Successfully submitted new URL for {get_domain_from_url(url)} for analysis."
                )
                URLS_SUBMITTED_THIS_RUN += 1
            elif response.status == 429:
                logging.warning("Rate limit hit while submitting URL. Will not retry.")
            elif response.status == 400 and "already exists" in (await response.text()):
                logging.debug(
                    f"URL for {get_domain_from_url(url)} was already submitted recently."
                )
            else:
                logging.warning(
                    f"Failed to submit URL for {get_domain_from_url(url)}. Status: {response.status}"
                )
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.error(f"NETWORK ERROR during URL submission: {e}")


async def process_url(session, domain, url, semaphore):
    """
    Fetches the scan report for a single URL from VirusTotal and returns a
    standardized record.
    """
    if QUOTA_EXHAUSTED:
        return domain, None

    async with semaphore:
        url_id = hashlib.sha256(url.encode()).hexdigest()
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": API_KEY}
        vt_stats = None  # This will hold the raw dict from the VT API

        try:
            async with session.get(report_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    vt_stats = (
                        data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats")
                    )
                elif response.status == 404:
                    logging.info(
                        f"No report for {domain}. Submitting and creating clean record."
                    )
                    await submit_url_for_analysis(session, url, headers)
                    # Create a default 'clean' stats object to record the check
                    vt_stats = {"malicious": 0, "suspicious": 0}
                elif response.status == 429 and await handle_429_error(response):
                    return domain, None  # Quota fully exhausted
                elif response.status == 401:
                    logging.error("VirusTotal API Key is invalid or unauthorized.")
                elif response.status != 404:
                    logging.warning(f"Unexpected status {response.status} for {domain}")
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logging.error(f"NETWORK ERROR for {domain}: {e}")
            return domain, None

        # If we got any stats (from API or our default), create our final, standardized record
        if vt_stats is not None:
            final_record = {
                "malicious": vt_stats.get("malicious", 0),
                "suspicious": vt_stats.get("suspicious", 0),
                "last_scanned": datetime.now(timezone.utc).isoformat(),
            }
            return domain, final_record

        return domain, None


# --- Core Scanning and File I/O Logic ---


def _save_scan_progress(results_db: dict, remaining_domains: set):
    """Atomically saves the current results database and the remaining scan queue."""
    logging.info(
        f"Saving progress: {len(results_db)} total results known, {len(remaining_domains)} domains left to scan."
    )
    # Save the latest results
    RESULTS_DB_FILE.write_text(json.dumps(results_db, indent=2))

    # Save the remaining queue
    if remaining_domains:
        SCAN_QUEUE_FILE.write_text(json.dumps(list(remaining_domains)))
    elif SCAN_QUEUE_FILE.exists():
        SCAN_QUEUE_FILE.unlink()


def _determine_domains_to_scan(
    all_domains: set, results_db: dict, force_rescan: bool
) -> set:
    """Determines which domains need scanning based on cache, expiry, and user flags."""
    # Priority 1: Resume from an incomplete scan
    if SCAN_QUEUE_FILE.exists():
        print(f"{C.YELLOW}Found an incomplete scan queue.{C.RESET}")
        choice = input("Do you want to resume the previous scan? (y/n): ").lower()
        if choice == "y":
            try:
                domains_to_scan = set(json.loads(SCAN_QUEUE_FILE.read_text()))
                print(f"Resuming scan with {len(domains_to_scan)} domains remaining.")
                return domains_to_scan
            except (json.JSONDecodeError, FileNotFoundError):
                print(f"{C.RED}Error reading queue. Starting fresh.{C.RESET}")
        SCAN_QUEUE_FILE.unlink(missing_ok=True)  # Clean up if not resuming

    # Priority 2: Force a full rescan of everything
    if force_rescan:
        print(
            f"{C.YELLOW}Forcing a full rescan of all {len(all_domains)} domains.{C.RESET}"
        )
        return all_domains

    # Priority 3: Standard scan (new and expired domains)
    domains_to_scan = set()
    rescan_days = CONFIG.get("features", {}).get("rescan_results_after_days", 30)
    expiry_date_threshold = datetime.now(timezone.utc) - timedelta(days=rescan_days)
    expired_count = 0

    for domain in all_domains:
        if domain not in results_db:
            domains_to_scan.add(domain)
        else:
            last_scanned_str = results_db[domain].get("last_scanned")
            try:
                if (
                    not last_scanned_str
                    or datetime.fromisoformat(last_scanned_str) < expiry_date_threshold
                ):
                    domains_to_scan.add(domain)
                    expired_count += 1
            except (ValueError, TypeError):
                domains_to_scan.add(domain)  # Rescan if date is invalid

    new_count = len(domains_to_scan) - expired_count
    logging.info(f"Found {C.CYAN}{len(all_domains)}{C.RESET} unique domains.")
    if new_count > 0:
        logging.info(f"-> {C.GREEN}{new_count}{C.RESET} are new.")
    if expired_count > 0:
        logging.info(
            f"-> {C.YELLOW}{expired_count}{C.RESET} are expired (older than {rescan_days} days)."
        )

    return domains_to_scan


async def _run_scanner_loop(
    domains_to_scan: set, url_map: dict, results_db: dict
) -> int:
    """The main asynchronous loop that manages and executes the scans."""
    remaining_domains = domains_to_scan.copy()
    new_results_count = 0
    BATCH_SAVE_SIZE = 10
    semaphore = asyncio.Semaphore(4)

    pbar = tqdm(
        total=len(domains_to_scan),
        desc=f"{C.CYAN}🚀 Scanning Domains{C.RESET}",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}",
    )

    try:
        async with aiohttp.ClientSession() as session:
            tasks = [
                process_url(session, domain, url_map[domain], semaphore)
                for domain in domains_to_scan
            ]
            for future in asyncio.as_completed(tasks):
                if QUOTA_EXHAUSTED:
                    pbar.set_description_str(f"{C.RED}SCAN ABORTED (Quota){C.RESET}")
                    break

                domain, stats = await future
                pbar.update(1)
                remaining_domains.discard(domain)

                if stats:
                    results_db[domain] = stats
                    new_results_count += 1
                    # Save progress in batches
                    if new_results_count % BATCH_SAVE_SIZE == 0:
                        _save_scan_progress(results_db, remaining_domains)
                        pbar.set_description_str(
                            f"{C.CYAN}🚀 Scanning Domains (Progress Saved){C.RESET}"
                        )
    finally:
        pbar.close()
        _save_scan_progress(results_db, remaining_domains)
        if remaining_domains and not QUOTA_EXHAUSTED:
            print(
                f"\n{C.YELLOW}Scan interrupted. Run again to resume from where you left off.{C.RESET}"
            )

    return new_results_count


# --- Main Orchestrator Function ---


def scan_playlists(
    playlists_with_content: dict, force_rescan: bool = False
) -> tuple[int, int]:
    """
    Orchestrates the entire domain scanning workflow.
    1. Extracts all unique domains from playlists.
    2. Determines which domains need to be scanned.
    3. Runs the asynchronous scanner.
    4. Returns the results.
    """
    global URLS_SUBMITTED_THIS_RUN
    URLS_SUBMITTED_THIS_RUN = 0

    print(f"\n{C.BRIGHT}--- 🛡️  PHASE 2: SCANNING DOMAINS ---{C.RESET}")

    # 1. Extract domains and create a URL map
    url_pattern = re.compile(r'https?://[^\s"\'`<>]+')
    all_domains, url_map = set(), {}
    for content in playlists_with_content.values():
        for url in url_pattern.findall(content):
            domain = get_domain_from_url(url)
            if domain and domain not in url_map:
                all_domains.add(domain)
                url_map[domain] = url

    # 2. Load database and determine scan scope
    results_db = load_json_config(RESULTS_DB_FILE, default={})
    if results_db is None:
        return 0, 0

    domains_to_scan = _determine_domains_to_scan(all_domains, results_db, force_rescan)

    if not domains_to_scan:
        logging.info("No new or expired domains to scan. Database is up-to-date.")
        return 0, 0

    # 3. Run the scanner
    new_results_count = asyncio.run(
        _run_scanner_loop(domains_to_scan, url_map, results_db)
    )

    scan_status = "aborted" if QUOTA_EXHAUSTED else "finished"
    logging.info(
        f"Scan {scan_status}. Added or updated {new_results_count} results in the database."
    )
    if URLS_SUBMITTED_THIS_RUN > 0:
        logging.info(
            f"Submitted {URLS_SUBMITTED_THIS_RUN} new URLs to VirusTotal for future analysis."
        )

    return new_results_count, URLS_SUBMITTED_THIS_RUN
