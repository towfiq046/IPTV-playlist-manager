import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

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


async def submit_url_for_analysis(session, url, headers) -> bool:
    """
    Submits a URL to VirusTotal for scanning if it's not already known.
    Returns True on success, False on failure.
    """
    global URLS_SUBMITTED_THIS_RUN
    submit_url = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": url}
    domain_of_url = urlparse(url).netloc
    try:
        async with session.post(submit_url, headers=headers, data=payload) as response:
            if response.status == 200:
                logging.info(
                    f"Successfully submitted new URL for {domain_of_url} for analysis."
                )
                URLS_SUBMITTED_THIS_RUN += 1
                return True
            # This specific 400 error is not a failure; it means the URL is already known to VT
            # and likely has a report, even if it returned 404 moments ago.
            elif response.status == 400 and "already exists" in (await response.text()):
                logging.debug(
                    f"URL for {domain_of_url} was already submitted recently."
                )
                return True
            else:
                logging.warning(
                    f"Failed to submit URL for {domain_of_url}. Status: {response.status}. It will be re-queued."
                )
                return False
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.error(f"NETWORK ERROR during URL submission: {e}")
        return False


async def process_url(session, domain, url, semaphore):
    """
    Fetches the scan report for a single URL from VirusTotal.
    Returns a result ONLY if the scan is definitive. Otherwise, returns None
    to keep the domain in the scan queue.
    """
    if QUOTA_EXHAUSTED:
        return domain, None

    async with semaphore:
        url_id = hashlib.sha256(url.encode()).hexdigest()
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": API_KEY}

        try:
            async with session.get(report_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    vt_stats = (
                        data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats")
                    )
                    # We have a definitive result, create a record
                    if vt_stats is not None:
                        final_record = {
                            "malicious": vt_stats.get("malicious", 0),
                            "suspicious": vt_stats.get("suspicious", 0),
                            "last_scanned": datetime.now(timezone.utc).isoformat(),
                        }
                        return domain, final_record

                elif response.status == 404:
                    # Report not found. We must submit it and check again next time.
                    # We do NOT create a default record. It remains unscanned.
                    logging.info(
                        f"No report for {domain}. Submitting URL to VT for future analysis."
                    )
                    await submit_url_for_analysis(session, url, headers)
                    return domain, None  # <-- Return None to keep it in the queue

                elif response.status == 429 and await handle_429_error(response):
                    return domain, None  # Quota fully exhausted

                elif response.status == 401:
                    logging.error("VirusTotal API Key is invalid or unauthorized.")
                else:
                    logging.warning(
                        f"Unexpected status {response.status} for {domain}. It will be re-queued."
                    )

        except (aiohttp.ClientError, asyncio.TimeoutError, RuntimeError) as e:
            logging.error(f"NETWORK ERROR for {domain}: {e}")

        # Any path that doesn't return a final_record will end up here.
        # This ensures failed or incomplete scans are always re-queued.
        return domain, None


# --- Core Scanning and File I/O Logic ---


def _save_scan_progress(results_db: dict, remaining_domains: set):
    """Atomically saves the current results database and the remaining scan queue."""
    logging.info(
        f"Saving progress: {len(results_db)} total results known, {len(remaining_domains)} domains left to scan."
    )
    # Save the latest results
    RESULTS_DB_FILE.write_text(json.dumps(results_db, indent=2))

    # Save or delete the remaining queue
    if remaining_domains:
        SCAN_QUEUE_FILE.write_text(json.dumps(list(remaining_domains)))
    elif SCAN_QUEUE_FILE.exists():
        SCAN_QUEUE_FILE.unlink()


def _determine_domains_to_scan(
    master_domain_list: set, results_db: dict, force_rescan: bool
) -> set:
    """Determines which domains need scanning based on cache, expiry, and user flags."""
    if SCAN_QUEUE_FILE.exists():
        print(f"{C.YELLOW}Found an incomplete scan queue.{C.RESET}")
        choice = input("Do you want to resume the previous scan? (y/n): ").lower()
        if choice == "y":
            try:
                domains_to_scan = set(json.loads(SCAN_QUEUE_FILE.read_text()))
                print(f"Resuming scan with {len(domains_to_scan)} domains remaining.")
                # Also add any brand new domains from the current playlists
                new_domains = master_domain_list - set(results_db.keys())
                if new_domains:
                    print(
                        f"Adding {len(new_domains)} newly discovered domains to the queue."
                    )
                    domains_to_scan.update(new_domains)
                return domains_to_scan
            except (json.JSONDecodeError, FileNotFoundError):
                print(f"{C.RED}Error reading queue. Starting fresh.{C.RESET}")
        SCAN_QUEUE_FILE.unlink(missing_ok=True)

    if force_rescan:
        print(
            f"{C.YELLOW}Forcing a full rescan of all {len(master_domain_list)} domains.{C.RESET}"
        )
        return master_domain_list

    domains_to_scan = set()
    rescan_days = CONFIG.get("features", {}).get("rescan_results_after_days", 30)
    expiry_date_threshold = datetime.now(timezone.utc) - timedelta(days=rescan_days)
    expired_count = 0

    for domain in master_domain_list:
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
                domains_to_scan.add(domain)

    new_count = len(domains_to_scan) - expired_count
    logging.info(f"Found {C.CYAN}{len(master_domain_list)}{C.RESET} unique domains.")
    if new_count > 0:
        logging.info(f"-> {C.GREEN}{new_count}{C.RESET} are new.")
    if expired_count > 0:
        logging.info(
            f"-> {C.YELLOW}{expired_count}{C.RESET} are expired (older than {rescan_days} days)."
        )

    return domains_to_scan


async def _run_scanner_loop(
    domains_to_scan: set, domain_to_rep_url: dict, results_db: dict
) -> int:
    """The main asynchronous loop that manages and executes the scans."""
    original_queued_count = len(domains_to_scan)
    domains_to_scan.intersection_update(domain_to_rep_url.keys())
    pruned_count = original_queued_count - len(domains_to_scan)

    if pruned_count > 0:
        logging.warning(
            f"Skipped {pruned_count} stale domains from the queue that are no longer in the playlists."
        )

    if not domains_to_scan:
        logging.info("All domains are accounted for. Nothing to scan.")
        if SCAN_QUEUE_FILE.exists():
            SCAN_QUEUE_FILE.unlink()
        return 0

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
                process_url(session, domain, domain_to_rep_url[domain], semaphore)
                for domain in domains_to_scan
                if domain in domain_to_rep_url
            ]
            for future in asyncio.as_completed(tasks):
                domain, stats = None, None
                try:
                    domain, stats = await future
                except Exception as e:
                    logging.error(f"A scanner task failed unexpectedly: {e}")

                pbar.update(1)

                if QUOTA_EXHAUSTED:
                    pbar.set_description_str(f"{C.RED}SCAN ABORTED (Quota){C.RESET}")
                    break

                if domain and stats:
                    # This is a successful, definitive scan.
                    # Save the result and remove it from the "to-do" list.
                    results_db[domain] = stats
                    remaining_domains.discard(domain)
                    new_results_count += 1
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
                f"\n{C.YELLOW}Scan interrupted or some URLs failed to scan. Run again to resume.{C.RESET}"
            )

    return new_results_count


# --- Main Orchestrator Function ---


def scan_playlists(
    master_domain_list: set,
    domain_to_rep_url: dict,
    force_rescan: bool = False,
) -> tuple[int, int]:
    """
    Orchestrates the entire domain scanning workflow.
    1. Determines which domains from the master list need to be scanned.
    2. Runs the asynchronous scanner using representative URLs.
    3. Returns the results.
    """
    global URLS_SUBMITTED_THIS_RUN
    URLS_SUBMITTED_THIS_RUN = 0

    print(f"\n{C.BRIGHT}--- 🛡️  PHASE 2: SCANNING DOMAINS ---{C.RESET}")

    results_db = load_json_config(RESULTS_DB_FILE, default={})
    if results_db is None:
        return 0, 0

    domains_to_scan = _determine_domains_to_scan(
        master_domain_list, results_db, force_rescan
    )

    if not domains_to_scan:
        logging.info("No new or expired domains to scan. Database is up-to-date.")
        return 0, 0

    new_results_count = asyncio.run(
        _run_scanner_loop(domains_to_scan, domain_to_rep_url, results_db)
    )

    scan_status = "finished"
    if QUOTA_EXHAUSTED:
        scan_status = "aborted due to quota"
    elif SCAN_QUEUE_FILE.exists() and SCAN_QUEUE_FILE.stat().st_size > 2:
        scan_status = "interrupted"

    logging.info(
        f"Scan {scan_status}. Added or updated {new_results_count} results in the database."
    )
    if URLS_SUBMITTED_THIS_RUN > 0:
        logging.info(
            f"Submitted {URLS_SUBMITTED_THIS_RUN} new URLs to VirusTotal for future analysis."
        )

    return new_results_count, URLS_SUBMITTED_THIS_RUN
