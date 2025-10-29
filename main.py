import argparse
import asyncio
import logging
import re
import sys

from iptv_manager.cleaner import clean_and_merge_zero_tolerance
from iptv_manager.config_loader import (
    CLEAN_DIR,
    SUMMARY_REPORT_FILE,
    C,
    RESULTS_DB_FILE,
    create_default_files,
    get_config,
    get_quota_tracker,
    initialize_project,
    load_json_config,
    setup_logging,
)
from iptv_manager.playlist_manager import fetch_playlists, run_health_checks
from iptv_manager.report_generator import generate_summary_report
from iptv_manager.url_resolver import resolve_and_map_urls
from iptv_manager.vt_scanner import scan_playlists

CONFIG = get_config()


def main():
    """Main workflow now driven by command-line arguments."""
    parser = argparse.ArgumentParser(
        description="IPTV Playlist Manager & Scanner v5.0 (Zero-Tolerance Mode)"
    )
    parser.add_argument(
        "--skip-health-check",
        action="store_true",
        help="Bypass the (slow) link health check phase.",
    )
    parser.add_argument(
        "--force-rescan",
        action="store_true",
        help="Force a rescan of all domains, ignoring the cache.",
    )
    parser.add_argument(
        "--init", action="store_true", help="Create default config files."
    )
    args = parser.parse_args()

    if args.init:
        create_default_files()
        sys.exit(0)

    setup_logging()
    run_stats = initialize_project()

    playlists_with_content, playlist_actions = fetch_playlists()
    if not playlists_with_content:
        print(f"{C.RED}No playlists were loaded. Exiting workflow.{C.RESET}")
        return

    # --- URL RESOLUTION PHASE ---
    url_pattern = re.compile(r'https?://[^\s"\'`<>]+')
    all_urls = set()
    for content in playlists_with_content.values():
        all_urls.update(url_pattern.findall(content))

    _redirect_map, master_domain_list, domain_to_rep_url = asyncio.run(
        resolve_and_map_urls(all_urls)
    )

    # --- HEALTH CHECK (Optional, for reporting only) ---
    health_reports = {}
    run_health_check_config = CONFIG.get("features", {}).get("check_link_health", True)
    if not args.skip_health_check and run_health_check_config:
        health_reports, _dead_links, total_links_checked = asyncio.run(
            run_health_checks(playlists_with_content)
        )
        run_stats["total_links_checked"] = total_links_checked
    else:
        logging.info("Skipping link health check phase as requested.")

    # --- SCANNING ---
    new_scans_count, urls_submitted = scan_playlists(
        master_domain_list, domain_to_rep_url, args.force_rescan
    )
    run_stats["new_scans_count"] = new_scans_count
    run_stats["urls_submitted_to_vt"] = urls_submitted

    # --- CLEAN & MERGE STEP ---
    merge_stats, playlist_reports = clean_and_merge_zero_tolerance(
        playlists_with_content
    )

    # --- REPORTING ---
    scan_results = load_json_config(RESULTS_DB_FILE, default={})
    generate_summary_report(
        run_stats,
        health_reports,
        playlist_actions,
        merge_stats,
        playlist_reports,
        scan_results,  # Pass the new data
    )

    print(f"{C.BRIGHT}{C.GREEN}\n============================================{C.RESET}")
    print(f"{C.BRIGHT}{C.GREEN}===    Workflow Finished Successfully    ==={C.RESET}")
    print(f"{C.BRIGHT}{C.GREEN}============================================{C.RESET}")
    print(
        f"-> Check '{C.CYAN}{SUMMARY_REPORT_FILE.name}{C.RESET}' for a clean overview."
    )
    print(
        f"-> Your clean playlists are in the '{C.CYAN}{CLEAN_DIR.name}/{C.RESET}' directory."
    )

    get_quota_tracker().fetch_and_print_quota()


if __name__ == "__main__":
    main()
