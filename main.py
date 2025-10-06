import argparse
import asyncio
import logging
import sys

from iptv_manager.cleaner import report_and_clean
from iptv_manager.config_loader import (
    CLEAN_DIR,
    SUMMARY_REPORT_FILE,
    C,
    create_default_files,
    get_config,
    get_quota_tracker,
    initialize_project,
    setup_logging,
)
from iptv_manager.playlist_manager import fetch_playlists, run_health_checks
from iptv_manager.report_generator import generate_summary_report
from iptv_manager.vt_scanner import scan_playlists

CONFIG = get_config()


def main():
    """Main workflow now driven by command-line arguments."""

    parser = argparse.ArgumentParser(description="IPTV Playlist Manager & Scanner v4.5")
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
        "--init",
        action="store_true",
        help="Create default config.json, playlists.json, and .env files.",
    )
    args = parser.parse_args()

    if args.init:
        create_default_files()
        sys.exit(0)

    setup_logging()
    run_stats = initialize_project()

    playlists_with_content = fetch_playlists()
    if not playlists_with_content:
        return

    health_reports, dead_links = {}, set()
    run_health_check_config = CONFIG.get("features", {}).get("check_link_health", True)
    if not args.skip_health_check and run_health_check_config:
        health_reports, dead_links, total_links_checked = asyncio.run(
            run_health_checks(playlists_with_content)
        )
        run_stats["total_links_checked"] = total_links_checked
        run_stats["dead_links_count"] = len(dead_links)
    else:
        logging.info("Skipping link health check phase as requested.")

    new_scans_count, urls_submitted = scan_playlists(
        playlists_with_content, args.force_rescan
    )
    run_stats["new_scans_count"] = new_scans_count
    run_stats["urls_submitted_to_vt"] = urls_submitted

    playlist_reports, domain_cross_ref, blocked_domains = report_and_clean(
        playlists_with_content, health_reports, dead_links
    )

    generate_summary_report(
        run_stats,
        health_reports,
        playlist_reports,
        domain_cross_ref,
        blocked_domains,
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
