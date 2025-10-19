import argparse
import asyncio
import logging
import sys

from iptv_manager.cleaner import parse_m3u_to_logical_entries, report_and_clean
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


def merge_clean_playlists():
    """
    Combines all generated clean playlists into a single master file,
    intelligently removing entries with duplicate stream URLs.
    """
    master_playlist_path = CLEAN_DIR / "_MASTER_PLAYLIST.m3u"
    print(f"\n{C.BRIGHT}---  consolidating playlists & de-duplicating ---{C.RESET}")

    clean_files = sorted(
        [f for f in CLEAN_DIR.glob("*.m3u*") if f.name != master_playlist_path.name]
    )

    if not clean_files:
        logging.warning("No clean playlist files found to merge.")
        return

    seen_urls = set()
    master_content_lines = ["#EXTM3U"]
    total_entries_processed = 0
    duplicate_streams_removed = 0

    for playlist_file in clean_files:
        content = playlist_file.read_text(encoding="utf-8")
        # Use the existing robust parser to break the file into logical entries
        _header, logical_entries = parse_m3u_to_logical_entries(content)

        for entry in logical_entries:
            total_entries_processed += 1
            # An entry might have multiple URLs, though it's rare. We handle it.
            if not entry.get("urls"):
                continue

            # We will only keep the metadata and the URLs that are new.
            unique_urls_for_this_entry = []
            for url in entry["urls"]:
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_urls_for_this_entry.append(url)
                else:
                    duplicate_streams_removed += 1

            # If we found at least one new, unique URL, add the channel entry.
            if unique_urls_for_this_entry:
                master_content_lines.extend(entry["metadata"])
                master_content_lines.extend(unique_urls_for_this_entry)

    master_playlist_path.write_text(
        "\n".join(master_content_lines) + "\n", encoding="utf-8"
    )

    print(f"✅ Successfully merged {len(clean_files)} playlists.")
    print(
        f"   -> Processed {total_entries_processed} entries and removed {C.YELLOW}{duplicate_streams_removed}{C.RESET} duplicate streams."
    )
    print(
        f"   -> Your final master playlist is '{C.CYAN}{master_playlist_path.name}{C.RESET}'"
    )


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

    # Merge all the clean files into a single master playlist
    merge_clean_playlists()

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
