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

# --- NEW ---
from iptv_manager.url_resolver import resolve_and_map_urls
import re
# --- END NEW ---

CONFIG = get_config()


def merge_clean_playlists() -> dict:
    """
    Combines all generated clean playlists into a single master file,
    intelligently removing entries with duplicate stream URLs.
    Returns a dictionary of statistics for the report.
    """
    master_playlist_path = CLEAN_DIR / "_MASTER_PLAYLIST.m3u"
    print(f"\n{C.BRIGHT}---  consolidating playlists & de-duplicating ---{C.RESET}")

    clean_files = sorted(
        [f for f in CLEAN_DIR.glob("*.m3u*") if f.name != master_playlist_path.name]
    )

    if not clean_files:
        logging.warning("No clean playlist files found to merge.")
        return {}

    seen_urls = set()
    master_content_lines = ["#EXTM3U"]
    total_entries_processed = 0
    duplicate_streams_removed = 0

    for playlist_file in clean_files:
        content = playlist_file.read_text(encoding="utf-8")
        _header, logical_entries = parse_m3u_to_logical_entries(content)

        for entry in logical_entries:
            total_entries_processed += 1
            if not entry.get("urls"):
                continue

            unique_urls_for_this_entry = []
            for url in entry["urls"]:
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_urls_for_this_entry.append(url)
                else:
                    duplicate_streams_removed += 1

            if unique_urls_for_this_entry:
                master_content_lines.extend(entry["metadata"])
                master_content_lines.extend(unique_urls_for_this_entry)

    master_playlist_path.write_text(
        "\n".join(master_content_lines) + "\n", encoding="utf-8"
    )

    # Final count excludes the #EXTM3U header
    final_channel_count = sum(
        1 for line in master_content_lines if line.startswith("#EXTINF")
    )

    print(f"✅ Successfully merged {len(clean_files)} playlists.")
    print(
        f"   -> Processed {total_entries_processed} entries and removed {C.YELLOW}{duplicate_streams_removed}{C.RESET} duplicate streams."
    )
    print(
        f"   -> Your final master playlist with {C.GREEN}{final_channel_count}{C.RESET} channels is '{C.CYAN}{master_playlist_path.name}{C.RESET}'"
    )

    return {
        "processed": total_entries_processed,
        "removed": duplicate_streams_removed,
        "final_count": final_channel_count,
    }


def main():
    """Main workflow now driven by command-line arguments."""
    parser = argparse.ArgumentParser(
        description="IPTV Playlist Manager & Scanner v5.0"
    )  # MODIFIED version
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

    # --- NEW: URL RESOLUTION PHASE ---
    # 1. Extract all unique URLs from all loaded playlists first.
    url_pattern = re.compile(r'https?://[^\s"\'`<>]+')
    all_urls = set()
    for content in playlists_with_content.values():
        all_urls.update(url_pattern.findall(content))

    # 2. Run the new resolver to get our critical data maps.
    redirect_map, master_domain_list, domain_to_rep_url = asyncio.run(
        resolve_and_map_urls(all_urls)
    )
    # --- END NEW ---

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

    # --- MODIFIED: Pass new data to scanner and cleaner ---
    new_scans_count, urls_submitted = scan_playlists(
        master_domain_list, domain_to_rep_url, args.force_rescan
    )
    run_stats["new_scans_count"] = new_scans_count
    run_stats["urls_submitted_to_vt"] = urls_submitted

    playlist_reports, domain_cross_ref, blocked_domains = report_and_clean(
        playlists_with_content, health_reports, dead_links, redirect_map
    )
    # --- END MODIFIED ---

    merge_stats = merge_clean_playlists()

    # --- MODIFIED: Pass new data to report generator ---
    generate_summary_report(
        run_stats,
        health_reports,
        playlist_reports,
        domain_cross_ref,
        blocked_domains,
        playlist_actions,
        merge_stats,
    )
    # --- END MODIFIED ---

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
