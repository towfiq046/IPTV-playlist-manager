import re

from .config_loader import CLEAN_DIR, RESULTS_DB_FILE, C, get_config, load_json_config
from .utils import get_domain_from_url

CONFIG = get_config()


def parse_m3u_to_logical_entries(content: str) -> tuple[list, list]:
    """
    Parses M3U content into a header and a list of logical channel entries.
    This new version strictly treats each stream URL as a separate entry,
    carrying over the preceding metadata for non-standard multi-link entries.
    """
    header = []
    entries = []
    lines = content.splitlines()

    if lines and lines[0].strip().upper() == "#EXTM3U":
        header.append(lines[0])

    current_metadata = []
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.upper() == "#EXTM3U":
            continue

        if line_stripped.startswith("#"):
            if line_stripped.startswith("#EXTINF"):
                current_metadata = [line]
            else:
                current_metadata.append(line)

        elif line_stripped.startswith("http"):
            if not current_metadata:
                entries.append({"metadata": [], "urls": [line]})
            else:
                entries.append({"metadata": current_metadata, "urls": [line]})

    return header, entries


def _is_entry_clean(entry: dict, scan_results: dict, rules: dict) -> tuple[bool, str]:
    """
    Checks if a channel entry is clean.
    An entry is considered UNCLEAN if ANY URL within it points to a domain that is
    either confirmed malicious/suspicious OR has not been successfully scanned.
    """
    all_lines_in_entry = entry.get("metadata", []) + entry.get("urls", [])
    if not all_lines_in_entry:
        return False, "Entry is empty"

    url_pattern = re.compile(r'https?://[^\s"\'<>,]+')
    found_urls = []
    for line in all_lines_in_entry:
        found_urls.extend(url_pattern.findall(line))

    if not found_urls:
        return False, "No URL found in entry"

    max_malicious = rules.get("max_malicious_count", 0)
    max_suspicious = rules.get("max_suspicious_count", 2)

    for url in found_urls:
        domain = get_domain_from_url(url)
        if not domain:
            continue

        domain_stats = scan_results.get(domain)
        # If a domain is not in the results DB, its status is unknown.
        # For zero-tolerance, unknown is treated as unsafe.
        if not domain_stats:
            return False, f"domain '{domain}' has not been successfully scanned"

        malicious_count = domain_stats.get("malicious", 0)
        suspicious_count = domain_stats.get("suspicious", 0)
        if malicious_count > max_malicious or suspicious_count > max_suspicious:
            reason = f"domain '{domain}' (Malicious: {malicious_count}, Suspicious: {suspicious_count})"
            return False, reason

    return True, "All associated domains are clean"


def clean_and_merge_zero_tolerance(playlists_with_content: dict) -> tuple[dict, dict]:
    """
    Cleans all playlists, saving both individual clean files and a merged,
    deduplicated master playlist.
    Returns global merge stats and a detailed per-playlist report.
    """
    print(
        f"\n{C.BRIGHT}--- 🧹 PHASE 3: CLEANING & MERGING (ZERO-TOLERANCE) ---{C.RESET}"
    )
    scan_results = load_json_config(RESULTS_DB_FILE, default={})
    if scan_results is None:
        print(f"{C.RED}Aborting: Could not load scan results.{C.RESET}")
        return {}, {}

    rules = CONFIG.get("zero_tolerance_rules", {})
    print(
        f"Applying rules: Max Malicious = {rules.get('max_malicious_count', 0)}, Max Suspicious = {rules.get('max_suspicious_count', 2)}"
    )
    print(
        f"{C.YELLOW}NOTE: Any entry with a domain that hasn't been scanned will be DISCARDED.{C.RESET}"
    )

    master_content_lines = ["#EXTM3U"]
    seen_stream_urls = set()
    total_entries_processed = 0
    total_discarded_count = 0

    playlist_reports = {}

    for filename, content in playlists_with_content.items():
        print(f"\n➡️  Processing '{C.CYAN}{filename}{C.RESET}'...")
        _header, logical_entries = parse_m3u_to_logical_entries(content)

        clean_entries_for_this_file = ["#EXTM3U"]

        kept_this_file = 0
        discarded_this_file = 0
        total_in_file = len(logical_entries)

        for entry in logical_entries:
            total_entries_processed += 1
            if not entry.get("urls"):
                discarded_this_file += 1
                continue

            is_clean, _reason = _is_entry_clean(entry, scan_results, rules)

            if is_clean:
                clean_entries_for_this_file.extend(entry["metadata"])
                clean_entries_for_this_file.extend(entry["urls"])
                kept_this_file += 1

                primary_stream_url = entry["urls"][0]
                if primary_stream_url not in seen_stream_urls:
                    seen_stream_urls.add(primary_stream_url)
                    master_content_lines.extend(entry["metadata"])
                    master_content_lines.extend(entry["urls"])
            else:
                discarded_this_file += 1

        if kept_this_file > 0:
            individual_clean_path = CLEAN_DIR / filename
            individual_clean_path.write_text(
                "\n".join(clean_entries_for_this_file) + "\n", encoding="utf-8"
            )

        playlist_reports[filename] = {
            "total": total_in_file,
            "kept": kept_this_file,
            "discarded": discarded_this_file,
        }

        total_discarded_count += discarded_this_file
        discard_color = C.GREEN if discarded_this_file == 0 else C.YELLOW
        print(
            f"  -> Results: Kept {C.GREEN}{kept_this_file}{C.RESET} clean entries, Discarded {discard_color}{discarded_this_file}{C.RESET} entries."
        )

    master_playlist_path = CLEAN_DIR / "_MASTER_PLAYLIST.m3u"
    master_playlist_path.write_text(
        "\n".join(master_content_lines) + "\n", encoding="utf-8"
    )

    final_channel_count = len(seen_stream_urls)

    print(f"\n{C.BRIGHT}--- ✅ Processing complete! ---{C.RESET}")
    print(f"   -> Total channel entries processed: {total_entries_processed}")
    print(f"   -> Total entries discarded: {C.YELLOW}{total_discarded_count}{C.RESET}")
    print(
        f"   -> Total unique clean channels saved to master: {C.GREEN}{final_channel_count}{C.RESET}"
    )
    print(f"   -> Your clean playlists are in '{C.CYAN}{CLEAN_DIR.name}/{C.RESET}'")

    merge_stats = {
        "processed": total_entries_processed,
        "discarded": total_discarded_count,
        "final_count": final_channel_count,
    }

    return merge_stats, playlist_reports




