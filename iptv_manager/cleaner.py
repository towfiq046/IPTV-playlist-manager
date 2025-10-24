import re

from .config_loader import CLEAN_DIR, RESULTS_DB_FILE, C, get_config, load_json_config
from .utils import get_domain_from_url

CONFIG = get_config()


def parse_m3u_to_logical_entries(content: str) -> tuple[list, list]:
    header = []
    entries = []
    current_entry = {}
    lines = content.splitlines()

    if lines and lines[0].strip().upper() == "#EXTM3U":
        header.append(lines[0])

    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.upper() == "#EXTM3U":
            continue

        if line_stripped.startswith("#EXTINF"):
            if current_entry:
                entries.append(current_entry)
            current_entry = {"metadata": [line], "urls": []}
        elif line_stripped.startswith("#"):
            if current_entry:
                current_entry["metadata"].append(line)
        elif line_stripped.startswith("http"):
            if not current_entry:
                current_entry = {"metadata": [], "urls": []}
            current_entry["urls"].append(line)

    if current_entry:
        entries.append(current_entry)

    return header, entries


def report_and_clean(
    playlists_with_content: dict, health_reports: dict, dead_links: set
) -> tuple[dict, dict, dict]:
    print(f"\n{C.BRIGHT}--- 🧹 PHASE 3 & 4: REPORTING & CLEANING ---{C.RESET}")
    results_db = load_json_config(RESULTS_DB_FILE, default={})
    if results_db is None:
        return {}, {}, {}

    rules = CONFIG.get("decision_rules", {})
    whitelist = set(rules.get("whitelist_domains", []))
    blocked_domains = {
        domain: "Force Blocked by User"
        for domain in rules.get("force_block_domains", [])
    }

    if whitelist:
        print(f"Ignoring {len(whitelist)} whitelisted domains.")
    if blocked_domains:
        print(f"Applying {len(blocked_domains)} user-defined force blocks.")

    for domain, stats in results_db.items():
        if domain in blocked_domains or domain in whitelist:
            continue

        reason = None
        if stats.get("malicious", 0) >= rules.get("malicious_threshold", 1):
            reason = f"Malicious Count ({stats.get('malicious', 0)})"
        elif rules.get("block_on_suspicious", False) and stats.get(
            "suspicious", 0
        ) >= rules.get("suspicious_threshold", 5):
            reason = f"Suspicious Count ({stats.get('suspicious', 0)})"

        if reason:
            blocked_domains[domain] = reason

    print(
        f"Identified a total of {C.RED}{len(blocked_domains)}{C.RESET} domains to block based on your rules."
    )
    playlist_reports = {
        fn: {"removed_channels": {}, "became_empty": False}
        for fn in playlists_with_content
    }

    # Start with an empty cross-reference. We only add to it when a domain is actually found.
    domain_cross_ref = {}

    for filename, content in playlists_with_content.items():
        header, logical_entries = parse_m3u_to_logical_entries(content)
        clean_output_lines = header[:]
        malicious_removed_count = 0
        dead_removed_count = 0

        for entry in logical_entries:
            if not entry["urls"]:
                continue

            is_entry_malicious = False
            for url in entry["urls"]:
                domain = get_domain_from_url(url)
                if domain in blocked_domains:
                    is_entry_malicious = True

                    # If this is the first time we've seen this malicious domain this run, create its entry.
                    if domain not in domain_cross_ref:
                        domain_cross_ref[domain] = {
                            "reason": blocked_domains[domain],
                            "found_in": [],
                        }

                    # Add the current playlist to its list (if not already present).
                    if filename not in domain_cross_ref[domain]["found_in"]:
                        domain_cross_ref[domain]["found_in"].append(filename)

                    if entry["metadata"]:
                        extinf_line = entry["metadata"][0]
                        channel_name = ""
                        match_tvg_name = re.search(
                            r'tvg-name="([^"]+)"', extinf_line, re.IGNORECASE
                        )
                        if match_tvg_name:
                            channel_name = match_tvg_name.group(1).strip()
                        elif "," in extinf_line:
                            channel_name = extinf_line.split(",")[-1].strip()
                        if not channel_name:
                            channel_name = "Unknown Channel"

                        if domain not in playlist_reports[filename]["removed_channels"]:
                            playlist_reports[filename]["removed_channels"][domain] = []
                        if (
                            channel_name
                            not in playlist_reports[filename]["removed_channels"][
                                domain
                            ]
                        ):
                            playlist_reports[filename]["removed_channels"][
                                domain
                            ].append(channel_name)

                    # We found a malicious URL in this entry, no need to check others in the same entry.
                    break

            if is_entry_malicious:
                malicious_removed_count += 1
                continue

            clean_urls_for_this_entry = []
            for url in entry["urls"]:
                is_dead = (
                    CONFIG.get("features", {}).get("auto_remove_dead_links", False)
                    and url in dead_links
                )
                if not is_dead:
                    clean_urls_for_this_entry.append(url)
                else:
                    dead_removed_count += 1

            if clean_urls_for_this_entry:
                clean_output_lines.extend(entry["metadata"])
                clean_output_lines.extend(clean_urls_for_this_entry)

        is_now_empty = len(clean_output_lines) <= 1
        if is_now_empty:
            playlist_reports[filename]["became_empty"] = True
            print(
                f"  -> ⚠️  Processed '{C.YELLOW}{filename}{C.RESET}': Playlist is now EMPTY after removing {C.RED}{malicious_removed_count}{C.RESET} malicious entries and {C.YELLOW}{dead_removed_count}{C.RESET} dead links."
            )
        else:
            print(
                f"  -> Processed '{C.YELLOW}{filename}{C.RESET}': Discarded {C.RED}{malicious_removed_count}{C.RESET} malicious entries and {C.YELLOW}{dead_removed_count}{C.RESET} dead links. Produced clean output."
            )

        final_content = "\n".join(clean_output_lines)
        (CLEAN_DIR / filename).write_text(final_content + "\n", encoding="utf-8")

    return playlist_reports, domain_cross_ref, blocked_domains
