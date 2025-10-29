import json
import logging
from datetime import datetime

from .config_loader import PLAYLIST_CONFIG_FILE, SUMMARY_REPORT_FILE, get_config

CONFIG = get_config()


def generate_summary_report(
    run_stats,
    health_reports,
    playlist_actions,
    merge_stats,
    playlist_reports,
    scan_results,  # <-- NEW ARGUMENT
):
    """Generates a comprehensive, professional summary report."""
    with open(SUMMARY_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("# 🛰️ IPTV Manager - Zero-Tolerance Scan Report\n\n")
        f.write(
            f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        # --- Section 1: Key Metrics ---
        f.write("## 🏆 Overall Results\n\n")
        if merge_stats:
            processed = merge_stats.get("processed", 0)
            final_count = merge_stats.get("final_count", 0)
            clean_rate = (final_count / processed * 100) if processed > 0 else 0

            f.write(f"- **Final Master Playlist Channel Count:** `{final_count}`\n")
            f.write(f"- **Total Entries Processed Across All Files:** `{processed}`\n")
            f.write(
                f"- **Total Unsafe/Duplicate Entries Discarded:** `{merge_stats.get('discarded', 0)}`\n"
            )
            f.write(f"- **Overall Clean Rate:** `{clean_rate:.2f}%`\n\n")
        else:
            f.write("No master playlist was generated.\n\n")

        # --- Section 2: Playlist Source Status ---
        f.write("---\n")
        f.write("## 🗂️ Playlist Source Status\n\n")
        if not playlist_actions.get("re_enabled") and not playlist_actions.get(
            "newly_disabled"
        ):
            f.write("✅ No changes to playlist sources during this run.\n\n")
        else:
            if playlist_actions.get("re_enabled"):
                f.write("**Back Online & Re-enabled:**\n")
                for pl in playlist_actions["re_enabled"]:
                    f.write(f"- `✅ {pl}`\n")
                f.write("\n")
            if playlist_actions.get("newly_disabled"):
                f.write("**Offline & Newly Disabled:**\n")
                for pl in playlist_actions["newly_disabled"]:
                    f.write(f"- `🚫 {pl}`\n")
                f.write("\n")

        try:
            playlist_config = json.loads(PLAYLIST_CONFIG_FILE.read_text())
            disabled_playlists = playlist_config.get("disabled_playlists", {})
            if disabled_playlists:
                f.write("**Currently Disabled Playlists:**\n")
                for pl in disabled_playlists:
                    f.write(f"- `{pl}`\n")
                f.write("\n")
        except (FileNotFoundError, json.JSONDecodeError):
            pass

        # --- Section 3: Detailed Cleaning Breakdown ---
        f.write("---\n")
        f.write("## 🛡️ Cleaning & Processing Summary\n\n")
        f.write(
            "| Playlist File | Status | Entries Kept | Entries Discarded | Clean Rate |\n"
        )
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        sorted_reports = sorted(playlist_reports.items(), key=lambda item: item[0])
        for filename, report in sorted_reports:
            total = report.get("total", 0)
            kept = report.get("kept", 0)
            discarded = report.get("discarded", 0)
            rate = (kept / total * 100) if total > 0 else 0
            status_emoji = "✅"
            if discarded > 0:
                status_emoji = "⚠️"
            if kept == 0 and total > 0:
                status_emoji = "❌"
            f.write(
                f"| `{filename}` | {status_emoji} | `{kept}` | `{discarded}` | `{rate:.1f}%` |\n"
            )
        f.write("\n")

        # --- NEW: Section 4: Blocked Domain Intelligence ---
        f.write("---\n")
        f.write("## 🚫 Blocked Domain Intelligence\n\n")
        rules = CONFIG.get("zero_tolerance_rules", {})
        malicious_rule = rules.get("max_malicious_count", 0)
        suspicious_rule = rules.get("max_suspicious_count", 2)

        blocked_domains = []
        for domain, stats in scan_results.items():
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            is_blocked = False
            reason = ""
            if malicious > malicious_rule:
                is_blocked = True
                reason = "Malicious"
            elif suspicious > suspicious_rule:
                is_blocked = True
                reason = "Suspicious"

            if is_blocked:
                blocked_domains.append(
                    {
                        "domain": domain,
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "reason": reason,
                    }
                )

        if not blocked_domains:
            f.write("✅ No domains met the blocking criteria during this scan.\n\n")
        else:
            blocked_domains.sort(
                key=lambda x: (x["malicious"], x["suspicious"]), reverse=True
            )
            f.write(
                f"Identified **{len(blocked_domains)}** domains that were blocked from the final playlists based on your rules.\n\n"
            )
            f.write("| Domain | Reason | Malicious Votes | Suspicious Votes |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for item in blocked_domains:
                reason_emoji = "☣️" if item["reason"] == "Malicious" else "🤔"
                f.write(
                    f"| `{item['domain']}` | {reason_emoji} {item['reason']} | `{item['malicious']}` | `{item['suspicious']}` |\n"
                )
            f.write("\n")

        # --- Section 5: Scan & Network Activity ---
        f.write("---\n")
        f.write("## 📡 Scan & Network Activity\n\n")
        f.write(
            f"- **Domains Scanned (New or Expired):** `{run_stats.get('new_scans_count', 0)}`\n"
        )
        f.write(
            f"- **New URLs Submitted to VirusTotal:** `{run_stats.get('urls_submitted_to_vt', 0)}`\n"
        )
        f.write(
            f"- **Stream Links Health-Checked:** `{run_stats.get('total_links_checked', 'N/A (Skipped)')}`\n\n"
        )

    logging.info(
        f"New comprehensive summary report saved to '{SUMMARY_REPORT_FILE.name}'"
    )
