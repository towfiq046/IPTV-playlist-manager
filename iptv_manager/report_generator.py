import json
import logging
from datetime import datetime

from .config_loader import PLAYLIST_CONFIG_FILE, SUMMARY_REPORT_FILE, get_config

CONFIG = get_config()


def generate_summary_report(
    run_stats,
    health_reports,
    playlist_reports,
    domain_cross_ref,
    blocked_domains,
    playlist_actions,
    merge_stats,
):
    """Generates a comprehensive and well-structured summary report."""
    with open(SUMMARY_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("# 🛰️ Playlist Scan & Health Report v5.0\n\n")  # MODIFIED version
        f.write(
            f"- **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        # --- Master Playlist Summary ---
        f.write("### 👑 Master Playlist Summary\n\n")
        if merge_stats:
            f.write(f"- **Final Channel Count:** {merge_stats.get('final_count', 0)}\n")
            f.write(
                f"- **Duplicate Streams Removed:** {merge_stats.get('removed', 0)}\n"
            )
            f.write(
                f"- **Total Source Entries Processed:** {merge_stats.get('processed', 0)}\n\n"
            )
        else:
            f.write("No master playlist was generated.\n\n")

        f.write("---\n\n### 📊 Run Summary\n\n")
        f.write(
            f"- **Domains Scanned (New & Expired):** {run_stats.get('new_scans_count', 0)}\n"
        )
        f.write(
            f"- **New URLs Submitted to VT:** {run_stats.get('urls_submitted_to_vt', 0)}\n"
        )
        f.write(
            f"- **Total Links Health-Checked:** {run_stats.get('total_links_checked', 'N/A (Skipped)')}\n"
        )
        f.write(
            f"- **Dead Links Found:** {run_stats.get('dead_links_count', 'N/A (Skipped)')}\n\n"
        )

        # --- Playlist Source Management ---
        f.write("---\n\n### 🗂️ Playlist Source Management\n\n")
        if not playlist_actions.get("re_enabled") and not playlist_actions.get(
            "newly_disabled"
        ):
            f.write("No playlist sources were changed during this run.\n\n")
        else:
            if playlist_actions.get("re_enabled"):
                f.write("**Re-enabled Playlists (Back Online):**\n")
                for pl in playlist_actions["re_enabled"]:
                    f.write(f"- `✅ {pl}`\n")
                f.write("\n")
            if playlist_actions.get("newly_disabled"):
                f.write("**Newly Disabled Playlists (Returned 404):**\n")
                for pl in playlist_actions["newly_disabled"]:
                    f.write(f"- `🚫 {pl}`\n")
                f.write("\n")

        # Also list all currently disabled playlists for reference
        try:
            playlist_config = json.loads(PLAYLIST_CONFIG_FILE.read_text())
            disabled_playlists = playlist_config.get("disabled_playlists", {})
            if disabled_playlists:
                f.write("**Currently Disabled Playlists:**\n")
                for pl in disabled_playlists:
                    f.write(f"- `{pl}`\n")
                f.write("\n")
        except (FileNotFoundError, json.JSONDecodeError):
            pass  # Ignore if we can't read the file for this section

        f.write("---\n\n### 🩺 Part 1: Source Playlist Health & Security Overview\n\n")

        # --- Formatted as a Table ---
        if not health_reports and CONFIG.get("features", {}).get(
            "check_link_health", True
        ):
            f.write(
                "Health check was skipped via command-line. No data to display.\n\n"
            )
        elif not health_reports:
            f.write("Health check was disabled in config.json. No data to display.\n\n")
        else:
            f.write(
                "| Playlist File | Health Status | Security Status | Final State |\n"
            )
            f.write("| :--- | :--- | :--- | :--- |\n")
            for filename, health in health_reports.items():
                live_percent = (
                    (health["live"] / health["total"] * 100)
                    if health["total"] > 0
                    else 0
                )
                health_status = (
                    f"✅ Healthy ({live_percent:.0f}%)"
                    if live_percent >= 80
                    else f"⚠️ Degraded ({live_percent:.0f}%)"
                    if live_percent >= 50
                    else f"❌ Unhealthy ({live_percent:.0f}%)"
                )

                security_status = (
                    "❗ Contaminated"
                    if any(playlist_reports.get(filename, {}).get("removed_channels"))
                    else "✅ Clean"
                )

                final_state = (
                    "🗑️ Became Empty"
                    if playlist_reports.get(filename, {}).get("became_empty")
                    else "OK"
                )

                f.write(
                    f"| `{filename}` | {health_status} | {security_status} | {final_state} |\n"
                )
            f.write("\n")

        f.write("---\n\n### 🛡️ Part 2: Malicious Content Audit Trail\n\n")
        contaminated_playlists = {
            fn: pr for fn, pr in playlist_reports.items() if pr["removed_channels"]
        }
        if not contaminated_playlists:
            f.write(
                "No malicious content was found in any playlist based on your rules.\n"
            )
        else:
            # --- MODIFIED: Enhanced Reporting Logic ---
            for i, (filename, report) in enumerate(contaminated_playlists.items(), 1):
                f.write(f"**{i}. Playlist: `{filename}`**\n")
                for domain, removed_items in report["removed_channels"].items():
                    f.write(
                        f"   - **Blocked Domain `{domain}`:** (Reason: *{blocked_domains.get(domain)}*)\n"
                    )
                    for item in removed_items:
                        channel = item["channel"]
                        reason = item["reason"]
                        f.write(f"     - 🗑️ Removed Channel: `{channel}` (*{reason}*)\n")
                f.write("\n")
            # --- END MODIFIED ---

        f.write("---\n\n### 🗺️ Part 3: Master Blocklist Cross-Reference\n\n")
        if not domain_cross_ref:
            f.write("No domains were blocked based on your rules.\n")
        else:
            for i, (domain, data) in enumerate(domain_cross_ref.items(), 1):
                f.write(f"**{i}. Domain: `{domain}`**\n")
                f.write(f"   - **Reason for Block:** *{data['reason']}*\n")
                f.write(f"   - **Found In ({len(data['found_in'])} Playlist(s)):**\n")
                for filename in data["found_in"]:
                    f.write(f"     - `{filename}`\n")
                f.write("\n")

    logging.info(f"Enhanced summary report saved to '{SUMMARY_REPORT_FILE.name}'")
