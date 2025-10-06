import logging
from datetime import datetime

from .config_loader import SUMMARY_REPORT_FILE, get_config

CONFIG = get_config()


def generate_summary_report(
    run_stats,
    health_reports,
    playlist_reports,
    domain_cross_ref,
    blocked_domains,
):
    with open(SUMMARY_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("# 🛰️ Playlist Scan & Health Report v4.3\n\n")
        f.write(
            f"- **Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        f.write("### 📊 Run Summary\n\n")
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
            f"- **Dead Links Found:** {run_stats.get('dead_links_count', 'N/A (Skipped)')}\n\n---\n"
        )
        f.write("### 🩺 Part 1: Playlist Health & Security Overview\n\n")
        run_health_check_config = CONFIG.get("features", {}).get(
            "check_link_health", True
        )
        if not health_reports and run_health_check_config:
            f.write(
                "Health check was skipped via command-line. No data to display.\n\n"
            )
        elif not run_health_check_config:
            f.write("Health check was disabled in config.json. No data to display.\n\n")
        else:
            for i, (filename, health) in enumerate(health_reports.items(), 1):
                live_percent = (
                    (health["live"] / health["total"] * 100)
                    if health["total"] > 0
                    else 0
                )
                health_status = (
                    "✅ Healthy"
                    if live_percent >= 80
                    else ("⚠️ Degraded" if live_percent >= 50 else "❌ Unhealthy")
                )
                security_status = (
                    "❗ **Contaminated**"
                    if any(playlist_reports.get(filename, {}).get("removed_channels"))
                    else "✅ **Clean**"
                )
                f.write(f"**{i}. `{filename}`**\n")
                f.write(
                    f"   - **Health Status:** {health_status} ({live_percent:.0f}% Live / {health['dead']} Dead Links)\n"
                )
                f.write(f"   - **Security Status:** {security_status}\n\n")

        f.write("---\n\n### 🛡️ Part 2: Malicious Content Audit Trail\n\n")
        contaminated_playlists = {
            fn: pr for fn, pr in playlist_reports.items() if pr["removed_channels"]
        }
        if not contaminated_playlists:
            f.write(
                "No malicious content was found in any playlist based on your rules.\n"
            )
        else:
            for i, (filename, report) in enumerate(contaminated_playlists.items(), 1):
                f.write(f"**{i}. Playlist: `{filename}`**\n")
                for domain, channels in report["removed_channels"].items():
                    f.write(
                        f"   - **Domain `{domain}`:** (Reason: *{blocked_domains.get(domain)}*)\n"
                    )
                    for channel in channels:
                        f.write(f"     - 🗑️ Removed Channel: `{channel}`\n")
                f.write("\n")

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
