import json
import re
from pathlib import Path
from urllib.parse import urlparse

# --- Configuration ---
# This script should be located in the root of your IPTV Manager project.
PROJECT_ROOT = Path(__file__).parent
REPORTS_DIR = PROJECT_ROOT / "reports"
CLEAN_DIR = PROJECT_ROOT / "clean_playlists"

# Files this script will audit
SCAN_RESULTS_FILE = REPORTS_DIR / "scan_results.json"
MASTER_PLAYLIST_FILE = CLEAN_DIR / "_MASTER_PLAYLIST.m3u"

# --- Verification Criteria ---
# These thresholds define what this script considers a "bad" domain.
# They should match the rules in your main project's config.json.
MALICIOUS_THRESHOLD = 1  # Fails if malicious is >= this value.
SUSPICIOUS_THRESHOLD = 2  # Fails if suspicious is > this value.


class C:
    """Simple ANSI color codes for terminal output."""

    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def get_domain_from_url(url: str) -> str | None:
    """
    Extracts the network location (domain) from a URL.
    Handles special cases like CORS proxy URLs.
    """
    try:
        if "https://" in url and url.rfind("https://") > 0:
            url = url[url.rfind("https://") :]
        elif "http://" in url and url.rfind("http://") > 0:
            url = url[url.rfind("http://") :]
        return urlparse(url.strip()).netloc
    except (ValueError, AttributeError):
        return None


def verify_master_playlist():
    """
    Main function to audit the final master playlist against the scan results.
    """
    print(f"{C.BOLD}--- IPTV Manager Verification Script ---{C.END}")
    print(
        f"Auditing: '{C.CYAN}{MASTER_PLAYLIST_FILE.relative_to(PROJECT_ROOT)}{C.END}'"
    )
    print(f"Against:  '{C.CYAN}{SCAN_RESULTS_FILE.relative_to(PROJECT_ROOT)}{C.END}'")
    print("-" * 36)

    # 1. Load Scan Results and build a list of domains that SHOULD have been blocked.
    if not SCAN_RESULTS_FILE.exists():
        print(
            f"{C.RED}❌ ERROR: Scan results file not found. Cannot perform verification.{C.END}"
        )
        return

    try:
        scan_results = json.loads(SCAN_RESULTS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(
            f"{C.RED}❌ ERROR: Could not read scan_results.json. File is likely corrupt.{C.END}"
        )
        return

    blocked_domains = {}
    for domain, stats in scan_results.items():
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious >= MALICIOUS_THRESHOLD or suspicious > SUSPICIOUS_THRESHOLD:
            blocked_domains[domain] = (
                f"Malicious: {malicious}, Suspicious: {suspicious}"
            )

    if not blocked_domains:
        print(
            f"{C.YELLOW}ℹ️ No domains in scan_results.json met the blocking criteria. Verification is trivial.{C.END}"
        )
    else:
        print(
            f"Identified {C.YELLOW}{len(blocked_domains)}{C.END} domains that should be blocked."
        )

    # 2. Load the Master Playlist and check every URL in it.
    if not MASTER_PLAYLIST_FILE.exists():
        print(
            f"{C.RED}❌ ERROR: Master playlist file not found. Run the main script first.{C.END}"
        )
        return

    playlist_content = MASTER_PLAYLIST_FILE.read_text(encoding="utf-8")

    # Split the playlist into individual channel entries. Each entry starts with #EXTINF.
    channel_entries = playlist_content.split("#EXTINF:")[1:]
    url_pattern = re.compile(r'https?://[^\s"\'<>,]+')
    failed_entries = []

    print(
        f"Scanning {C.CYAN}{len(channel_entries)}{C.END} entries in the master playlist..."
    )

    for entry_text in channel_entries:
        # Re-add the #EXTINF tag for context in case of failure
        full_entry_text = "#EXTINF:" + entry_text

        # Extract channel name for clear reporting
        channel_name = (
            entry_text.splitlines()[0].split(",")[-1].strip() or "Unknown Channel"
        )

        all_urls_in_entry = url_pattern.findall(full_entry_text)

        for url in all_urls_in_entry:
            domain = get_domain_from_url(url)
            if domain and domain in blocked_domains:
                failed_entries.append(
                    {
                        "name": channel_name,
                        "domain": domain,
                        "reason": blocked_domains[domain],
                        "url": url,
                    }
                )
                # Once one bad domain is found, we can stop checking this entry
                break

    # 3. Report the final verdict.
    print("-" * 36)
    if not failed_entries:
        print(f"{C.GREEN}{C.BOLD}✅ VERIFICATION SUCCESSFUL{C.END}")
        print(
            "No channels associated with blocked domains were found in the master playlist."
        )
    else:
        print(f"{C.RED}{C.BOLD}❌ VERIFICATION FAILED{C.END}")
        print(f"Found {len(failed_entries)} channel(s) that should have been removed:")
        for i, failure in enumerate(failed_entries, 1):
            print(f"\n  {i}. Channel: {C.YELLOW}{failure['name']}{C.END}")
            print(f"     - Problem Domain: {C.RED}{failure['domain']}{C.END}")
            print(f"     - Reason: {failure['reason']}")
            print(f"     - Found in URL: {failure['url']}")


if __name__ == "__main__":
    verify_master_playlist()
