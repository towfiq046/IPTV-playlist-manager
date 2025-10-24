import json
import logging
import shutil
import sys
from pathlib import Path

import requests
from colorama import Fore, Style, init

init(autoreset=True)


class C:
    RESET = Style.RESET_ALL
    BRIGHT = Style.BRIGHT
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN


# --- Project Structure and File Paths ---
SCRIPT_DIR = Path(__file__).parent.parent.resolve()
INPUT_DIR = SCRIPT_DIR / "input_playlists"
CLEAN_DIR = SCRIPT_DIR / "clean_playlists"
REPORTS_DIR = SCRIPT_DIR / "reports"
LOGS_DIR = SCRIPT_DIR / "logs"
PLAYLIST_CONFIG_FILE = SCRIPT_DIR / "playlists.json"
APP_CONFIG_FILE = SCRIPT_DIR / "config.json"
ENV_FILE = SCRIPT_DIR / ".env"
RESULTS_DB_FILE = REPORTS_DIR / "scan_results.json"
SUMMARY_REPORT_FILE = REPORTS_DIR / "summary_report.md"
SCAN_QUEUE_FILE = SCRIPT_DIR / "reports/scan_queue.json"


DEFAULT_CONFIG = {
    "decision_rules": {
        "malicious_threshold": 1,
        "suspicious_threshold": 5,
        "block_on_suspicious": False,
        "whitelist_domains": ["example.com"],
        "force_block_domains": [],
    },
    "features": {
        "check_link_health": True,
        "auto_remove_dead_links": True,
        "rescan_results_after_days": 30,
        "recheck_disabled_after_days": 7,
    },
    "network_settings": {
        "playlist_timeout_seconds": 30,
        "link_check_timeout_seconds": 10,
        "valid_stream_content_types": [
            "video/",
            "application/vnd.apple.mpegurl",
            "application/x-mpegURL",
            "audio/mpeg",
            "application/octet-stream",
        ],
    },
}


def save_playlist_config(config_data: dict):
    """
    Safely writes to the playlists.json file after first creating a backup.
    """
    backup_path = PLAYLIST_CONFIG_FILE.with_suffix(".json.bak")
    try:
        # Create a backup before every write operation
        if PLAYLIST_CONFIG_FILE.exists():
            shutil.copy2(PLAYLIST_CONFIG_FILE, backup_path)
            logging.info(
                f"Created a backup of your playlist config at '{backup_path.name}'"
            )

        PLAYLIST_CONFIG_FILE.write_text(json.dumps(config_data, indent=2))
    except Exception as e:
        logging.critical(
            f"FATAL: Could not save playlist configuration to '{PLAYLIST_CONFIG_FILE.name}': {e}"
        )
        logging.critical(
            "Your original file should be safe. Please check permissions and file integrity."
        )


def create_default_files():
    """Creates default configuration files if they don't exist."""
    print("--- Running Initial Setup ---")
    if not APP_CONFIG_FILE.exists():
        print(f"Creating default '{APP_CONFIG_FILE.name}'...")
        APP_CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2))

    if not PLAYLIST_CONFIG_FILE.exists():
        print(f"Creating example '{PLAYLIST_CONFIG_FILE.name}'...")
        default_playlists = {
            "playlists_to_fetch": {
                "example_playlist.m3u": "https://example.com/playlist.m3u"
            },
            "disabled_playlists": {},
        }
        PLAYLIST_CONFIG_FILE.write_text(json.dumps(default_playlists, indent=2))

    if not ENV_FILE.exists():
        print(f"Creating empty '{ENV_FILE.name}'...")
        ENV_FILE.write_text("VIRUSTOTAL_API_KEY=\nVT_USER_ID=\n")
        print(
            f"\n{C.YELLOW}ACTION REQUIRED: Add your API key and User ID to the '{ENV_FILE.name}' file.{C.RESET}"
        )
    print("\nSetup complete. You can now run the script normally.")


def setup_logging():
    """Configures the logging format and level."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def load_json_config(file_path, default=None):
    """
    Loads a JSON file, handling errors and gracefully falling back to a .bak file if available.
    """
    if not file_path.exists():
        if default is not None:
            logging.warning(f"'{file_path.name}' not found. Using default settings.")
            return default
        logging.error(f"Required config file '{file_path.name}' not found.")
        return None

    try:
        # First, try to load the primary file
        return json.loads(file_path.read_text())
    except json.JSONDecodeError:
        logging.warning(
            f"{C.YELLOW}WARNING: Syntax error in '{file_path.name}'. The file is malformed.{C.RESET}"
        )
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")

        if backup_path.exists():
            logging.warning(
                f"Attempting to fall back to the last known good configuration: '{backup_path.name}'"
            )
            try:
                # If the primary fails, try to load the backup
                backup_config = json.loads(backup_path.read_text())
                print(
                    f"{C.GREEN}Successfully loaded the backup configuration. The script will continue.{C.RESET}"
                )
                print(
                    f"{C.YELLOW}ACTION REQUIRED: Please fix the syntax errors in '{file_path.name}' before the next run.{C.RESET}"
                )
                return backup_config
            except json.JSONDecodeError:
                # If the backup is ALSO broken, then we must stop.
                logging.critical(
                    f"CRITICAL: The backup file '{backup_path.name}' is also corrupted. Cannot proceed."
                )
                return None
        else:
            # If there's no backup to fall back to, we must stop.
            logging.critical(
                f"CRITICAL: '{file_path.name}' is corrupted and no backup file was found. Cannot proceed."
            )
            return None


_CONFIG = load_json_config(APP_CONFIG_FILE, default=DEFAULT_CONFIG)


def get_config() -> dict:
    """Returns the loaded application configuration."""
    if _CONFIG is None:
        logging.critical(
            "Could not load application configuration from 'config.json'. Exiting."
        )
        sys.exit(1)
    return _CONFIG


class ApiQuotaTracker:
    """Fetches and displays the final VirusTotal API quota."""

    def __init__(self, api_key, user_id):
        self.api_key = api_key
        self.user_id = user_id

    def fetch_and_print_quota(self):
        """Fetches the latest API quota from VirusTotal and prints a summary."""
        if not self.user_id or not self.api_key:
            print(
                f"\n{C.YELLOW}Cannot fetch quota. VT_USER_ID or VIRUSTOTAL_API_KEY is missing.{C.RESET}"
            )
            return

        api_url = (
            f"https://www.virustotal.com/api/v3/users/{self.user_id}/overall_quotas"
        )
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(api_url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json().get("data", {})

            # Daily Quota
            daily_data = data.get("api_requests_daily", {}).get("user", {})
            daily_allowed = daily_data.get("allowed", 0)
            daily_used = daily_data.get("used", 0)
            daily_remaining = daily_allowed - daily_used

            # Hourly Quota
            hourly_data = data.get("api_requests_hourly", {}).get("user", {})
            hourly_allowed = hourly_data.get("allowed", 0)
            hourly_used = hourly_data.get("used", 0)
            hourly_remaining = hourly_allowed - hourly_used

            print(f"\n{C.BRIGHT}--- VirusTotal API Quota ---{C.RESET}")
            print(
                f"Daily Usage:  {daily_used}/{daily_allowed} ({C.GREEN}{daily_remaining} remaining{C.RESET})"
            )
            print(
                f"Hourly Usage: {hourly_used}/{hourly_allowed} ({C.GREEN}{hourly_remaining} remaining{C.RESET})"
            )

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                print(
                    f"\n{C.RED}ERROR: Failed to fetch API quota: 403 Forbidden.{C.RESET}"
                )
                print(
                    f"{C.YELLOW}This error means your 'VT_USER_ID' in the .env file does not match your 'VIRUSTOTAL_API_KEY'.{C.RESET}"
                )
                print(
                    f"{C.CYAN}Please log in to VirusTotal, find your User ID in the 'API Key' section of your profile, and correct the .env file.{C.RESET}"
                )
            else:
                print(f"\n{C.RED}Failed to fetch final API quota: {e}{C.RESET}")
        except requests.exceptions.RequestException as e:
            print(
                f"\n{C.RED}Failed to fetch final API quota due to a network error: {e}{C.RESET}"
            )
        except json.JSONDecodeError:
            print(f"\n{C.RED}Failed to parse API quota response.{C.RESET}")


_QUOTA_TRACKER: ApiQuotaTracker | None = None


def get_quota_tracker() -> ApiQuotaTracker:
    """Returns the singleton instance of the ApiQuotaTracker."""
    if _QUOTA_TRACKER is None:
        logging.critical("Quota tracker was not initialized. Critical program error.")
        sys.exit(1)
    return _QUOTA_TRACKER


def initialize_project():
    """Initializes project directories, loads environment variables, and sets up the quota tracker."""
    print(f"{C.BRIGHT}{C.MAGENTA}============================================{C.RESET}")
    print(f"{C.BRIGHT}{C.MAGENTA}=== Hybrid Playlist Scanner v4.6 (Final) ==={C.RESET}")
    print(f"{C.BRIGHT}{C.MAGENTA}============================================{C.RESET}")

    import os

    from dotenv import load_dotenv

    load_dotenv(dotenv_path=ENV_FILE)
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    user_id = os.getenv("VT_USER_ID")

    if not api_key:
        logging.critical(f"VIRUSTOTAL_API_KEY not found in '{ENV_FILE.name}'.")
        logging.critical(
            "Run with the --init flag to create the file, then add your key."
        )
        sys.exit(1)

    global _QUOTA_TRACKER
    _QUOTA_TRACKER = ApiQuotaTracker(api_key=api_key, user_id=user_id)

    for dir_path in [INPUT_DIR, CLEAN_DIR, REPORTS_DIR, LOGS_DIR]:
        dir_path.mkdir(exist_ok=True)

    return {
        "new_scans_count": 0,
        "total_links_checked": 0,
        "dead_links_count": 0,
        "urls_submitted_to_vt": 0,
    }
