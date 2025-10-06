# 🛰️ IPTV Playlist Manager & Scanner

A powerful, command-line tool designed to automate the cleaning, maintenance, and security scanning of your IPTV M3U playlists. This script fetches remote and local playlists, checks every link's health, scans domains against the VirusTotal API for threats, and generates clean, safe playlist files based on your custom rules.

*(Note: You can replace this with a real screenshot of your tool in action!)*

## ✨ Key Features

- **Automatic Playlist Fetching**: Gathers playlists from remote URLs (`playlists.json`) and local files (`input_playlists/` directory).

- **Link Health Validation**: Asynchronously checks thousands of links to identify and flag dead or unresponsive streams, ensuring a high-quality playlist.

- **VirusTotal API Integration**: Scans every unique domain against the VirusTotal database to identify and block domains associated with malware or suspicious activity.

- **Intelligent Caching & Resuming**: Caches scan results to avoid wasting API calls and can resume an interrupted scan session right where it left off.

- **Rule-Based Cleaning**: Automatically removes channels based on configurable rules in `config.json` (e.g., block if a domain has 1+ malicious detection).

- **Detailed Reporting**: Generates a comprehensive `summary_report.md` with run statistics, a health overview for each playlist, and a full audit trail of all removed content.

- **Modern CLI**: Clean, colorful, and informative command-line interface with progress bars.

## ⚙️ Requirements

- Python 3.10+
- `uv` (for fast dependency management)
- A free VirusTotal API Key

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/IPTV-playlist-manager.git
cd IPTV-playlist-manager
```

### 2. Install Dependencies

This project uses `uv` for fast and reliable dependency installation.

```bash
uv pip sync
```

### 3. Run Initial Setup

Run the script with the `--init` flag. This will create the essential configuration files (`config.json`, `playlists.json`, `.env`) if they don't exist.

```bash
python main.py --init
```

### 4. Configure Your Credentials (CRITICAL STEP)

Open the newly created `.env` file. You **must** add your VirusTotal API Key and User ID.

- Log in to [VirusTotal.com](https://www.virustotal.com/).
- Click your user icon in the top-right and select **API Key**.
- Copy your **User ID** and **API Key** into the `.env` file.

```dotenv
# .env
VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE
VT_USER_ID=YOUR_USER_ID_HERE
```

> **Warning**  
> Your API Key and User ID must belong to the same account, or you will receive a 403 Forbidden error when the script tries to fetch your API quota.

### 5. Configure Your Playlists

**Remote Playlists**: Edit `playlists.json` to add URLs of playlists you want to download automatically. The key is the filename it will be saved as.

```json
{
  "my_favorite_playlist.m3u": "https://example.com/playlist.m3u",
  "another_playlist.m3u": "https://another_example.com/playlist.m3u"
}
```

**Local Playlists**: Place any local `.m3u` or `.m3u8` files directly into the `input_playlists/` directory.

## 🛠️ Usage

Once configured, running the script is simple.

### Run the Full Workflow

This command will fetch, health-check, scan, clean, and report on all your playlists.

```bash
python main.py
```

### Command-Line Arguments

**`--skip-health-check`**: (Optional) Bypass the slow link health check phase. Useful if you only want to perform a security scan.

```bash
python main.py --skip-health-check
```

**`--force-rescan`**: (Optional) Force a rescan of all domains, ignoring the cached results in `reports/scan_results.json`.

```bash
python main.py --force-rescan
```

**`--init`**: (Setup only) Creates the default configuration files.

## 📄 Configuration Files Explained

You can fine-tune the script's behavior by editing `config.json`.

```json
{
  "decision_rules": {
    "malicious_threshold": 1,
    "suspicious_threshold": 5,
    "block_on_suspicious": false,
    "whitelist_domains": ["example.com"],
    "force_block_domains": ["malicious-domain.org"]
  },
  "features": {
    "check_link_health": true,
    "auto_remove_dead_links": false,
    "rescan_results_after_days": 30
  },
  "network_settings": {
    "playlist_timeout_seconds": 30,
    "link_check_timeout_seconds": 10,
    "vt_retries": 2,
    "valid_stream_content_types": [
      "video/", "application/vnd.apple.mpegurl", "..."
    ]
  }
}
```

### decision_rules:

- **`malicious_threshold`**: Block a domain if it has this many (or more) "malicious" votes on VirusTotal. 1 is a good default.
- **`whitelist_domains`**: A list of domains that will never be blocked, regardless of scan results.
- **`force_block_domains`**: A list of domains that will always be blocked, regardless of scan results.

### features:

- **`check_link_health`**: Master switch to enable or disable the link health check phase.
- **`auto_remove_dead_links`**: If true, dead links will be removed from the final playlists.
- **`rescan_results_after_days`**: How old a cached scan result can be before it's considered "expired" and needs to be rescanned.

### network_settings:

- **`playlist_timeout_seconds`**: How long to wait when downloading a remote playlist.
- **`link_check_timeout_seconds`**: How long to wait for a response from an individual stream URL during the health check.

## 📋 Output

After a successful run, you will find the following in your project directory:

- **`clean_playlists/`**: This directory contains the final, processed `.m3u` files with malicious channels (and optionally, dead links) removed.

- **`reports/summary_report.md`**: A detailed report of the last run, perfect for reviewing what was changed and why.

- **`reports/scan_results.json`**: The local cache of VirusTotal scan results. Deleting this file will cause all domains to be scanned again on the next run.

## ⚖️ License

This project is licensed under the MIT License. See the LICENSE file for details.