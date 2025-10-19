# 🛰️ IPTV Playlist Manager & Scanner

A powerful, command-line tool designed to automate the cleaning, maintenance, and security scanning of your IPTV M3U playlists. This script fetches remote and local playlists concurrently, checks every link's health, scans domains against the VirusTotal API for threats, and generates a single, de-duplicated master playlist based on your custom rules.

The goal is to provide a "set it and forget it" solution: run the script, update a single online file, and have all your IPTV players refresh automatically with clean, reliable, and safe content.

## ✨ Key Features

- **⚡ High-Speed Concurrent Fetching**: Downloads all remote playlists simultaneously, dramatically reducing wait times.

- **🔗 Universal Playlist Aggregation**: Gathers playlists from remote URLs (`playlists.json`) and local files (`input_playlists/`).

- **❤️ Advanced Link Health Validation**: Asynchronously checks thousands of links for live status and valid stream content types, ensuring a high-quality playlist.

- **🛡️ VirusTotal Security Scanning**: Scans every unique domain against the VirusTotal database to identify and block domains associated with malware or suspicious activity.

- **🧠 Intelligent Caching & Resuming**: Caches scan results to avoid wasting API calls and can resume an interrupted scan session right where it left off, saving your progress.

- **📜 Rule-Based Cleaning**: Automatically removes channels based on highly configurable rules in `config.json` (e.g., block if a domain has 1+ malicious detection).

- **🎯 MASTER PLAYLIST - Intelligent Merging & De-duplication**:
  - Automatically combines all clean playlists into a single `_MASTER_PLAYLIST.m3u`.
  - Smartly removes entries with duplicate stream URLs to eliminate redundancy while keeping channels with the same name but different, valid stream sources.

- **📊 Comprehensive Reporting**: Generates a detailed `summary_report.md` with run statistics, a health overview for each playlist, and a full audit trail of all removed content.

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

Open the newly created `.env` file. You must add your VirusTotal API Key and User ID.

1. Log in to [VirusTotal.com](https://www.virustotal.com).
2. Click your user icon in the top-right and select **API Key**.
3. Copy your **User ID** and **API Key** into the `.env` file.

```env
# .env
VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE
VT_USER_ID=YOUR_USER_ID_HERE
```

> **⚠️ Warning**  
> Your API Key and User ID must belong to the same account, or you will receive a 403 Forbidden error when the script tries to fetch your API quota.

### 5. Configure Your Playlists

- **Remote Playlists**: Edit `playlists.json` to add URLs of playlists you want to download automatically. The key is the filename it will be saved as.

```json
{
  "playlist_one.m3u": "https://example.com/playlist1.m3u",
  "another_list.m3u8": "https://example.com/playlist2.m3u8"
}
```

- **Local Playlists**: Place any local `.m3u` or `.m3u8` files directly into the `input_playlists/` directory.

## 🛠️ Usage

Once configured, running the script is simple.

### Run the Full Workflow

This command will fetch, health-check, scan, clean, and generate your master playlist.

```bash
python main.py
```

### Command-Line Arguments

- `--skip-health-check`: (Optional) Bypass the slow link health check phase. Useful if you only want to perform a security scan.
- `--force-rescan`: (Optional) Force a rescan of all domains, ignoring the cached results in `reports/scan_results.json`.
- `--init`: (Setup only) Creates the default configuration files.

## 🎯 Workflow: The "One Playlist to Rule Them All" Method

This script is designed to give you a single, stable URL for all your players.

### Step 1: Run the Script Locally

Execute the script. It will process everything and create `_MASTER_PLAYLIST.m3u` in the `clean_playlists/` folder.

```bash
python main.py
```

### Step 2: Host Your Master Playlist on GitHub Gist

1. Navigate to [gist.github.com](https://gist.github.com).
2. Create a new Gist (or edit an existing one).
3. **Filename**: Name the Gist file `iptv_master.m3u` (or any name you prefer).
4. **Content**: Open the local `clean_playlists/_MASTER_PLAYLIST.m3u` file, copy its entire content, and paste it into the Gist.
5. Click **"Create public Gist"** or **"Update public Gist"**.

### Step 3: Get the Raw URL and Add to Your Player

1. On your Gist page, click the **"Raw"** button.
2. Copy the URL from your browser's address bar. This is your permanent playlist URL.
3. Add this single URL to your IPTV player (Tivimate, IPTV Smarters, etc.).

Now, your maintenance routine is simple: Run the script, then update the Gist content. Your players will automatically pull the changes without you ever touching their settings again.

## 📄 Configuration Explained (config.json)

Fine-tune the script's behavior by editing `config.json`.

### decision_rules

- `malicious_threshold`: Block a domain if it has this many (or more) "malicious" votes on VirusTotal. `1` is a good default.
- `whitelist_domains`: A list of domains that will never be blocked.
- `force_block_domains`: A list of domains that will always be blocked.

### features

- `check_link_health`: Master switch to enable or disable the link health check phase.
- `auto_remove_dead_links`: If true, dead links will be removed from the final playlists.
- `rescan_results_after_days`: How old a cached scan result can be before it's considered "expired" and needs to be rescanned.

### network_settings

- `playlist_timeout_seconds`: How long to wait when downloading a remote playlist.
- `link_check_timeout_seconds`: How long to wait for a response from an individual stream URL.

## 📋 Output

- `clean_playlists/`: Contains the processed `.m3u` files for each source, plus the de-duplicated `_MASTER_PLAYLIST.m3u`.
- `reports/summary_report.md`: A detailed report of the last run.
- `reports/scan_results.json`: The local cache of VirusTotal scan results.

## ⚖️ License

This project is licensed under the MIT License.

---

**Made with ❤️ for IPTV enthusiasts who value quality, security, and automation.**