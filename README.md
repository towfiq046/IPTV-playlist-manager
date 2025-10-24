# 🛰️ IPTV Playlist Manager & Scanner

A powerful, robust, and self-healing command-line tool designed to completely automate the maintenance and security of your IPTV M3U playlists.

This script fetches remote and local playlists concurrently, validates every link's health, scans domains against VirusTotal for threats, and generates a single, de-duplicated master playlist. It's architected with safety first: your configuration is automatically backed up, and the script can even recover from syntax errors in your config file, ensuring it runs reliably every time.

The goal is a true **"set-it-and-forget-it"** solution: run the script, update a single online file, and have all your IPTV players refresh automatically with clean, reliable, and safe content.

---

## ✨ Key Features

* 🛡️ **Safety First – Automatic Backups & Fallback**

  * Your `playlists.json` is always safe. The script automatically creates a `.bak` file before making any changes.
  * If you make a syntax error in `playlists.json`, the script won't crash. It will gracefully fall back to the last known good backup and continue running, warning you to fix the file.

* 🧠 **Self-Healing Automation**

  * **Auto-Disables Dead Playlists:** If a playlist URL returns a `404 Not Found`, it's automatically moved to a `disabled_playlists` section in your config.
  * **Auto Re-enables Live Playlists:** The script periodically re-checks disabled playlists. If one comes back online, it's automatically re-enabled and moved back to the active list.

* 👑 **Intelligent Master Playlist Creation**

  * Combines all your clean sources into a single, unified `_MASTER_PLAYLIST.m3u`.
  * Smartly de-duplicates by stream URL, eliminating true redundancy while preserving unique backup streams for the same channel.

* ⚡ **High-Speed Concurrent Fetching:** Downloads all remote playlists simultaneously, dramatically reducing startup time.

* ❤️ **Advanced Link Health Validation:** Asynchronously checks thousands of links for live status and valid stream content types.

* 🛡️ **VirusTotal Security Scanning:** Scans every unique domain against the VirusTotal database to identify and block malicious sources.

* 📊 **Comprehensive & Accurate Reporting:** Generates a `reports/summary_report.md` with:

  * A new Master Playlist summary.
  * A Source Management section detailing which playlists were auto-enabled or disabled.
  * A clean and accurate overview of all actions taken.

---

## ⚙️ Requirements

* Python **3.10+**
* `uv` (recommended for fast dependency management)
* A free VirusTotal API Key

---

## 🚀 Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/IPTV-playlist-manager.git
cd IPTV-playlist-manager
```

### 2. Install Dependencies

```bash
uv pip sync
```

### 3. Run Initial Setup

This creates the essential configuration files (`config.json`, `playlists.json`, `.env`).

```bash
python main.py --init
```

### 4. Configure Your Credentials (CRITICAL STEP)

Open the newly created `.env` file and add your VirusTotal API Key and User ID.

> Log in to `VirusTotal.com`, click your user icon (top-right) and select **API Key**.

```dotenv
# .env
VIRUSTOTAL_API_KEY=YOUR_API_KEY_HERE
VT_USER_ID=YOUR_USER_ID_HERE
```

> **Warning:** Your API Key and User ID must belong to the **same account**, or you will receive a `403 Forbidden` error.

### 5. Add Your Playlists

Edit `playlists.json` to add remote URLs, or place local `.m3u` files in the `input_playlists/` directory.

---

## 🛠️ The "One Playlist" Workflow

This script is designed to give you a single, stable URL for all your players.

**Step 1: Run the Script Locally**

```bash
python main.py
```

**Step 2: Host Your Master Playlist on GitHub Gist**

1. Navigate to [https://gist.github.com](https://gist.github.com).
2. Create a new Gist (or edit an existing one).

   * **Filename:** `iptv_master.m3u`
   * **Content:** Open the local `clean_playlists/_MASTER_PLAYLIST.m3u` file, copy its content, and paste it into the Gist.
3. Click **Create public Gist** or **Update public Gist**.

**Step 3: Get the Raw URL and Add to Your Player**

1. On your Gist page, click the **Raw** button.
2. Copy the URL from your browser's address bar. This is your permanent playlist URL.
3. Add this single URL to your IPTV player (Tivimate, etc.).

Your routine is now simple: Run the script, then update the Gist content. Your players will automatically pull the changes.

---

## 📄 Configuration Files Explained

### `config.json`

Fine-tune the script's behavior.

* `decision_rules`:

  * `malicious_threshold`: Block a domain if it has this many "malicious" votes.
  * `force_block_domains`: A list of domains (e.g., `"example.com"`) to always block.
  * `whitelist_domains`: A list of domains to never block.

* `features`:

  * `recheck_disabled_after_days`: (New!) How many days to wait before re-checking a disabled playlist to see if it's back online. Set to `0` to disable.
  * `auto_remove_dead_links`: If `true`, dead links will be removed.
  * `rescan_results_after_days`: How old a cached VirusTotal scan can be before a re-scan.

* `network_settings`:

  * Timeouts for downloading playlists and checking links.

### `playlists.json`

This file now has a new, more robust structure. The script will automatically upgrade your old file if needed.

```json
{
  "playlists_to_fetch": {
    "playlist_one.m3u": "https://example.com/playlist1.m3u",
    "another_list.m3u8": "https://example.com/playlist2.m3u8"
  },
  "disabled_playlists": {
    "dead_list.m3u": {
      "url": "https://example.com/dead.m3u",
      "disabled_on": "2025-10-26T10:00:00.000000"
    }
  }
}
```

* `playlists_to_fetch`: Your active playlist URLs.
* `disabled_playlists`: Playlists the script has automatically disabled because they returned a `404 Not Found`. The script manages this section for you.

---

## 📋 Output

* `clean_playlists/`: Contains the processed `.m3u` files and the final `_MASTER_PLAYLIST.m3u`.
* `reports/summary_report.md`: The detailed, accurate report of the last run.
* `playlists.json.bak`: A backup of your playlist configuration, created before any changes are made.

---

## ⚖️ License

This project is licensed under the **MIT License**.

---