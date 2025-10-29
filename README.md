# IPTV Manager & Zero-Tolerance Scanner

![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)

A powerful, automated tool for fetching, cleaning, and security-scanning IPTV playlists. This script ensures a safe, high-quality, and de-duplicated viewing experience by leveraging the VirusTotal API in a highly efficient manner.

The core philosophy is **"Zero-Tolerance"**: if any URL (stream, logo, EPG, etc.) within a channel's entry is associated with a malicious or suspicious domain, that specific stream is rigorously removed, guaranteeing the cleanliness of your final playlists.

## 🏆 Key Features

- **Comprehensive Security Scanning**: Scans every URL found in your playlists—not just the stream links—including EPG sources (`url-tvg`) and channel logos (`tvg-logo`)

- **Zero-Tolerance Cleaning**: Any stream entry associated with a domain exceeding your defined malicious or suspicious thresholds is completely removed

- **Redirect Chain Resolution**: Intelligently follows URL redirect chains to scan the true, final destination of a link, uncovering hidden threats

- **Dual Clean Output**: Generates both individually cleaned versions of your source playlists and a merged, de-duplicated master playlist

- **Intelligent De-duplication**: The final master playlist contains only unique stream URLs, taking the first-seen version of any channel

- **Automated Source Management**: Automatically disables playlist sources that are offline (404) and re-enables them when they come back online

- **Detailed Reporting**: Creates a professional, easy-to-read Markdown report (`summary_report.md`) with key metrics, source status, and a list of all domains that were blocked and why

- **Independent Verification Script**: Includes a standalone script (`verify_cleanliness.py`) to audit the final master playlist and mathematically prove its cleanliness

- **Efficient API Usage**: Prioritizes free report lookups from VirusTotal and only uses your API quota to submit new, unknown URLs for analysis

## 🚀 How It Works

The script operates in a clear, multi-phase workflow:

### Phase 1: Fetch & Resolve
- Fetches all active remote playlists defined in `playlists.json`
- Reads all local playlists from the `input_playlists/` directory
- Discovers every single URL (http/https) from all files
- Resolves all URL redirect chains to build a comprehensive map of final destinations

### Phase 2: Scan
- Creates a master list of all unique domains discovered
- Checks for existing VirusTotal reports for these domains (free)
- Submits any new or unknown domains for analysis (uses API quota)
- Saves all results to `reports/scan_results.json` to cache them for future runs

### Phase 3: Clean & Merge
- Processes each playlist file individually
- For each channel entry, it checks all associated domains against your zero-tolerance rules
- It saves a clean version of each individual playlist
- It adds the clean, unique streams to a master playlist, ensuring no duplicate stream URLs

### Phase 4: Report
- Generates the `summary_report.md` with detailed statistics and insights from the run

## 🔧 Installation & Setup

**Prerequisites**: Python 3.10+

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd iptv-manager-project
```

### 2. Set Up a Virtual Environment

This project uses `uv` for fast dependency management.

```bash
# Create the virtual environment
uv venv

# Activate it (Linux/macOS)
source .venv/bin/activate

# Activate it (Windows)
.venv\Scripts\activate
```

### 3. Install Dependencies

`uv` will install the exact versions from the lock file.

```bash
uv pip sync
```

### 4. Run Initial Setup

This crucial command creates the default configuration files you need to edit.

```bash
python main.py --init
```

### 5. Edit Configuration Files

After running `--init`, you will have new files. Edit them as follows:

#### `.env` (Required)
Add your VirusTotal API key and User ID. You can find these in your VirusTotal account under the API Key section.

```ini
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
VT_USER_ID=your_virustotal_user_id_or_username
```

#### `playlists.json` (Required)
Add the remote playlists you want to fetch. The key is the filename it will be saved as.

```json
{
  "playlists_to_fetch": {
    "my_awesome_list.m3u": "http://example.com/playlist.m3u",
    "another_list.m3u8": "http://another.com/list.m3u8"
  },
  "disabled_playlists": {}
}
```

You can also place `.m3u` or `.m3u8` files directly into the `input_playlists/` directory.

#### `config.json` (Optional)
The default settings are excellent, but you can fine-tune the script's behavior here. The most important section is `zero_tolerance_rules`.

```json
{
  "zero_tolerance_rules": {
    "max_malicious_count": 0,  // Block if malicious votes are > 0
    "max_suspicious_count": 2   // Block if suspicious votes are > 2
  }
}
```

## ▶️ Usage

To run the main script:

```bash
python main.py
```

### Command-Line Arguments

- `--skip-health-check`: Bypasses the optional (and slow) check for dead stream links. Cleaning is still performed.
- `--force-rescan`: Forces a re-scan of all domains on VirusTotal, ignoring any cached results in `scan_results.json`.
- `--init`: Use this only for the very first setup.

### Verifying the Results

After a run, you can use the standalone verification script to audit the master playlist:

```bash
python verify_cleanliness.py
```

This script acts as an independent auditor and will either give a "SUCCESS" or "FAILURE" message, proving that the cleaning process worked as expected.

## 📁 Project Structure

```
IPTV_Manager/
├── 📄 .env                     # Your API keys (secret)
├── 📄 config.json              # Main script configuration
├── 📄 playlists.json           # List of remote playlists to fetch
├── 🐍 main.py                  # The main entry point to run the script
├── 🐍 verify_cleanliness.py    # Standalone audit script
│
├── 📁 iptv_manager/            # Core logic modules
│   ├── 🐍 cleaner.py           # Zero-tolerance cleaning and parsing logic
│   ├── 🐍 config_loader.py     # Handles loading all configs and paths
│   ├── 🐍 playlist_manager.py  # Fetches and manages playlist sources
│   ├── 🐍 report_generator.py  # Creates the summary_report.md
│   ├── 🐍 url_resolver.py      # Resolves redirect chains
│   ├── 🐍 utils.py             # Small helper functions
│   └── 🐍 vt_scanner.py        # All VirusTotal API interaction
│
├── 📁 input_playlists/         # Place local .m3u files here
├── 📁 clean_playlists/         # OUTPUT: Cleaned individual and master playlists
└── 📁 reports/                 # OUTPUT: Summary report and scan results
```

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.

---

**Stay Safe. Stay Clean. Zero Tolerance.**