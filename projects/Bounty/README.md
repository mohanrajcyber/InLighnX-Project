Perfect 👍 since your script is ready and dependencies are sorted, let’s make a **README.md** for your project so anyone can set it up and run it easily on Kali/Parrot.

Here’s a clean draft:

---

# Cloud Software Group Bug Bounty Recon Script

## 📌 Overview

This script automates reconnaissance for bug bounty programs.
It installs commonly used recon tools, runs them against chosen targets, scrapes endpoints, filters results, and generates an HTML summary report.

⚠️ **Use only on authorized assets (in-scope bug bounty programs). Unauthorized usage may be illegal.**

---

## ✨ Features

* Auto installation & check for popular recon tools:

  * `gau`, `katana`, `amass`, `subfinder`, `assetfinder`, `httpx`, `gobuster`, `ffuf`, `nmap`, `nikto`
* Subdomain enumeration & URL discovery
* Directory & fuzzing scans
* JS endpoint extraction
* Nikto scan with filtered results
* Out-of-scope filtering
* HTML summary report generation
* Option to zip results for sharing

---

## 🔧 Requirements

### System

* Python 3.9+
* Go (`apt install golang -y`)
* Internet connection
* VPN connection (if required by program)

### Python Dependencies

* `rich`
* `requests`

Install via virtual environment:

```bash
sudo apt install python3-venv -y
python3 -m venv venv
source venv/bin/activate
pip install rich requests
```

Or via apt:

```bash
sudo apt install python3-rich python3-requests -y
```

---

## 🚀 Usage

1. Clone your project and move into it:

   ```bash
   git clone https://github.com/YourUser/YourRepo.git
   cd YourRepo
   ```

2. Ensure your public IP is whitelisted:

   ```bash
   echo "YOUR_PUBLIC_IP" > whitelisted_ips.txt
   ```

   (Check with `curl ifconfig.me`)

3. Run the script:

   ```bash
   python3 recon.py
   ```

4. Follow the prompts:

   * Confirm VPN connection
   * Choose target asset
   * Provide a wordlist path
   * (Optional) add out-of-scope filters

5. Reports:

   * Results saved in `results_YYYYMMDD_HHMMSS/`
   * HTML summary: `summary.html`
   * Optional zipped archive

---

## 📂 Example Output

```
results_20250829_153500/
├── amass_output.txt
├── ffuf_output.json
├── gau_output.txt
├── gobuster_output.txt
├── httpx_output.txt
├── katana_output.txt
├── nmap_output.txt
├── nikto_filtered.txt
├── subfinder_output.txt
├── all_discovered_urls.txt
├── summary.html
```

---

## ⚠️ Disclaimer

This project is intended **only for educational purposes and legal bug bounty hunting.**
You are responsible for ensuring you have proper authorization before scanning any target.

---

