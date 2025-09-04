#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import shutil
import sys
import re
import requests
import datetime
import zipfile
from rich import print
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel
from pathlib import Path
from collections import Counter

console = Console()

# --------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------

TOOLS = [
    "gau",
    "katana",
    "amass",
    "subfinder",
    "assetfinder",
    "httpx",
    "gobuster",
    "ffuf",
    "nmap",
    "nikto",
]

INSTALL_CMDS = {
    "gau": ["go", "install", "github.com/lc/gau/v2/cmd/gau@latest"],
    "katana": ["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"],
    "amass": ["apt", "install", "-y", "amass"],
    "subfinder": ["go", "install", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    "assetfinder": ["go", "install", "github.com/tomnomnom/assetfinder@latest"],
    "httpx": ["go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    "gobuster": ["apt", "install", "-y", "gobuster"],
    "ffuf": ["go", "install", "github.com/ffuf/ffuf@latest"],
    "nmap": ["apt", "install", "-y", "nmap"],
    "nikto": ["apt", "install", "-y", "nikto"],
}

VALID_ASSETS = [
    "citrix.cloud.com",
    "citrixworkspaceapi.net",
    "eu.cloud.com",
    "us.cloud.com",
    "onboarding.cloud.com",
    "accounts.cloud.com",
    "accounts-internal.cloud.com",
]

DEFAULT_OOS = [
    ".cdn.cloud.com",
    ".blog.cloud.com",
    ".partner.cloud.com",
    ".support.cloud.com",
    ".status.cloud.com",
]

NIKTO_FILTER_PATTERNS = [
    "HTTPOnly",
    "X-Frame-Options",
    "Strict-Transport",
    "robots.txt",
    "Allowed HTTP Methods",
    "TLSv1",
    "SSLv2",
    "SSLv3",
    "Server leaks",
]

# --------------------------------------------------------
# UTILITY FUNCTIONS
# --------------------------------------------------------

def check_tool(tool):
    path = shutil.which(tool)
    if path:
        return True
    go_path = os.path.expanduser(f"~/go/bin/{tool}")
    return os.path.isfile(go_path) and os.access(go_path, os.X_OK)

def install_tool(tool):
    if tool not in INSTALL_CMDS:
        console.print(f"[red][!] No install command for {tool}. Install manually.[/red]")
        return
    console.print(f"[cyan]Installing {tool}...[/cyan]")
    subprocess.run(INSTALL_CMDS[tool])

    go_binary = os.path.expanduser(f"~/go/bin/{tool}")
    if os.path.exists(go_binary):
        target_path = f"/usr/local/bin/{tool}"
        try:
            shutil.copy(go_binary, target_path)
            os.chmod(target_path, 0o755)
            console.print(f"[green]Installed {tool} to {target_path}[/green]")
        except PermissionError:
            console.print(f"[red]Permission denied copying {tool} to {target_path}. Run as root.[/red]")

def install_missing_tools():
    missing = []
    table = Table(title="Tool Check Results", show_lines=True, style="cyan")
    table.add_column("Tool")
    table.add_column("Status")
    for tool in TOOLS:
        if check_tool(tool):
            table.add_row(tool, "[green]✓ Installed[/green]")
        else:
            table.add_row(tool, "[red]✗ Missing[/red]")
            missing.append(tool)
    console.print(table)
    if missing:
        console.print(Panel("[yellow]Installing missing tools...[/yellow]"))
        for tool in missing:
            install_tool(tool)
        console.print(Panel("[bold green]Tool installation complete![/bold green]"))
    else:
        console.print(Panel("[bold green]All tools installed![/bold green]"))

def run_command(cmd, desc, outfile=None):
    console.print(f"\n[bold yellow][+] Running: {desc}[/bold yellow]")
    console.print("[dim]" + " ".join(cmd) + "[/dim]\n")

    if outfile:
        with open(outfile, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False)
    else:
        subprocess.run(cmd, check=False)

def scrape_js_for_endpoints(js_url, verify_ssl=True):
    endpoints = []
    try:
        resp = requests.get(js_url, verify=verify_ssl, timeout=10)
        if resp.status_code == 200:
            regex = r'["\']https?://[^"\']+'
            matches = re.findall(regex, resp.text)
            endpoints.extend([m.strip('"\'') for m in matches])
    except Exception as e:
        console.print(f"[red][!] Error fetching JS {js_url}: {e}[/red]")
    return endpoints

def process_urls(urls, out_of_scope=[]):
    return list(set(u for u in urls if not any(oos in u for oos in out_of_scope)))

def clean_domain(url):
    return url.replace("https://", "").replace("http://", "").split("/")[0]

def check_ip_whitelisted():
    my_ip = requests.get("https://api.ipify.org").text.strip()
    console.print(f"[green]Detected your public IP: {my_ip}[/green]")
    if not os.path.exists("whitelisted_ips.txt"):
        console.print("[red]No whitelisted_ips.txt file found. Exiting.[/red]")
        sys.exit(1)
    with open("whitelisted_ips.txt") as f:
        allowed_ips = [x.strip() for x in f if x.strip()]
    if my_ip not in allowed_ips:
        console.print("[red]Your IP is NOT whitelisted. Exiting.[/red]")
        sys.exit(1)
    else:
        console.print("[green]Your IP is whitelisted.[/green]")

def run_nikto(domain, output_dir):
    temp_file = os.path.join(output_dir, "nikto_raw.txt")
    filtered_file = os.path.join(output_dir, "nikto_filtered.txt")

    run_command(["nikto", "-h", domain, "-output", temp_file], f"Nikto scan on {domain}")

    if os.path.exists(temp_file):
        filtered_output = []
        for line in open(temp_file):
            if not any(pattern in line for pattern in NIKTO_FILTER_PATTERNS):
                filtered_output.append(line)
        with open(filtered_file, "w") as f:
            f.writelines(filtered_output)
        os.remove(temp_file)
        console.print(f"[green]Nikto scan complete. Filtered results saved to {filtered_file}[/green]")
        return filtered_file
    else:
        return None

def generate_html_report(report_path, summary, discovered_urls, tool_files):
    with open(report_path, "w") as f:
        f.write("<html><body>\n")
        f.write(f"<h1>Recon Summary ({datetime.datetime.now()})</h1>\n")

        f.write("<h2>Summary</h2>\n<ul>\n")
        for item, value in summary.items():
            f.write(f"<li><b>{item}:</b> {value}</li>\n")
        f.write("</ul>\n")

        f.write("<h2>Tool Outputs</h2>\n<ul>\n")
        for tool, path in tool_files.items():
            rel_path = os.path.relpath(path, os.path.dirname(report_path))
            f.write(f"<li><a href='{rel_path}'>{tool} output</a></li>\n")
        f.write("</ul>\n")

        f.write("<h2>Sample URLs</h2>\n<ul>\n")
        for url in discovered_urls[:20]:
            f.write(f"<li>{url}</li>\n")
        f.write("</ul>\n")

        f.write("</body></html>\n")

    console.print(f"[green]HTML report written to {report_path}[/green]")

# --------------------------------------------------------
# MAIN
# --------------------------------------------------------

def main():
    console.print(Panel("[bold green]Cloud Software Group Bug Bounty Recon Script[/bold green]"))

    install_missing_tools()

    vpn_connected = Confirm.ask("[cyan]Are you connected to VPN?[/cyan]", default=True)
    if not vpn_connected:
        console.print("[red]Please connect VPN first.[/red]")
        sys.exit(1)

    check_ip_whitelisted()

    # Let user pick asset
    console.print("\n[cyan]Select asset to scan:[/cyan]")
    for i, asset in enumerate(VALID_ASSETS, start=1):
        console.print(f"[{i}] {asset}")
    choice = Prompt.ask("Enter asset number")
    try:
        asset_index = int(choice) - 1
        target = VALID_ASSETS[asset_index]
    except:
        console.print("[red]Invalid choice. Exiting.[/red]")
        sys.exit(1)

    domain = clean_domain(target)

    wordlist = Prompt.ask("[cyan]Enter path to wordlist[/cyan]")

    # Add OOS if user wants
    console.print(Panel("Default out-of-scope filters:\n" + "\n".join(DEFAULT_OOS)))
    if Confirm.ask("[yellow]Add more out-of-scope keywords/domains?[/yellow]", default=False):
        extra = Prompt.ask("Enter comma-separated items").split(",")
        DEFAULT_OOS.extend(x.strip() for x in extra if x.strip())

    out_of_scope = DEFAULT_OOS.copy()

    # Prepare output directory
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"results_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    tool_files = {}
    all_urls = set()

    # Run tools
    def run_and_record(cmd, desc, filename):
        out_path = os.path.join(output_dir, filename)
        run_command(cmd, desc, outfile=out_path)
        tool_files[desc] = out_path
        if os.path.exists(out_path) and desc in ["gau", "katana", "httpx"]:
            all_urls.update([line.strip() for line in open(out_path)])

    run_and_record(["gau", domain], "gau", "gau_output.txt")
    run_and_record(["katana", "-u", target, "-o", os.path.join(output_dir, "katana_output.txt"), "-c", "50"], "katana", "katana_output.txt")
    run_and_record(["amass", "enum", "-d", domain, "-o", os.path.join(output_dir, "amass_output.txt")], "amass", "amass_output.txt")
    run_and_record(["subfinder", "-d", domain, "-o", os.path.join(output_dir, "subfinder_output.txt")], "subfinder", "subfinder_output.txt")
    run_and_record(["assetfinder", domain, "-subs-only"], "assetfinder", "assetfinder_output.txt")
    run_and_record(["httpx", "-u", target, "-o", os.path.join(output_dir, "httpx_output.txt"), "-rate-limit", "50"], "httpx", "httpx_output.txt")
    run_and_record(["nmap", "-Pn", "-sV", "-oN", os.path.join(output_dir, "nmap_output.txt"), domain], "nmap", "nmap_output.txt")
    run_and_record(["gobuster", "dir", "-u", target, "-w", wordlist, "-o", os.path.join(output_dir, "gobuster_output.txt"), "-q", "-k", "-t", "5"], "gobuster", "gobuster_output.txt")
    run_and_record(["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-o", os.path.join(output_dir, "ffuf_output.json"), "-of", "json", "-t", "5"], "ffuf", "ffuf_output.json")

    nikto_file = run_nikto(target, output_dir)
    if nikto_file:
        tool_files["nikto"] = nikto_file

    # JS scraping
    js_links = [u for u in all_urls if u.endswith(".js")]
    for js in js_links:
        all_urls.update(scrape_js_for_endpoints(js))

    all_urls = process_urls(all_urls, out_of_scope)

    urls_file = os.path.join(output_dir, "all_discovered_urls.txt")
    with open(urls_file, "w") as f:
        for u in sorted(all_urls):
            f.write(u + "\n")

    tool_files["all_discovered_urls"] = urls_file

    summary = {
        "Unique URLs discovered": len(all_urls),
        "JS endpoints found": len(js_links),
        "Out-of-scope filters applied": len(out_of_scope),
    }

    report_path = os.path.join(output_dir, "summary.html")
    generate_html_report(report_path, summary, sorted(all_urls), tool_files)

    # Optional zip
    if Confirm.ask("[cyan]Zip results for easy sharing?[/cyan]", default=True):
        zip_name = f"{output_dir}.zip"
        shutil.make_archive(output_dir, 'zip', output_dir)
        console.print(f"[green]Results zipped to {zip_name}[/green]")

    console.print("[bold green]\n[+] Recon complete! Check reports for results.[/bold green]")

if __name__ == "__main__":
    main()
