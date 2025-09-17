Here’s a README.md you can drop into the repo.

# Nikto Multiprocess Web Scanner

A Python wrapper around Nikto that performs exhaustive web server scans in parallel, shows a real-time progress bar, and exports results as TXT, Excel, and PDF per target. It auto-installs a local Nikto copy if not found, forces deep directory checks, and runs all plugins for thorough coverage.[11][12][13]

## Features

- Multiprocessing for parallel scans across multiple targets.[14]
- Exhaustive Nikto runs with all plugins and forced directory checks via flags.[12][13][11]
- Real-time progress bar during scans and visible Nikto status output.[15][16]
- Auto-install Nikto locally if not already present.[17]
- Robust output handling:
  - Raw TXT: canonical Nikto output for audit and parsing.[18]
  - Excel: parsed “+ …” findings as a numbered list.[18]
  - PDF: clean report summarizing key findings.[19]
- Safe absolute output paths to avoid permission/cwd issues.[20]

## Requirements

- Python 3.8+ and Linux shell environment.[14]
- Packages: requests, tqdm, openpyxl, dnspython, reportlab.[15][19]
- Perl available in PATH (for local nikto.pl runner).[11]
- Network access to targets and to download Nikto on first run.[17]

Install Python deps:
- pip install requests tqdm openpyxl dnspython reportlab[19][15]

## Quick Start

- Single target:
  - python3 main.py https://example.com[11]
- Multiple targets in parallel:
  - python3 main.py http://a.com https://b.org c.net[14]

Outputs are written to:
- reports_txt/nikto_report_<timestamp>.txt (raw)[18]
- reports_xlsx/nikto_report_<timestamp>.xlsx (parsed)[18]
- reports_pdf/nikto_report_<timestamp>.pdf (summary)[19]

If Nikto isn’t installed system-wide, the script downloads and installs 2.1.6 locally under ./nikto and runs perl nikto.pl with correct cwd.[17]

## What the Script Does

- Validates input URLs (adds http:// if missing), resolves DNS, and tests reachability with HEAD before scanning.[11]
- Ensures output directories exist and uses absolute paths for Nikto -output to prevent write failures.[20]
- Runs exhaustive scans:
  - -Plugins "@@ALL" to run all plugin categories explicitly.[13]
  - -C all to force-check all common CGI/dir locations.[12]
  - -Display P to print periodic scan status lines.[21]
- Shows a live tqdm progress bar tied to a per-scan timeout (default 30 min) for UX feedback.[15]
- Parses the raw TXT for lines starting with “+” (Nikto finding format), writes Excel and PDF summaries.[19][18]

## CLI Options

The main entry accepts targets as positional args:
- python3 main.py <target1> [<target2> ...][11]

To adjust the per-scan timeout globally, change the timeout_sec passed in main/run_targets (default 1800 seconds).[14]

## Notes on Exhaustive Mode

Enabling all plugins and -C all significantly increases scan time and load; a 30-minute per-target cap is set by default and can be raised if necessary for large or slow endpoints.[12][11]

If rate-limits or WAFs are present, expect intermittent banner changes or throttling; Nikto will still report headers and common misconfigurations, but some findings may be suppressed by intermediaries.[22]

## Known Behaviors and Tips

- If the progress bar appears late or not at all in certain terminals, force unbuffered mode:
  - python -u main.py <targets>[15]
- If permission issues occur, ensure the working directory is writable and keep -output absolute as implemented.[20]
- System-wide Nikto uses nikto binary; local runner uses perl nikto.pl under nikto/program to preserve relative resources.[11]

## Output Artifacts

- TXT: complete Nikto output including server info, headers, and detailed plugin findings. Keep for audits.[18]
- XLSX: simple sheet with Timestamp, Target, and enumerated findings parsed from “+ …” lines.[18]
- PDF: brief, readable summary report convenient for sharing.[19]

## Legal and Ethical Use

Only scan assets with explicit permission. Unauthorized scanning may violate laws and acceptable use policies. This tool is intended for authorized security testing and research.[23]

## Roadmap

- Optional JSON export of structured findings.[11]
- Tuneable -Tuning categories for targeted scans (e.g., excluding DoS).[11]
- Retry/backoff and per-target headers or cookies via nikto.conf when needed.[24]

## References

- Nikto manual and usage flags overview.[11]
- Nikto cheat sheet for options like -C all and output formats.[12][18]
- Plugin selection guidance and macros like "@@ALL".[13]
- Multiprocessing Pool usage and best practices.[14]
- ReportLab PDF generation user guide.[19]
- tqdm docs for real-time console progress.[15]
- Kali tools page for Nikto packaging.[17]
