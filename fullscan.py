import subprocess
import sys
import os
from datetime import datetime
from openpyxl import Workbook
import requests
import tarfile
import shutil
import logging
from tqdm import tqdm
import time
import threading
import urllib.parse
import dns.resolver
from multiprocessing import Pool, cpu_count
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('nikto_scan.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Nikto constants
NIKTO_VERSION = "2.1.6"
NIKTO_TARBALL = f"nikto-{NIKTO_VERSION}.tar.gz"
NIKTO_URL = f"https://github.com/sullo/nikto/archive/refs/tags/{NIKTO_VERSION}.tar.gz"
NIKTO_SRC_DIR = f"nikto-{NIKTO_VERSION}"
NIKTO_INSTALL_DIR = "nikto"  # contains program/, docs/, etc.

# Output folders
OUT_TXT_DIR = "detailed_reports_txt"
OUT_XLSX_DIR = "detailed_reports_xlsx"
OUT_PDF_DIR = "detailed_reports_pdf"

def ensure_directories():
    for d in (OUT_TXT_DIR, OUT_XLSX_DIR, OUT_PDF_DIR):
        os.makedirs(d, exist_ok=True)

def check_nikto_installed():
    logger.info("Checking for Nikto installation...")
    try:
        res = subprocess.run(["nikto", "-Version"], capture_output=True, text=True, check=True)
        logger.info("Nikto is installed system-wide: %s", res.stdout.strip())
        return True, "nikto"
    except (subprocess.CalledProcessError, FileNotFoundError):
        local_pl = os.path.join(os.getcwd(), NIKTO_INSTALL_DIR, "program", "nikto.pl")
        if os.path.exists(local_pl):
            try:
                res = subprocess.run(["perl", local_pl, "-Version"], capture_output=True, text=True, check=True)
                logger.info("Nikto is installed locally: %s", res.stdout.strip())
                return True, local_pl
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.error("Local Nikto found but not functional: %s", e)
        logger.info("Nikto is not installed.")
        return False, None

def download_and_install_nikto():
    logger.info("Attempting to download and install Nikto in the current directory...")
    try:
        logger.info("Downloading Nikto from %s", NIKTO_URL)
        r = requests.get(NIKTO_URL, stream=True, timeout=60)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        with open(NIKTO_TARBALL, "wb") as f, tqdm(
            total=total, unit="B", unit_scale=True, unit_divisor=1024, desc="Downloading Nikto", file=sys.stdout, dynamic_ncols=True
        ) as pbar:
            for chunk in r.iter_content(1024 * 64):
                if chunk:
                    f.write(chunk)
                    pbar.update(len(chunk))
        logger.info("Nikto tarball downloaded successfully.")

        logger.info("Extracting Nikto...")
        with tarfile.open(NIKTO_TARBALL, "r:gz") as tar:
            tar.extractall()

        if os.path.exists(NIKTO_INSTALL_DIR):
            shutil.rmtree(NIKTO_INSTALL_DIR, ignore_errors=True)
        shutil.move(NIKTO_SRC_DIR, NIKTO_INSTALL_DIR)

        nikto_pl = os.path.join(NIKTO_INSTALL_DIR, "program", "nikto.pl")
        if os.path.exists(nikto_pl):
            os.chmod(nikto_pl, 0o755)
        logger.info("Nikto installed to %s", nikto_pl)

        os.remove(NIKTO_TARBALL)
        logger.info("Cleaned up temporary files.")
        return check_nikto_installed()
    except Exception as e:
        logger.error("Failed to install Nikto: %s", e)
        return False, None

def validate_url_early(target_url):
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    parsed = urllib.parse.urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL format (no scheme or netloc)")
    hostname = parsed.netloc.split(":")[0]
    dns.resolver.resolve(hostname, "A")
    r = requests.head(target_url, timeout=10, allow_redirects=True)
    r.raise_for_status()
    return target_url

def write_excel(output_excel_file, timestamp, target_url, issues):
    wb = Workbook()
    ws = wb.active
    ws.title = "Nikto Scan Results"
    ws.append(["Timestamp", timestamp])
    ws.append(["Target URL", target_url])
    ws.append([])
    ws.append(["#", "Issue"])
    for idx, issue in enumerate(issues, start=1):
        ws.append([idx, issue])
    wb.save(output_excel_file)

def wrap_text(text, max_chars=100):
    words = text.split()
    line = []
    current = 0
    for w in words:
        add = (1 if line else 0) + len(w)
        if current + add <= max_chars:
            line.append(w)
            current += add
        else:
            yield " ".join(line)
            line = [w]
            current = len(w)
    if line:
        yield " ".join(line)

def write_pdf(output_pdf_file, timestamp, target_url, issues):
    c = canvas.Canvas(output_pdf_file, pagesize=A4)
    width, height = A4
    margin = 2*cm
    y = height - margin
    c.setTitle(f"Nikto Report - {target_url}")
    c.setFont("Helvetica-Bold", 14)
    c.drawString(margin, y, "Nikto Scan Report")
    y -= 18
    c.setFont("Helvetica", 10)
    c.drawString(margin, y, f"Timestamp: {timestamp}")
    y -= 14
    c.drawString(margin, y, f"Target URL: {target_url}")
    y -= 18
    c.setFont("Helvetica-Bold", 12)
    c.drawString(margin, y, "Findings:")
    y -= 16
    c.setFont("Helvetica", 10)
    for issue in issues:
        for line in wrap_text(issue, max_chars=100):
            if y < margin + 40:
                c.showPage()
                y = height - margin
                c.setFont("Helvetica", 10)
            c.drawString(margin, y, f"- {line}")
            y -= 12
    c.showPage()
    c.save()

def run_nikto_scan_single(target_url, nikto_path, timeout_sec=1800):
    ensure_directories()
    target_url = validate_url_early(target_url)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"nikto_report_{timestamp}"
    output_txt_file = os.path.join(OUT_TXT_DIR, f"{base_name}.txt")
    output_excel_file = os.path.join(OUT_XLSX_DIR, f"{base_name}.xlsx")
    output_pdf_file = os.path.join(OUT_PDF_DIR, f"{base_name}.pdf")
    output_txt_abs = os.path.abspath(output_txt_file)

    # Build exhaustive Nikto command
    if nikto_path == "nikto":
        cmd = [
            "nikto", "-h", target_url,
            "-Plugins", "@@ALL",
            "-C", "all",
            "-Display", "P",
            "-output", output_txt_abs, "-Format", "txt"
        ]
        cwd = None
    else:
        cwd = os.path.join(NIKTO_INSTALL_DIR, "program")
        cmd = [
            "perl", "nikto.pl", "-h", target_url,
            "-Plugins", "@@ALL",
            "-C", "all",
            "-Display", "P",
            "-output", output_txt_abs, "-Format", "txt"
        ]

    # Launch Nikto
    proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Real-time tqdm bar bound to timeout, printing to stdout
    start = time.time()
    done_flag = {"done": False}

    def monitor():
        try:
            proc.wait(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            try:
                proc.terminate()
                proc.wait(5)
            except Exception:
                proc.kill()
        finally:
            done_flag["done"] = True

    t = threading.Thread(target=monitor, daemon=True)
    t.start()

    with tqdm(total=100, desc=f"Scanning {target_url}", unit="%", leave=True,
              file=sys.stdout, dynamic_ncols=True, mininterval=0.1, maxinterval=1.0, ascii=True) as pbar:
        while not done_flag["done"]:
            elapsed = time.time() - start
            progress = min((elapsed / timeout_sec) * 100.0, 99.0)
            pbar.n = progress
            pbar.refresh()
            time.sleep(0.1)
        pbar.n = 100
        pbar.refresh()

    t.join()
    stdout, stderr = proc.communicate()
    returncode = proc.returncode

    issues = []
    if returncode != 0:
        issues = [f"Scan failed: {stderr or stdout or 'unknown error'}"]
        try:
            with open(output_txt_abs, "w", encoding="utf-8") as f:
                f.write(stderr or stdout or "Scan failed without output.")
        except Exception as e:
            logger.error("Failed writing raw output file: %s", e)
    # Parse output file for "+ ..." findings
    if os.path.exists(output_txt_abs) and os.path.getsize(output_txt_abs) > 0:
        try:
            with open(output_txt_abs, "r", encoding="utf-8") as f:
                lines = f.readlines()
            parsed_issues = [ln.strip() for ln in lines if ln.strip().startswith("+")]
            issues = parsed_issues or (issues if issues else ["No issues found."])
        except Exception as e:
            logger.error("Failed to parse output file: %s", e)
            if not issues:
                issues = ["Nikto did not produce any parseable output."]
    else:
        if not issues:
            issues = ["Nikto did not produce any output."]

    write_excel(output_excel_file, timestamp, target_url, issues)
    write_pdf(output_pdf_file, timestamp, target_url, issues)
    return (target_url, output_txt_abs, output_excel_file, output_pdf_file, issues)

# Top-level worker (picklable)
def worker_run(args):
    target, nikto_path, timeout_sec = args
    return run_nikto_scan_single(target, nikto_path, timeout_sec)

def run_targets(targets, timeout_sec=1800):
    ensure_directories()
    installed, nikto_path = check_nikto_installed()
    if not installed:
        logger.info("Nikto not found. Attempting to install locally...")
        installed, nikto_path = download_and_install_nikto()
        if not installed:
            raise RuntimeError("Unable to install Nikto")

    max_workers = min(len(targets), cpu_count())
    logger.info("Starting scans with %d workers", max_workers)
    args_list = [(t, nikto_path, timeout_sec) for t in targets]

    results = []
    with Pool(processes=max_workers) as pool:
        for res in pool.imap_unordered(worker_run, args_list):
            results.append(res)
            tgt, txt, xlsx, pdf, issues = res
            logger.info("Completed: %s -> TXT:%s XLSX:%s PDF:%s", tgt, txt, xlsx, pdf)
    return results

def main():
    if len(sys.argv) < 2:
        logger.error("Usage: python main.py <target1> [<target2> ...]")
        sys.exit(1)
    targets = sys.argv[1:]
    try:
        results = run_targets(targets, timeout_sec=1800)  # 30 minutes cap per target for exhaustive scan
        for tgt, txt, xlsx, pdf, issues in results:
            logger.info("Summary for %s -> %d findings; TXT:%s XLSX:%s PDF:%s",
                        tgt, len(issues) if issues else 0, txt, xlsx, pdf)
    except Exception as e:
        logger.error("Run failed: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
