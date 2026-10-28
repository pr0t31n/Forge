#!/usr/bin/env python3
"""Forge installer — multi-platform."""
import subprocess
import sys
import shutil
from pathlib import Path

TOOL_NAME = "Forge"
MIN_PYTHON = (3, 10)


def _run(cmd, check=True):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)


def _has(binary):
    return shutil.which(binary) is not None


def _brew_installed(formula):
    try:
        r = subprocess.run(["brew", "list", "--formula", "-1"],
                           capture_output=True, text=True, timeout=15)
        return formula in r.stdout.split()
    except Exception:
        return False


def _brew_cask_installed(cask):
    try:
        r = subprocess.run(["brew", "list", "--cask", "-1"],
                           capture_output=True, text=True, timeout=15)
        return cask in r.stdout.split()
    except Exception:
        return False


def _install_aws_cli_linux():
    """Install AWS CLI v2 on Linux via the official bundled installer."""
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="forge_aws_"))
    try:
        print("  [install] Downloading AWS CLI v2 …")
        _run(f"curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o {tmp}/awscliv2.zip",
             check=False)
        if not (tmp / "awscliv2.zip").exists():
            print("  [WARN] AWS CLI download failed — install manually")
            return
        _run(f"unzip -qo {tmp}/awscliv2.zip -d {tmp}", check=False)
        installer = tmp / "aws" / "install"
        if installer.exists():
            if _has("aws"):
                _run(f"{installer} --update", check=False)
            else:
                _run(str(installer), check=False)
        else:
            print("  [WARN] AWS CLI installer not found after unzip")
    finally:
        _run(f"rm -rf {tmp}", check=False)


def install_system_deps():
    """Install aws + az + gcloud CLIs via the platform package manager when available."""
    if sys.platform.startswith("linux"):
        if not _has("aws"):
            print("[install] Installing AWS CLI v2 (bundled installer) …")
            for dep in ("curl", "unzip"):
                if not _has(dep):
                    if shutil.which("apt-get"):
                        _run(["apt-get", "install", "-y", dep], check=False)
                    elif shutil.which("dnf"):
                        _run(["dnf", "install", "-y", dep], check=False)
            _install_aws_cli_linux()
        else:
            print("  [ok] aws already installed")
        if shutil.which("apt-get"):
            print("[install] Installing system packages via apt …")
            if not _has("az"):
                if not _dpkg_installed("azure-cli"):
                    _run(["apt-get", "install", "-y", "azure-cli"], check=False)
            else:
                print("  [ok] az already installed")
            if not _has("gcloud"):
                if not _dpkg_installed("google-cloud-sdk"):
                    _run(["apt-get", "install", "-y", "google-cloud-sdk"], check=False)
            else:
                print("  [ok] gcloud already installed")
        elif shutil.which("dnf"):
            if not _has("az"):
                _run(["dnf", "install", "-y", "azure-cli"], check=False)
            else:
                print("  [ok] az already installed")
            if not _has("gcloud"):
                _run(["dnf", "install", "-y", "google-cloud-sdk"], check=False)
            else:
                print("  [ok] gcloud already installed")
    elif sys.platform == "darwin":
        if shutil.which("brew"):
            print("[install] Installing system packages via brew …")
            if not _has("aws"):
                if _brew_installed("awscli"):
                    print("  [ok] awscli already installed")
                else:
                    _run(["brew", "install", "awscli"], check=False)
            else:
                print("  [ok] aws already installed")
            if not _has("az"):
                if _brew_installed("azure-cli"):
                    print("  [ok] azure-cli already installed")
                else:
                    _run(["brew", "install", "azure-cli"], check=False)
            else:
                print("  [ok] az already installed")
            if not _has("gcloud"):
                if _brew_cask_installed("google-cloud-sdk"):
                    print("  [ok] google-cloud-sdk already installed")
                else:
                    _run(["brew", "install", "--cask", "google-cloud-sdk"], check=False)
            else:
                print("  [ok] gcloud already installed")
    elif sys.platform == "win32":
        if shutil.which("choco"):
            if not _has("aws"):
                _run(["choco", "install", "-y", "awscli"], check=False)
            else:
                print("  [ok] aws already installed")
            if not _has("az"):
                _run(["choco", "install", "-y", "azure-cli"], check=False)
            else:
                print("  [ok] az already installed")
            if not _has("gcloud"):
                _run(["choco", "install", "-y", "gcloudsdk"], check=False)
            else:
                print("  [ok] gcloud already installed")


def _dpkg_installed(pkg):
    try:
        r = subprocess.run(["dpkg", "-s", pkg],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _rpm_installed(pkg):
    try:
        return subprocess.run(
            ["rpm", "-q", pkg],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0
    except FileNotFoundError:
        return False


def install_pip_deps():
    import importlib.util
    from pathlib import Path
    req = Path(__file__).parent / "requirements.txt"
    if not req.exists():
        print("[install] No requirements.txt found — skipping pip install")
        return
    print("[install] Installing Python packages …")

    def _pip_installed(pkg_spec):
        name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
        _IMPORT_MAP = {
            "python-nmap": "nmap", "beautifulsoup4": "bs4", "python-docx": "docx",
            "python-whois": "whois", "Pillow": "PIL", "pyOpenSSL": "OpenSSL",
            "dnspython": "dns", "pyyaml": "yaml", "scikit-learn": "sklearn",
            "python-dateutil": "dateutil", "python-magic": "magic",
            "flask-socketio": "flask_socketio", "flask-cors": "flask_cors",
            "python-engineio": "engineio", "python-socketio": "socketio",
            "charset-normalizer": "charset_normalizer",
            "ruamel.yaml": "ruamel", "lxml-html-clean": "lxml_html_clean",
            "pyserial": "serial", "python-can": "can",
            "python-multipart": "multipart", "graphql-core": "graphql",
            "playwright-stealth": "playwright_stealth",
        }
        mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
        return importlib.util.find_spec(mod) is not None

    lines = req.read_text().splitlines()
    missing = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _pip_installed(line):
            print(f"  [ok] {line} already installed")
        else:
            missing.append(line)
    if missing:
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages"] + missing, check=False)
    else:
        print("  [+] All Python packages already installed.")


def install_playwright():
    """Install/upgrade Playwright + Chromium for Console Login support."""
    print("[install] Installing/upgrading Playwright via pip ...")
    _run([sys.executable, "-m", "pip", "install", "--break-system-packages",
          "--upgrade", "playwright>=1.40.0"], check=False)
    print("[install] Installing Playwright Chromium browser + OS deps ...")
    _run([sys.executable, "-m", "playwright", "install", "--with-deps", "chromium"], check=False)


def main():
    if sys.version_info < MIN_PYTHON:
        print(f"ERROR: Python {'.'.join(map(str, MIN_PYTHON))}+ required")
        sys.exit(1)
    print(f"{TOOL_NAME} — Installation")
    install_system_deps()
    install_pip_deps()
    install_playwright()
    print(f"\n{TOOL_NAME} installed.")
    print("Start with:")
    print("  python3 forge.py --azure-subscription <sub-id>")
    print("  python3 forge.py --gcp-project <project-id>")


if __name__ == "__main__":
    main()
