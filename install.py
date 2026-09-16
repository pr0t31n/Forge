#!/usr/bin/env python3
"""Forge installer — multi-platform."""
import subprocess
import sys
import shutil

TOOL_NAME = "Forge"
MIN_PYTHON = (3, 10)


def _run(cmd, check=True):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)


def _has(binary):
    return shutil.which(binary) is not None


def install_system_deps():
    """Install az + gcloud CLIs via the platform package manager when available."""
    if sys.platform.startswith("linux"):
        if shutil.which("apt-get"):
            print("[install] Installing system packages via apt …")
            if not _has("az"):
                _run(["apt-get", "install", "-y", "azure-cli"], check=False)
            if not _has("gcloud"):
                _run(["apt-get", "install", "-y", "google-cloud-sdk"], check=False)
        elif shutil.which("dnf"):
            if not _has("az"):
                _run(["dnf", "install", "-y", "azure-cli"], check=False)
            if not _has("gcloud"):
                _run(["dnf", "install", "-y", "google-cloud-sdk"], check=False)
    elif sys.platform == "darwin":
        if shutil.which("brew"):
            print("[install] Installing system packages via brew …")
            if not _has("az"):
                _run(["brew", "install", "azure-cli"], check=False)
            if not _has("gcloud"):
                _run(["brew", "install", "--cask", "google-cloud-sdk"], check=False)
    elif sys.platform == "win32":
        if shutil.which("choco"):
            if not _has("az"):
                _run(["choco", "install", "-y", "azure-cli"], check=False)
            if not _has("gcloud"):
                _run(["choco", "install", "-y", "gcloudsdk"], check=False)


def install_pip_deps():
    print("[install] Installing Python packages …")
    _run([sys.executable, "-m", "pip", "install",
          "--break-system-packages", "-r", "requirements.txt"], check=False)


def main():
    if sys.version_info < MIN_PYTHON:
        print(f"ERROR: Python {'.'.join(map(str, MIN_PYTHON))}+ required")
        sys.exit(1)
    print(f"{TOOL_NAME} v0.2.0 — Installation")
    install_system_deps()
    install_pip_deps()
    print(f"\n{TOOL_NAME} installed.")
    print("Start with:")
    print("  python3 forge.py --azure-subscription <sub-id>")
    print("  python3 forge.py --gcp-project <project-id>")


if __name__ == "__main__":
    main()
