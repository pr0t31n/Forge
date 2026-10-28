#!/usr/bin/env python3
"""
Forge — AWS / Azure / GCP cloud control-plane security auditor.

Token protocol (emitted on stdout for Crucible-style managers):
  __CRUCIBLE_LOG__     <message>
  __CRUCIBLE_ERR__     <message>
  __CRUCIBLE_STATUS__  <json>
  __CRUCIBLE_FINDING__ <json>

Run direct (CLI) or under a Flask manager that sets CRUCIBLE_MANAGED=1
to switch outputs to token mode.
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

try:
    if "/opt/pr0t31n/shared" not in sys.path:
        sys.path.insert(0, "/opt/pr0t31n/shared")
    import pr0t31n_schema as _us
except ImportError:
    _us = None

try:
    import pr0t31n_tool_runner as _ur
except ImportError:
    _ur = None

try:
    import pr0t31n_event_log as _el
except ImportError:
    _el = None

try:
    from pr0t31n_pause import PauseManager as _PP
except ImportError:
    _PP = None

_MANAGED = os.environ.get("CRUCIBLE_MANAGED", "") == "1"
_findings: list = []

_MANUAL_KEY_STEPS = (
    "To create access keys manually:\n"
    "  1. Open a browser and log into the AWS Console for this account\n"
    "  2. Click your username in the top-right corner → 'Security credentials'\n"
    "     (or go to: IAM → Users → select the pentest user → Security credentials tab)\n"
    "  3. Scroll down to 'Access keys' and click 'Create access key'\n"
    "  4. Select 'Command Line Interface (CLI)' as the use case → Next\n"
    "  5. Click 'Create access key'\n"
    "  6. Copy the Access Key ID and Secret Access Key (this is the only time\n"
    "     the secret is shown — save it now)\n"
    "  7. Re-run Forge with: --aws-access-key-id <key> --aws-secret-key <secret>\n"
    "     Or set the auth method to 'Access Keys' in the Crucible project wizard\n\n"
    "  NOTE: The IAM user must have the iam:CreateAccessKey permission.\n"
    "  If the user lacks this permission, ask an AWS admin to either:\n"
    "    a) Attach a policy granting iam:CreateAccessKey to the pentest user, OR\n"
    "    b) Create the access key on the user's behalf via IAM → Users → <user>\n"
    "       → Security credentials → Create access key, and provide the key pair"
)

_IAM_PERMISSION_STEPS = (
    "The IAM user does not have permission to create access keys (iam:CreateAccessKey).\n"
    "This is an AWS policy restriction — neither Forge nor manual Console access can\n"
    "create keys until the permission is granted.\n\n"
    "Ask an AWS administrator to do ONE of the following:\n\n"
    "  Option A — Grant iam:CreateAccessKey to the pentest user:\n"
    "    1. Log into the AWS Console as an admin\n"
    "    2. Go to IAM → Users → select the pentest user → Permissions tab\n"
    "    3. Click 'Add permissions' → 'Attach policies directly'\n"
    "    4. Create an inline policy with this JSON:\n"
    '       {"Version":"2012-10-17","Statement":[{"Effect":"Allow",\n'
    '        "Action":"iam:CreateAccessKey","Resource":"arn:aws:iam::*:user/${aws:username}"}]}\n'
    "    5. Save the policy, then re-run Forge\n\n"
    "  Option B — Have the admin create the key directly:\n"
    "    1. Log into the AWS Console as an admin\n"
    "    2. Go to IAM → Users → select the pentest user → Security credentials tab\n"
    "    3. Scroll to 'Access keys' → 'Create access key'\n"
    "    4. Select 'Command Line Interface (CLI)' → Next → Create\n"
    "    5. Copy the Access Key ID and Secret Access Key\n"
    "    6. Re-run Forge with: --aws-access-key-id <key> --aws-secret-key <secret>\n"
    "       Or set the auth method to 'Access Keys' in the Crucible project wizard"
)

_RUN_DIR: Optional[Path] = None
_RUNLOG = None
_pause = None

_IAM_DENY_PATTERNS = ("not authorized to perform", "AccessDenied", "AccessDeniedException")


def _check_iam_error(resp_data: dict) -> None:
    """Raise with specific guidance if an IAM API response is a permission denial."""
    if not isinstance(resp_data, dict):
        return
    err_type = resp_data.get("__type", "") or resp_data.get("Error", {}).get("Code", "")
    err_msg = (resp_data.get("message", "") or resp_data.get("Message", "")
               or resp_data.get("Error", {}).get("Message", ""))
    combined = f"{err_type} {err_msg}"
    for pat in _IAM_DENY_PATTERNS:
        if pat.lower() in combined.lower():
            raise RuntimeError(
                f"AWS IAM permission denied: {err_msg or err_type}\n\n"
                + _IAM_PERMISSION_STEPS
            )
    if err_type and "LimitExceeded" in err_type:
        raise RuntimeError(
            f"AWS IAM limit exceeded: {err_msg}\n"
            "The user may already have the maximum number of access keys (2).\n"
            "Delete an existing key in IAM → Users → <user> → Security credentials\n"
            "before creating a new one."
        )


_CSV_FIELDS = ["id", "tool", "title", "datetime", "ip", "port", "hostname",
               "risk", "command", "description", "output_file", "affected",
               "cves", "service", "catalogue_id", "remediation", "sources"]

# Secret-like environment variable / user-data pattern — shared across Lambda,
# ECS, and EC2 user-data checks.
_SECRET_PATTERNS = re.compile(
    r'(password|secret|key|token|aws_access_key|aws_secret|private_key|'
    r'api_key|apikey|db_password|mysql_password|postgres_password)',
    re.IGNORECASE,
)

# Deprecated Lambda runtimes (no longer receive security patches).
_DEPRECATED_RUNTIMES = frozenset({
    "python2.7", "python3.6", "python3.7",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "dotnetcore2.1", "dotnetcore3.1",
    "ruby2.5", "ruby2.7",
    "java8", "go1.x",
})

# Temp profile name used when Forge creates ephemeral access keys.
_AWS_TMP_PROFILE = "forge_tmp"
_aws_tmp_cleanup = None


# ── AWS credential setup ─────────────────────────────────────────────────────

def _aws_configure_from_keys(access_key_id: str, secret_key: str,
                              region: str = "") -> str:
    """Write a temp AWS CLI profile from explicit access keys.
    Returns the profile name.  Registers ``_aws_tmp_cleanup`` to remove it.
    """
    global _aws_tmp_cleanup
    import configparser

    profile = _AWS_TMP_PROFILE
    creds_file = Path.home() / ".aws" / "credentials"
    config_file = Path.home() / ".aws" / "config"
    creds_file.parent.mkdir(parents=True, exist_ok=True)

    cfg = configparser.ConfigParser()
    if creds_file.exists():
        cfg.read(str(creds_file))
    cfg[profile] = {
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": secret_key,
    }
    with open(creds_file, "w") as f:
        cfg.write(f)

    if region:
        cfg2 = configparser.ConfigParser()
        if config_file.exists():
            cfg2.read(str(config_file))
        section = f"profile {profile}"
        if not cfg2.has_section(section):
            cfg2.add_section(section)
        cfg2.set(section, "region", region)
        with open(config_file, "w") as f:
            cfg2.write(f)

    log(f"[aws] Temp profile '{profile}' configured (key {access_key_id[:8]}...)")

    if _RUN_DIR is not None:
        try:
            aws_dir = _RUN_DIR / "aws_profile"
            aws_dir.mkdir(parents=True, exist_ok=True)
            p_creds = configparser.ConfigParser()
            p_creds[profile] = {
                "aws_access_key_id": access_key_id,
                "aws_secret_access_key": secret_key,
            }
            with open(aws_dir / "credentials", "w") as f:
                p_creds.write(f)
            if region:
                p_conf = configparser.ConfigParser()
                section = f"profile {profile}"
                p_conf.add_section(section)
                p_conf.set(section, "region", region)
                with open(aws_dir / "config", "w") as f:
                    p_conf.write(f)
            log(f"[aws] Profile copy saved to {aws_dir}")
        except Exception as exc:
            err(f"[aws] Could not save profile to run dir: {exc}")

    def _cleanup():
        try:
            cfg = configparser.ConfigParser()
            creds = Path.home() / ".aws" / "credentials"
            if creds.exists():
                cfg.read(str(creds))
                if cfg.has_section(profile):
                    cfg.remove_section(profile)
                    with open(creds, "w") as f:
                        cfg.write(f)
            cfg2 = configparser.ConfigParser()
            conf = Path.home() / ".aws" / "config"
            if conf.exists():
                cfg2.read(str(conf))
                section = f"profile {profile}"
                if cfg2.has_section(section):
                    cfg2.remove_section(section)
                    with open(conf, "w") as f:
                        cfg2.write(f)
            log("[aws] Temp profile removed from ~/.aws/")
        except Exception as exc:
            err(f"[aws] Profile cleanup warning: {exc}")

    _aws_tmp_cleanup = _cleanup
    return profile


def _parse_account_from_url(url: str) -> str:
    """Extract account ID or alias from an IAM sign-in URL."""
    import urllib.parse
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    parts = host.split(".")
    if parts and parts[0] not in ("signin", "console", ""):
        return parts[0]
    return ""


def _aws_console_login_requests(console_url, account, username, password, signin_url):
    """Lightweight requests-based Console login. Returns a session + True on
    success, or (None, False) on 403 (anti-bot block)."""
    try:
        import requests as _req
    except ImportError:
        raise RuntimeError("requests library required for console login — pip install requests")

    sess = _req.Session()
    sess.headers["User-Agent"] = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    try:
        sess.get(console_url, timeout=30, allow_redirects=True)
    except Exception as exc:
        raise RuntimeError(f"Cannot reach {console_url}: {exc}")

    form_data = {
        "action": "iam-user-authentication",
        "account": account,
        "username": username,
        "password": password,
        "client_id": "arn:aws:signin:::console/canvas",
        "redirect_uri": "https://console.aws.amazon.com/console/home",
    }

    try:
        login_resp = sess.post(signin_url, data=form_data, timeout=30,
                               allow_redirects=True)
    except Exception as exc:
        raise RuntimeError(f"Console login request failed: {exc}")

    body = login_resp.text.lower()
    _check_console_body_errors(body)
    if login_resp.status_code == 403:
        return None, False
    if login_resp.status_code not in (200, 301, 302, 303):
        raise RuntimeError(f"AWS Console login returned HTTP {login_resp.status_code}")

    return sess, True


def _check_console_body_errors(body):
    """Inspect AWS sign-in response body for known error conditions."""
    if "newpasswordrequired" in body or "change_password" in body or "new-password" in body:
        raise RuntimeError(
            "AWS Console requires a password change before login.\n"
            "  -> Log into the Console manually in a browser, change your password, then re-run."
        )
    if "captcha" in body:
        raise RuntimeError(
            "AWS sign-in requires CAPTCHA — automated login is blocked.\n"
            "  -> Retrying with headless browser..."
        )
    if "mfatype" in body or "mfa_serial" in body or "mfa-code" in body:
        raise RuntimeError(
            "AWS sign-in requires MFA — automated login cannot complete MFA challenges.\n\n"
            + _MANUAL_KEY_STEPS
            + "\n  Or use --aws-profile with an already-authenticated CLI profile."
        )
    if "iam_user_authentication_failure" in body or "authentication_failed" in body:
        raise RuntimeError("AWS Console login failed — check URL, username and password")


def _url_on_console(url: str) -> bool:
    """True when URL hostname is *.console.aws.amazon.com — not just in query params."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or "").lower()
    return host == "console.aws.amazon.com" or host.endswith(".console.aws.amazon.com")


def _poll_for_console(page, timeout_s: int = 90) -> bool:
    """Poll page.url every 2s until we land on *.console.aws.amazon.com."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _url_on_console(page.url):
            return True
        try:
            page.wait_for_timeout(2000)
        except Exception:
            break
    return False


def _kick_oauth_redirect(page) -> None:
    """If the OAuth page has an auto-submit form, submit it manually."""
    try:
        page.evaluate("""() => {
            const forms = document.querySelectorAll('form');
            for (const f of forms) {
                if (f.method && f.action) { f.submit(); return; }
            }
        }""")
    except Exception:
        pass


def _aws_console_login_browser(console_url, account, username, password):
    """Playwright headless Chromium fallback for Console login when the
    lightweight requests approach is blocked (403)."""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
    except ImportError:
        raise RuntimeError(
            "Playwright required for Console login (AWS blocked the lightweight method).\n"
            "  -> Run: cd /opt/pr0t31n/Forge && sudo python3 install.py\n\n"
            + _MANUAL_KEY_STEPS
        )

    _stealth_fn = None
    try:
        from playwright_stealth import Stealth
        _s = Stealth()
        _stealth_fn = _s.apply_stealth_sync
    except Exception:
        try:
            from playwright_stealth import stealth_sync
            _stealth_fn = stealth_sync
        except ImportError:
            pass

    log("[aws-console] Lightweight login blocked (HTTP 403) — retrying with headless browser")
    if _stealth_fn:
        log("[aws-console] playwright-stealth available — applying anti-detection")
    else:
        log("[aws-console] playwright-stealth not installed — using basic stealth only")
    status("aws-console", "AWS Console Login — launching browser", "running")

    browser = None
    try:
        pw_ctx = sync_playwright()
        pw = pw_ctx.start()
    except Exception as exc:
        raise RuntimeError(
            f"Playwright failed to start: {exc}\n"
            "  -> Run: cd /opt/pr0t31n/Forge && sudo python3 install.py\n"
            "     This upgrades Playwright and installs Chromium + OS deps.\n\n"
            + _MANUAL_KEY_STEPS
        )

    try:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-first-run",
                "--no-default-browser-check",
            ],
        )
        ctx = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 720},
            locale="en-US",
        )
        page = ctx.new_page()

        if _stealth_fn:
            _stealth_fn(page)
        else:
            ctx.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                window.chrome = {runtime: {}, loadTimes: function(){}, csi: function(){}};
            """)

        status("aws-console", "AWS Console Login — navigating to sign-in", "running")
        try:
            page.goto(console_url, wait_until="networkidle", timeout=30000)
        except Exception as exc:
            raise RuntimeError(f"Cannot reach {console_url}: {exc}")

        status("aws-console", "AWS Console Login — authenticating", "running")
        try:
            acct_input = page.locator("#resolving_input, #account")
            if acct_input.count() > 0 and acct_input.is_visible():
                acct_input.fill(account)
                page.locator("#next_button, button[type='submit']").first.click()
                page.wait_for_load_state("networkidle", timeout=10000)

            user_input = page.locator("#username")
            if user_input.count() > 0 and user_input.is_visible():
                user_input.fill(username)

            pass_input = page.locator("#password")
            if pass_input.count() > 0 and pass_input.is_visible():
                pass_input.fill(password)

            page.locator("#signin_button, button[type='submit']").first.click()

            status("aws-console", "AWS Console Login — waiting for redirect", "running")
            try:
                page.wait_for_load_state("load", timeout=30000)
            except PwTimeout:
                pass
        except PwTimeout:
            pass
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Browser login interaction failed: {exc}")

        body = page.content().lower()
        current_url = page.url.lower()

        if "newpasswordrequired" in body or "change_password" in body or "new-password" in body or "/updateaccount" in current_url:
            raise RuntimeError(
                "AWS Console requires a password change before login.\n"
                "  -> Log into the Console manually in a browser, change your password, then re-run."
            )
        if "mfatype" in body or "mfa" in current_url:
            raise RuntimeError(
                "AWS sign-in requires MFA — automated login cannot complete MFA challenges.\n\n"
                + _MANUAL_KEY_STEPS
                + "\n  Or use --aws-profile with an already-authenticated CLI profile."
            )
        if "authentication_failed" in body or "iam_user_authentication_failure" in body:
            raise RuntimeError("AWS Console login failed — check URL, username and password")

        on_console = _url_on_console(page.url)
        if not on_console:
            log(f"[aws-console] On OAuth page: {_sanitize_url(page.url)[:120]}...")
            _kick_oauth_redirect(page)
            status("aws-console", "AWS Console Login — completing OAuth", "running")
            on_console = _poll_for_console(page, timeout_s=90)

        log(f"[aws-console] Post-login URL: {_sanitize_url(page.url)}")
        log(f"[aws-console] On console domain: {on_console}")

        if not on_console:
            log("[aws-console] OAuth redirect did not complete — browser may be detected")

        status("aws-console", "AWS Console Login — creating temp key", "running")
        create_payload = json.dumps({"UserName": username})
        key_data = None

        if on_console:
            log("[aws-console] Navigating to IAM console")
            try:
                page.goto("https://us-east-1.console.aws.amazon.com/iam/home#/users",
                           wait_until="commit", timeout=30000)
                _poll_for_console(page, timeout_s=60)
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception as exc:
                log(f"[aws-console] IAM navigation warning: {exc}")

            log(f"[aws-console] IAM page URL: {_sanitize_url(page.url)}")
            if _url_on_console(page.url):
                try:
                    resp = page.evaluate("""async ([payload]) => {
                        const r = await fetch(window.location.origin + '/iam/api', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-amz-json-1.1',
                                'X-Amz-Target': 'AWSIdentityManagementService.CreateAccessKey'
                            },
                            body: payload,
                            credentials: 'include'
                        });
                        return {status: r.status, body: await r.text()};
                    }""", [create_payload])
                    key_data = json.loads(resp["body"])
                    _check_iam_error(key_data)
                    log(f"[aws-console] In-page CreateAccessKey succeeded")
                except RuntimeError:
                    raise
                except Exception as exc:
                    log(f"[aws-console] In-page IAM fetch failed: {exc}")

        if key_data is None:
            log("[aws-console] Trying cookie-based IAM API fallback")
            import requests as _rq
            _sess = _rq.Session()
            for c in ctx.cookies():
                _sess.cookies.set(c["name"], c["value"],
                                  domain=c.get("domain", ""),
                                  path=c.get("path", "/"))
            _iam_endpoints = [
                "https://us-east-1.console.aws.amazon.com/iam/api",
                "https://console.aws.amazon.com/iam/api",
            ]
            for ep in _iam_endpoints:
                try:
                    r = _sess.post(
                        ep, data=create_payload,
                        headers={
                            "Content-Type": "application/x-amz-json-1.1",
                            "X-Amz-Target": "AWSIdentityManagementService.CreateAccessKey",
                        },
                        timeout=30, verify=True,
                    )
                    log(f"[aws-console] Cookie fallback {ep}: HTTP {r.status_code}")
                    if r.status_code == 200:
                        key_data = r.json()
                        _check_iam_error(key_data)
                        break
                    if r.status_code == 403:
                        try:
                            _check_iam_error(r.json())
                        except RuntimeError:
                            raise
                        except Exception:
                            pass
                except RuntimeError:
                    raise
                except Exception as exc:
                    log(f"[aws-console] Cookie fallback {ep}: {exc}")

        if key_data is None:
            log("[aws-console] Trying browser-context IAM API (navigate + fetch)")
            try:
                page.goto("https://us-east-1.console.aws.amazon.com/iam/home",
                           wait_until="commit", timeout=30000)
                _poll_for_console(page, timeout_s=60)

                if _url_on_console(page.url):
                    page.wait_for_load_state("networkidle", timeout=15000)
                    resp = page.evaluate("""async ([payload]) => {
                        const r = await fetch(window.location.origin + '/iam/api', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/x-amz-json-1.1',
                                'X-Amz-Target': 'AWSIdentityManagementService.CreateAccessKey'
                            },
                            body: payload,
                            credentials: 'include'
                        });
                        return {status: r.status, body: await r.text()};
                    }""", [create_payload])
                    key_data = json.loads(resp["body"])
                    _check_iam_error(key_data)
                    log("[aws-console] Retry navigate+fetch succeeded")
            except RuntimeError:
                raise
            except Exception as exc:
                log(f"[aws-console] Retry navigate+fetch failed: {exc}")

        if key_data is None:
            raise RuntimeError(
                "AWS OAuth redirect did not complete — the headless browser was likely detected.\n"
                "  Page was on: " + _sanitize_url(page.url)[:200] + "\n\n"
                + _MANUAL_KEY_STEPS
            )

        return key_data
    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        try:
            pw.stop()
        except Exception:
            pass


def _aws_console_login_visible(console_url, account, username, password):
    """Visible-browser fallback: launch a real browser, let the user log in
    manually past any CAPTCHA/anti-bot challenges, then capture the session
    to create temporary access keys."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    log("[aws-console] Headless browser detected — falling back to visible browser")
    log("[aws-console] A browser window will open. Log in manually, then confirm in Crucible.")
    status("aws-console", "AWS Console Login — visible browser", "running",
           step="Waiting for manual login")

    browser = None
    try:
        pw_ctx = sync_playwright()
        pw = pw_ctx.start()
    except Exception as exc:
        log(f"[aws-console] Playwright failed to start for visible mode: {exc}")
        return None

    try:
        try:
            browser = pw.chromium.launch(
                headless=False,
                args=["--disable-blink-features=AutomationControlled",
                      "--start-maximized"],
            )
        except Exception as launch_exc:
            if "XServer" in str(launch_exc) or "Target page, context or browser has been closed" in str(launch_exc):
                log("[aws-console] No display server (X11/Wayland) — visible browser unavailable on this host")
                log("[aws-console] This fallback requires a desktop environment or VNC session")
                return None
            raise
        ctx = browser.new_context(
            viewport={"width": 1280, "height": 900},
            locale="en-US",
            no_viewport=True,
        )
        page = ctx.new_page()

        try:
            page.goto(console_url, wait_until="networkidle", timeout=30000)
        except Exception:
            page.goto(console_url, timeout=60000)

        prompt(
            "A browser window has opened with the AWS sign-in page. "
            "Complete the login (including any CAPTCHA or MFA challenges), "
            "then click OK here to continue.",
            skippable=True,
        )

        status("aws-console", "AWS Console Login — visible browser", "running",
               step="Capturing session")
        on_console = _url_on_console(page.url)
        if not on_console:
            log(f"[aws-console] Visible browser URL after login: {_sanitize_url(page.url)[:120]}")
            on_console = _poll_for_console(page, timeout_s=15)

        if not on_console:
            log("[aws-console] Not on console domain after manual login — cannot extract session")
            return None

        log("[aws-console] Manual login successful — attempting to create temp access key")
        create_payload = json.dumps({"UserName": username})

        try:
            page.goto("https://us-east-1.console.aws.amazon.com/iam/home#/users",
                       wait_until="networkidle", timeout=15000)
        except Exception:
            pass

        try:
            resp = page.evaluate("""async ([payload]) => {
                const r = await fetch(window.location.origin + '/iam/api', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-amz-json-1.1',
                        'X-Amz-Target': 'AWSIdentityManagementService.CreateAccessKey',
                    },
                    body: payload,
                    credentials: 'include',
                });
                return await r.json();
            }""", [create_payload])
            _check_iam_error(resp)
            return resp
        except RuntimeError:
            raise
        except Exception as exc:
            log(f"[aws-console] Visible browser CreateAccessKey failed: {exc}")
            return None
    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        try:
            pw.stop()
        except Exception:
            pass


def _aws_console_login(console_url: str, username: str, password: str,
                        region: str = "") -> str:
    """Log into the AWS Console, create a temp access key, configure a CLI
    profile and return the profile name.

    Three-tier fallback:
      1. Lightweight requests POST (fastest, no browser)
      2. Playwright headless + stealth (anti-detection patches)
      3. Visible browser window (user logs in manually)

    On failure raises RuntimeError with a user-friendly message.
    """
    global _aws_tmp_cleanup
    import configparser

    account = _parse_account_from_url(console_url)
    if not account:
        raise RuntimeError(f"Cannot extract account ID/alias from URL: {console_url}")
    log(f"[aws-console] Account: {account}, user: {username}")
    status("aws-console", "AWS Console Login", "running")

    signin_url = "https://signin.aws.amazon.com/signin"
    sess = None
    used_browser = False

    try:
        sess, ok = _aws_console_login_requests(console_url, account, username, password, signin_url)
    except RuntimeError as exc:
        if "CAPTCHA" in str(exc):
            ok = False
        else:
            raise

    if not ok:
        try:
            key_data = _aws_console_login_browser(console_url, account, username, password)
        except RuntimeError as exc:
            headless_err = str(exc)
            if "headless browser was likely detected" in headless_err or \
               "OAuth redirect did not complete" in headless_err:
                log("[aws-console] Headless browser blocked — trying visible browser fallback")
                key_data = _aws_console_login_visible(
                    console_url, account, username, password)
                if key_data is None:
                    raise RuntimeError(
                        "All browser login methods failed.\n"
                        "  1. Lightweight requests: HTTP 403\n"
                        "  2. Headless browser: AWS anti-bot detection\n"
                        "  3. Visible browser: no display server or manual login did not succeed\n\n"
                        + _MANUAL_KEY_STEPS
                    )
            else:
                raise
        used_browser = True
    else:
        log("[aws-console] Console login successful — creating temp access key")
        iam_endpoint = "https://us-east-1.console.aws.amazon.com/iam/api"
        create_payload = json.dumps({"UserName": username})

        try:
            key_resp = sess.post(
                iam_endpoint,
                data=create_payload,
                headers={
                    "Content-Type": "application/x-amz-json-1.1",
                    "X-Amz-Target": "AWSIdentityManagementService.CreateAccessKey",
                },
                timeout=30,
            )
            key_data = key_resp.json()
            _check_iam_error(key_data)
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"Failed to create access key via Console: {exc}\n\n"
                + _MANUAL_KEY_STEPS
            )

    _check_iam_error(key_data)
    ak = key_data.get("CreateAccessKeyResponse", {}).get("CreateAccessKeyResult", {}).get("AccessKey", {})
    if not ak:
        ak = key_data.get("AccessKey", {})
    access_key_id = ak.get("AccessKeyId", "")
    secret_key = ak.get("SecretAccessKey", "")
    if not access_key_id or not secret_key:
        detail = json.dumps(key_data, indent=2)[:500] if key_data else "(empty response)"
        raise RuntimeError(
            "Console did not return access keys.\n"
            f"  Response: {detail}\n\n"
            + _MANUAL_KEY_STEPS
        )

    log(f"[aws-console] Temporary access key created: {access_key_id[:8]}...")

    profile = _aws_configure_from_keys(access_key_id, secret_key, region)

    log(f"[aws-console] Access key {access_key_id[:8]}... left active in IAM for re-use (e.g. Prowler)")
    log("[aws-console] Remember to delete it from IAM when the engagement ends")
    status("aws-console", "AWS Console Login", "complete")
    return profile


def _check_pause():
    if _pause is not None and _pause.check_and_pause():
        sys.exit(42)


def _rel(p) -> str:
    if not p:
        return ""
    if _us is not None and _RUN_DIR is not None:
        try:
            r = _us.to_relative_output_file(p, str(_RUN_DIR))
            if r:
                return r
        except Exception:
            pass
    return str(p)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _sanitize_url(url: str) -> str:
    """Strip sensitive query params (password, credentials) from a URL before logging."""
    try:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        p = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        _SENSITIVE = {"password", "passwd", "pass", "secret", "token",
                      "aws_secret_access_key", "aws_session_token",
                      "x-amz-security-token", "credential"}
        redacted = False
        for k in list(qs.keys()):
            if k.lower() in _SENSITIVE:
                qs[k] = ["[REDACTED]"]
                redacted = True
        if not redacted:
            return url
        return urlunparse(p._replace(query=urlencode(qs, doseq=True)))
    except Exception:
        return url


def _tok(token: str, msg: str) -> None:
    if _MANAGED:
        print(f"{token}:{msg}", flush=True)
    else:
        print(f"[{_ts()}] {msg}", flush=True)


def log(msg: str) -> None:
    _tok("__CRUCIBLE_LOG__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass


def err(msg: str) -> None:
    _tok("__CRUCIBLE_ERR__", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass


def status(phase: str, label: str, state: str, step: str = "") -> None:
    rec = {"phase": phase, "label": label, "status": state, "step": step}
    _tok("__CRUCIBLE_STATUS__", json.dumps(rec))


def prompt(question: str, skippable: bool = False) -> str:
    import uuid as _uid
    if _MANAGED:
        payload = {"id": str(_uid.uuid4()), "question": question,
                   "type": "text", "options": [], "skippable": skippable}
        print(f"__CRUCIBLE_PROMPT__:{json.dumps(payload)}", flush=True)
        try:
            return sys.stdin.readline().rstrip("\n")
        except Exception:
            return ""
    else:
        try:
            return input(f"\n  [?] {question}\n  > ").strip()
        except (EOFError, KeyboardInterrupt):
            return ""


def finding(*, title: str, severity: str, description: str, ip: str = "",
             port: int = 0, data: dict | None = None,
             output_file: str = "") -> None:
    of_rel = ""
    if output_file:
        parts = [output_file]
        logp = str(output_file) + ".log"
        if os.path.exists(logp):
            parts.append(logp)
        of_rel = ",".join(r for r in (_rel(p) for p in parts) if r)
    if _us is not None:
        rec = _us.make_finding(
            tool="forge", title=title, risk=severity.upper(),
            description=description, ip=ip, port=port,
            command=(data or {}).get("command", ""),
            output_file=of_rel,
            affected=(data or {}).get("affected", ""),
            remediation=(data or {}).get("remediation", ""),
            sources="forge", catalogue_id=(data or {}).get("catalogue_id", ""),
        )
    else:
        rec = {
            "id": str(uuid.uuid4()),
            "tool": "forge",
            "title": title,
            "risk": severity.upper(),
            "description": description,
            "ip": ip, "port": port,
            "datetime": datetime.now(timezone.utc).isoformat(),
            "output_file": of_rel,
            "data": data or {},
        }
    _findings.append(rec)
    _tok("__CRUCIBLE_FINDING__", json.dumps(rec))
    _flush_findings()


def _flush_findings():
    if _RUN_DIR is None:
        return
    try:
        if _us is not None:
            out = [_us.augment_finding(dict(f), tool="forge") for f in _findings]
            _us.atomic_write_json(_RUN_DIR / "findings.json", out)
        else:
            (_RUN_DIR / "findings.json").write_text(
                json.dumps(_findings, indent=2), encoding="utf-8")
    except Exception:
        pass


def _save_checkpoint():
    if _RUN_DIR is None:
        return
    try:
        cp = {
            "findings_count": len(_findings),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        (_RUN_DIR / "checkpoint.json").write_text(
            json.dumps(cp, indent=2), encoding="utf-8")
    except Exception:
        pass


# ── Azure auditor ─────────────────────────────────────────────────────────────

def audit_azure(subscription_id: str, output_dir: Path) -> None:
    _check_pause()
    log(f"[azure] Starting Azure audit — subscription {subscription_id}")
    status("azure", "Azure Subscription Audit", "running")
    az = shutil.which("az")
    if not az:
        err("az CLI not installed — skipping Azure audit")
        status("azure", "Azure Subscription Audit", "skipped")
        return
    log(f"[azure] az CLI found at {az}")

    out_dir = output_dir / "azure"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _az_run(args: list, out_name: str) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [az] + args + ["--subscription", subscription_id, "--output", "json"]
        log(f"[azure] Running: az {' '.join(args)}")
        try:
            if _ur is not None:
                cp = _ur.run_tool(cmd, output_file=str(out_file),
                                    timeout=300, tool_name="az",
                                    errors_log=(str(_RUN_DIR / "errors.log")
                                                if _RUN_DIR is not None else None))
            else:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            raw = cp.stdout or ""
            if not raw.strip() and (cp.stderr or "").strip():
                out_file.write_text(cp.stderr, encoding="utf-8")
            else:
                out_file.write_text(raw, encoding="utf-8")
            try:
                return json.loads(raw) if raw.strip() else None
            except json.JSONDecodeError:
                return None
        except Exception as exc:
            err(f"az {args[0] if args else '?'} failed: {exc}")
            return None

    _save_checkpoint()
    log("[azure] Enumerating storage accounts...")
    accounts = _az_run(["storage", "account", "list"], "storage_accounts.json") or []
    log(f"[azure] Found {len(accounts)} storage account(s)")
    _check_pause()
    for acct in accounts:
        name = acct.get("name", "")
        rg   = acct.get("resourceGroup", "")
        log(f"[azure] Checking storage account {name} (rg={rg})...")
        if acct.get("enableHttpsTrafficOnly") is False:
            log(f"[azure] {name} — HTTPS-only disabled (HIGH)")
            finding(title=f"Azure Storage: Azure Storage Account allows HTTP: {name}",
                     severity="HIGH",
                     description=("Storage account does not enforce HTTPS-only. "
                                   "Data in transit may traverse plaintext."),
                     data={"catalogue_id": "FORGE-AZ-001",
                           "affected": f"{rg}/{name}",
                           "remediation": "az storage account update --https-only true"},
                     output_file=str(out_dir / "storage_accounts.json"))
        else:
            log(f"[azure] {name} — HTTPS-only OK")
        net_acl = (acct.get("networkRuleSet") or {}).get("defaultAction", "")
        if net_acl == "Allow":
            log(f"[azure] {name} — network ACL defaults to Allow (HIGH)")
            finding(title=f"Azure Storage: Azure Storage Account publicly accessible: {name}",
                     severity="HIGH",
                     description=("Storage account network ACL defaults to Allow "
                                   "(no IP restrictions configured)."),
                     data={"catalogue_id": "FORGE-AZ-002",
                           "affected": f"{rg}/{name}"},
                     output_file=str(out_dir / "storage_accounts.json"))
        else:
            log(f"[azure] {name} — network ACL: {net_acl}")

    _check_pause()
    _save_checkpoint()
    log("[azure] Enumerating key vaults...")
    vaults = _az_run(["keyvault", "list"], "keyvaults.json") or []
    log(f"[azure] Found {len(vaults)} key vault(s)")
    _check_pause()
    for kv in vaults:
        name = kv.get("name", "")
        props = kv.get("properties") or {}
        log(f"[azure] Checking key vault {name}...")
        if not props.get("enableSoftDelete", True):
            log(f"[azure] {name} — soft-delete disabled (MEDIUM)")
            finding(title=f"Azure Key Vault: Azure Key Vault soft-delete disabled: {name}",
                     severity="MEDIUM",
                     description="Soft-delete not enabled — accidental deletions are unrecoverable.",
                     data={"catalogue_id": "FORGE-AZ-010", "affected": name},
                     output_file=str(out_dir / "keyvaults.json"))
        if not props.get("enablePurgeProtection"):
            log(f"[azure] {name} — purge-protection disabled (MEDIUM)")
            finding(title=f"Azure Key Vault: Azure Key Vault purge-protection disabled: {name}",
                     severity="MEDIUM",
                     description="Purge-protection disabled — soft-deleted keys can be purged immediately.",
                     data={"catalogue_id": "FORGE-AZ-011", "affected": name},
                     output_file=str(out_dir / "keyvaults.json"))
        if props.get("enableSoftDelete", True) and props.get("enablePurgeProtection"):
            log(f"[azure] {name} — soft-delete + purge-protection OK")

    _check_pause()
    _save_checkpoint()
    log("[azure] Enumerating virtual machines...")
    vms = _az_run(["vm", "list"], "vms.json") or []
    log(f"[azure] Found {len(vms)} VM(s)")
    _check_pause()
    for vm in vms:
        name = vm.get("name", "")
        rg   = vm.get("resourceGroup", "")
        log(f"[azure] Checking VM {name} (rg={rg})...")
        sd   = (vm.get("storageProfile") or {}).get("osDisk") or {}
        enc  = (sd.get("encryptionSettings") or {}).get("enabled") if sd else None
        if enc is False:
            log(f"[azure] {name} — OS disk unencrypted (HIGH)")
            finding(title=f"Azure VM: Azure VM OS disk unencrypted: {name}",
                     severity="HIGH",
                     description="Azure Disk Encryption (ADE) is disabled on the OS disk.",
                     data={"catalogue_id": "FORGE-AZ-020", "affected": f"{rg}/{name}"},
                     output_file=str(out_dir / "vms.json"))
        else:
            log(f"[azure] {name} — disk encryption OK")

    log(f"[azure] Azure audit complete — subscription {subscription_id}")
    status("azure", "Azure Subscription Audit", "complete")


# ── GCP auditor ───────────────────────────────────────────────────────────────

def audit_gcp(project_id: str, output_dir: Path) -> None:
    _check_pause()
    log(f"[gcp] Starting GCP audit — project {project_id}")
    status("gcp", "GCP Project Audit", "running")
    gcloud = shutil.which("gcloud")
    if not gcloud:
        err("gcloud CLI not installed — skipping GCP audit")
        status("gcp", "GCP Project Audit", "skipped")
        return
    log(f"[gcp] gcloud CLI found at {gcloud}")

    out_dir = output_dir / "gcp"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _g_run(args: list, out_name: str) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [gcloud] + args + ["--project", project_id, "--format=json"]
        log(f"[gcp] Running: gcloud {' '.join(args)}")
        try:
            if _ur is not None:
                cp = _ur.run_tool(cmd, output_file=str(out_file),
                                    timeout=300, tool_name="gcloud",
                                    errors_log=(str(_RUN_DIR / "errors.log")
                                                if _RUN_DIR is not None else None))
            else:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            raw = cp.stdout or ""
            if not raw.strip() and (cp.stderr or "").strip():
                out_file.write_text(cp.stderr, encoding="utf-8")
            else:
                out_file.write_text(raw, encoding="utf-8")
            try:
                return json.loads(raw) if raw.strip() else None
            except json.JSONDecodeError:
                return None
        except Exception as exc:
            err(f"gcloud {' '.join(args[:2])} failed: {exc}")
            return None

    _save_checkpoint()
    log("[gcp] Enumerating GCS buckets...")
    buckets = _g_run(["storage", "buckets", "list"], "buckets.json") or []
    log(f"[gcp] Found {len(buckets)} bucket(s)")
    _check_pause()
    for b in buckets:
        name = b.get("name", "")
        log(f"[gcp] Checking bucket {name}...")
        iam_cfg = (b.get("iamConfiguration") or {}).get("uniformBucketLevelAccess") or {}
        if not iam_cfg.get("enabled"):
            log(f"[gcp] {name} — uniform access disabled (MEDIUM)")
            finding(title=f"GCS: GCS bucket uniform access disabled: {name}",
                     severity="MEDIUM",
                     description="Uniform bucket-level access disabled — legacy ACLs may grant unintended access.",
                     data={"catalogue_id": "FORGE-GCP-001", "affected": name},
                     output_file=str(out_dir / "buckets.json"))
        else:
            log(f"[gcp] {name} — uniform access OK")

    _check_pause()
    _save_checkpoint()
    log("[gcp] Enumerating compute instances...")
    instances = _g_run(["compute", "instances", "list"], "instances.json") or []
    log(f"[gcp] Found {len(instances)} instance(s)")
    _check_pause()
    for inst in instances:
        _check_pause()
        name = inst.get("name", "")
        log(f"[gcp] Checking instance {name}...")
        sas  = inst.get("serviceAccounts") or []
        for sa in sas:
            email = sa.get("email", "")
            if "compute@developer.gserviceaccount.com" in email:
                log(f"[gcp] {name} — uses default service account {email} (MEDIUM)")
                finding(title=f"GCE: GCE instance uses default service account: {name}",
                         severity="MEDIUM",
                         description="Default Compute Engine service account grants over-broad scopes.",
                         data={"catalogue_id": "FORGE-GCP-010",
                               "affected": name,
                               "service_account": email},
                         output_file=str(out_dir / "instances.json"))
        for iface in inst.get("networkInterfaces", []):
            if iface.get("accessConfigs"):
                log(f"[gcp] {name} — has external IP (INFO)")
                finding(title=f"GCE: GCE instance has public IP: {name}",
                         severity="INFO",
                         description="Instance has an ephemeral or static external IP configured.",
                         data={"catalogue_id": "FORGE-GCP-011",
                               "affected": name},
                         output_file=str(out_dir / "instances.json"))

    _check_pause()
    _save_checkpoint()
    log("[gcp] Retrieving IAM policy...")
    iam = _g_run(["projects", "get-iam-policy", project_id], "iam_policy.json") or {}
    bindings = iam.get("bindings", []) or []
    log(f"[gcp] IAM policy has {len(bindings)} binding(s)")
    _check_pause()
    for binding in bindings:
        role = binding.get("role", "")
        if role in ("roles/owner", "roles/editor"):
            for member in binding.get("members", []) or []:
                if member.startswith("user:") or member.startswith("serviceAccount:"):
                    sev = "HIGH" if role == "roles/owner" else "MEDIUM"
                    log(f"[gcp] {member} — project-level {role} ({sev})")
                    finding(title=f"GCP: GCP project-level {role} granted to {member}",
                             severity=sev,
                             description=("Over-privileged role granted at project level. "
                                           "Prefer per-resource or custom roles."),
                             data={"catalogue_id": "FORGE-GCP-020",
                                   "affected": member,
                                   "role": role},
                             output_file=str(out_dir / "iam_policy.json"))

    log(f"[gcp] GCP audit complete — project {project_id}")
    status("gcp", "GCP Project Audit", "complete")


# ── AWS auditor ───────────────────────────────────────────────────────────────

def audit_aws(profile: str, region: str, output_dir: Path) -> None:
    _check_pause()
    log(f"[aws] Starting AWS audit — profile={profile or 'default'}, region={region or 'default'}")
    status("aws", "AWS Account Audit", "running")
    aws = shutil.which("aws")
    if not aws:
        err("aws CLI not installed — skipping AWS audit")
        status("aws", "AWS Account Audit", "skipped")
        return
    log(f"[aws] aws CLI found at {aws}")

    out_dir = output_dir / "aws"
    out_dir.mkdir(parents=True, exist_ok=True)

    def _aws_run(args: list, out_name: str, use_region: bool = True) -> dict | list | None:
        out_file = out_dir / out_name
        cmd = [aws] + args + ["--output", "json"]
        if profile:
            cmd += ["--profile", profile]
        if use_region and region:
            cmd += ["--region", region]
        log(f"[aws] Running: aws {' '.join(args)}")
        try:
            if _ur is not None:
                cp = _ur.run_tool(cmd, output_file=str(out_file),
                                    timeout=300, tool_name="aws",
                                    errors_log=(str(_RUN_DIR / "errors.log")
                                                if _RUN_DIR is not None else None))
            else:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            raw = cp.stdout or ""
            if not raw.strip() and (cp.stderr or "").strip():
                out_file.write_text(cp.stderr, encoding="utf-8")
            else:
                out_file.write_text(raw, encoding="utf-8")
            try:
                return json.loads(raw) if raw.strip() else None
            except json.JSONDecodeError:
                return None
        except Exception as exc:
            err(f"aws {' '.join(args[:2])} failed: {exc}")
            return None

    # ── S3 ────────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting S3 bucket audit...")
    status("aws", "S3 bucket audit", "running")
    buckets_resp = _aws_run(["s3api", "list-buckets"], "s3_buckets.json", use_region=False) or {}
    buckets = buckets_resp.get("Buckets") or []
    log(f"[aws] Found {len(buckets)} S3 bucket(s)")
    _check_pause()
    for bucket in buckets:
        _check_pause()
        name = bucket.get("Name", "")
        log(f"[aws] Checking S3 bucket {name}...")

        log(f"[aws] {name} — checking public access block...")
        pab = _aws_run(["s3api", "get-public-access-block", "--bucket", name],
                        f"s3_{name}_public_access.json", use_region=False) or {}
        pab_cfg = pab.get("PublicAccessBlockConfiguration") or {}
        if not pab_cfg:
            log(f"[aws] {name} — no public access block configured (HIGH)")
            finding(title=f"S3 bucket missing public access block: {name}",
                     severity="HIGH",
                     description="No S3 public access block configured — objects may be publicly accessible.",
                     data={"catalogue_id": "FORGE-AWS-001", "affected": name,
                           "remediation": "aws s3api put-public-access-block --bucket <name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"},
                     output_file=str(out_dir / f"s3_{name}_public_access.json"))
        elif not all(pab_cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                                "BlockPublicPolicy", "RestrictPublicBuckets")):
            log(f"[aws] {name} — incomplete public access block (MEDIUM)")
            finding(title=f"S3 bucket incomplete public access block: {name}",
                     severity="MEDIUM",
                     description="Not all four public access block settings are enabled.",
                     data={"catalogue_id": "FORGE-AWS-002", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_public_access.json"))
        else:
            log(f"[aws] {name} — public access block OK")

        log(f"[aws] {name} — checking versioning...")
        versioning = _aws_run(["s3api", "get-bucket-versioning", "--bucket", name],
                               f"s3_{name}_versioning.json", use_region=False) or {}
        if versioning.get("Status") != "Enabled":
            log(f"[aws] {name} — versioning disabled (LOW)")
            finding(title=f"S3 bucket versioning disabled: {name}",
                     severity="LOW",
                     description="Versioning is not enabled — accidental deletions or overwrites are unrecoverable.",
                     data={"catalogue_id": "FORGE-AWS-003", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_versioning.json"))
        else:
            log(f"[aws] {name} — versioning enabled")

        # S3 deep: MFA Delete (FORGE-AWS-007)
        if versioning.get("MFADelete") != "Enabled":
            log(f"[aws] {name} — MFA Delete not enabled (MEDIUM)")
            finding(title=f"S3 bucket MFA Delete not enabled: {name}",
                     severity="MEDIUM",
                     description="MFA Delete is not enabled — versioned objects can be permanently deleted without MFA.",
                     data={"catalogue_id": "FORGE-AWS-007", "affected": name,
                           "remediation": "Enable MFA Delete via aws s3api put-bucket-versioning with MFA device."},
                     output_file=str(out_dir / f"s3_{name}_versioning.json"))
        else:
            log(f"[aws] {name} — MFA Delete enabled")

        log(f"[aws] {name} — checking encryption...")
        enc = _aws_run(["s3api", "get-bucket-encryption", "--bucket", name],
                        f"s3_{name}_encryption.json", use_region=False)
        if enc is None:
            log(f"[aws] {name} — no default encryption (MEDIUM)")
            finding(title=f"S3 bucket default encryption not configured: {name}",
                     severity="MEDIUM",
                     description="No default server-side encryption configured on the bucket.",
                     data={"catalogue_id": "FORGE-AWS-004", "affected": name,
                           "remediation": "Enable SSE-S3 or SSE-KMS default encryption."},
                     output_file=str(out_dir / f"s3_{name}_encryption.json"))
        else:
            log(f"[aws] {name} — default encryption configured")

        log(f"[aws] {name} — checking access logging...")
        logging_resp = _aws_run(["s3api", "get-bucket-logging", "--bucket", name],
                                 f"s3_{name}_logging.json", use_region=False) or {}
        if not logging_resp.get("LoggingEnabled"):
            log(f"[aws] {name} — access logging disabled (LOW)")
            finding(title=f"S3 bucket access logging disabled: {name}",
                     severity="LOW",
                     description="Server access logging is not enabled — access patterns are not auditable.",
                     data={"catalogue_id": "FORGE-AWS-005", "affected": name},
                     output_file=str(out_dir / f"s3_{name}_logging.json"))
        else:
            log(f"[aws] {name} — access logging enabled")

        # S3 deep: bucket policy public status (FORGE-AWS-006)
        log(f"[aws] {name} — checking bucket policy public status...")
        pol_status = _aws_run(["s3api", "get-bucket-policy-status", "--bucket", name],
                               f"s3_{name}_policy_status.json", use_region=False) or {}
        ps = pol_status.get("PolicyStatus") or {}
        if ps.get("IsPublic") is True:
            log(f"[aws] {name} — bucket policy is PUBLIC (CRITICAL)")
            finding(title=f"S3 bucket policy is public: {name}",
                     severity="CRITICAL",
                     description="The S3 bucket policy evaluates as public — objects may be accessible to anyone on the internet.",
                     data={"catalogue_id": "FORGE-AWS-006", "affected": name,
                           "remediation": "Review and restrict the bucket policy. Enable S3 Block Public Access."},
                     output_file=str(out_dir / f"s3_{name}_policy_status.json"))
        else:
            log(f"[aws] {name} — bucket policy not public")
    log(f"[aws] S3 audit complete — checked {len(buckets)} bucket(s)")

    # ── EC2 ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting EC2 instance audit...")
    status("aws", "EC2 instance audit", "running")
    instances_resp = _aws_run(["ec2", "describe-instances"], "ec2_instances.json") or {}
    reservations = instances_resp.get("Reservations") or []
    total_instances = sum(len(r.get("Instances") or []) for r in reservations)
    log(f"[aws] Found {total_instances} EC2 instance(s) across {len(reservations)} reservation(s)")
    _check_pause()
    for reservation in reservations:
        for inst in reservation.get("Instances") or []:
            iid = inst.get("InstanceId", "")
            name_tag = ""
            for tag in inst.get("Tags") or []:
                if tag.get("Key") == "Name":
                    name_tag = tag.get("Value", "")
            label = f"{name_tag} ({iid})" if name_tag else iid
            log(f"[aws] Checking EC2 instance {label}...")

            if inst.get("PublicIpAddress"):
                log(f"[aws] {label} — has public IP {inst['PublicIpAddress']} (INFO)")
                finding(title=f"EC2 instance with public IP: {label}",
                         severity="INFO",
                         description=f"Instance {iid} has public IP {inst['PublicIpAddress']}.",
                         data={"catalogue_id": "FORGE-AWS-010", "affected": label},
                         output_file=str(out_dir / "ec2_instances.json"))
            else:
                log(f"[aws] {label} — no public IP")

            # EC2 deep: IMDSv2 check (FORGE-AWS-014)
            meta_opts = inst.get("MetadataOptions") or {}
            if meta_opts.get("HttpTokens") != "required":
                log(f"[aws] {label} — IMDSv2 not enforced (MEDIUM)")
                finding(title=f"EC2 instance IMDSv2 not enforced: {label}",
                         severity="MEDIUM",
                         description=f"Instance {iid} does not require IMDSv2 (HttpTokens != required). "
                                     "IMDSv1 is vulnerable to SSRF-based credential theft.",
                         data={"catalogue_id": "FORGE-AWS-014", "affected": label,
                               "remediation": "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required"},
                         output_file=str(out_dir / "ec2_instances.json"))
            else:
                log(f"[aws] {label} — IMDSv2 enforced OK")

            # EC2 deep: user data secrets (FORGE-AWS-016)
            log(f"[aws] {label} — checking user data for secrets...")
            ud_resp = _aws_run(["ec2", "describe-instance-attribute",
                                "--attribute", "userData", "--instance-id", iid],
                               f"ec2_{iid}_userdata.json")
            ud_val = (ud_resp or {}).get("UserData", {}).get("Value", "") if ud_resp else ""
            if ud_val:
                try:
                    ud_decoded = base64.b64decode(ud_val).decode("utf-8", errors="replace")
                    secret_matches = _SECRET_PATTERNS.findall(ud_decoded)
                    if secret_matches:
                        matched_keys = sorted(set(m.lower() for m in secret_matches))
                        log(f"[aws] {label} — user data contains secret-like patterns: {matched_keys} (CRITICAL)")
                        finding(title=f"EC2 instance user data contains secrets: {label}",
                                 severity="CRITICAL",
                                 description=f"Instance {iid} user data contains secret-like environment variables or values "
                                             f"matching patterns: {', '.join(matched_keys)}. Anyone with ec2:DescribeInstanceAttribute "
                                             "can read these.",
                                 data={"catalogue_id": "FORGE-AWS-016", "affected": label,
                                       "remediation": "Move secrets to AWS Secrets Manager or SSM Parameter Store (SecureString)."},
                                 output_file=str(out_dir / f"ec2_{iid}_userdata.json"))
                    else:
                        log(f"[aws] {label} — user data present but no secret patterns found")
                except Exception:
                    log(f"[aws] {label} — could not decode user data")
            else:
                log(f"[aws] {label} — no user data configured")

    _check_pause()
    log("[aws] Checking EBS volumes...")
    ebs_resp = _aws_run(["ec2", "describe-volumes"], "ec2_volumes.json") or {}
    volumes = ebs_resp.get("Volumes") or []
    log(f"[aws] Found {len(volumes)} EBS volume(s)")
    _check_pause()
    for vol in volumes:
        vid = vol.get("VolumeId", "")
        if not vol.get("Encrypted"):
            log(f"[aws] EBS {vid} — unencrypted (HIGH)")
            finding(title=f"EBS volume unencrypted: {vid}",
                     severity="HIGH",
                     description="EBS volume is not encrypted at rest.",
                     data={"catalogue_id": "FORGE-AWS-011", "affected": vid,
                           "remediation": "Create an encrypted snapshot and replace the volume."},
                     output_file=str(out_dir / "ec2_volumes.json"))
        else:
            log(f"[aws] EBS {vid} — encrypted OK")

    _check_pause()
    log("[aws] Checking security groups...")
    sgs_resp = _aws_run(["ec2", "describe-security-groups"], "ec2_security_groups.json") or {}
    sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200}
    sgs = sgs_resp.get("SecurityGroups") or []
    log(f"[aws] Found {len(sgs)} security group(s)")
    _check_pause()
    for sg in sgs:
        sg_id = sg.get("GroupId", "")
        sg_name = sg.get("GroupName", "")
        log(f"[aws] Checking security group {sg_name} ({sg_id})...")
        for perm in sg.get("IpPermissions") or []:
            from_port = perm.get("FromPort", 0)
            to_port = perm.get("ToPort", 0)
            for ip_range in perm.get("IpRanges") or []:
                cidr = ip_range.get("CidrIp", "")
                if cidr == "0.0.0.0/0":
                    exposed = {p for p in sensitive_ports if from_port <= p <= to_port}
                    if exposed:
                        log(f"[aws] {sg_name} ({sg_id}) — exposes ports {sorted(exposed)} to 0.0.0.0/0 (HIGH)")
                        finding(title=f"Security group {sg_name} ({sg_id}) exposes sensitive ports to 0.0.0.0/0",
                                 severity="HIGH",
                                 description=f"Inbound rule allows 0.0.0.0/0 access to port(s) {', '.join(str(p) for p in sorted(exposed))}.",
                                 data={"catalogue_id": "FORGE-AWS-012",
                                       "affected": f"{sg_name} ({sg_id})",
                                       "remediation": "Restrict source CIDR to known IP ranges."},
                                 output_file=str(out_dir / "ec2_security_groups.json"))
                    elif from_port == 0 and to_port == 65535:
                        log(f"[aws] {sg_name} ({sg_id}) — allows ALL ports from 0.0.0.0/0 (CRITICAL)")
                        finding(title=f"Security group {sg_name} ({sg_id}) allows all ports from 0.0.0.0/0",
                                 severity="CRITICAL",
                                 description="Inbound rule allows unrestricted access (all ports) from any IP.",
                                 data={"catalogue_id": "FORGE-AWS-013",
                                       "affected": f"{sg_name} ({sg_id})"},
                                 output_file=str(out_dir / "ec2_security_groups.json"))
    log(f"[aws] EC2 audit complete — {total_instances} instance(s), {len(volumes)} volume(s), {len(sgs)} SG(s)")

    # ── IAM ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting IAM audit...")
    status("aws", "IAM audit", "running")
    users_resp = _aws_run(["iam", "list-users"], "iam_users.json", use_region=False) or {}
    iam_users = users_resp.get("Users") or []
    log(f"[aws] Found {len(iam_users)} IAM user(s)")
    _check_pause()
    for user in iam_users:
        _check_pause()
        uname = user.get("UserName", "")
        log(f"[aws] Checking IAM user {uname}...")

        log(f"[aws] {uname} — checking MFA devices...")
        mfa_resp = _aws_run(["iam", "list-mfa-devices", "--user-name", uname],
                              f"iam_{uname}_mfa.json", use_region=False) or {}
        mfa_devices = mfa_resp.get("MFADevices") or []
        if not mfa_devices:
            log(f"[aws] {uname} — no MFA configured (HIGH)")
            finding(title=f"IAM user without MFA: {uname}",
                     severity="HIGH",
                     description=f"IAM user {uname} has no MFA device configured.",
                     data={"catalogue_id": "FORGE-AWS-020", "affected": uname,
                           "remediation": "Enable virtual or hardware MFA for this user."},
                     output_file=str(out_dir / f"iam_{uname}_mfa.json"))
        else:
            log(f"[aws] {uname} — MFA enabled ({len(mfa_devices)} device(s))")

        log(f"[aws] {uname} — checking attached policies...")
        policies_resp = _aws_run(["iam", "list-attached-user-policies", "--user-name", uname],
                                   f"iam_{uname}_policies.json", use_region=False) or {}
        attached = policies_resp.get("AttachedPolicies") or []
        log(f"[aws] {uname} — {len(attached)} attached polic(ies)")
        for pol in attached:
            if pol.get("PolicyArn", "").endswith("/AdministratorAccess"):
                log(f"[aws] {uname} — has AdministratorAccess directly attached (CRITICAL)")
                finding(title=f"IAM user has AdministratorAccess: {uname}",
                         severity="CRITICAL",
                         description=f"User {uname} has the AdministratorAccess managed policy directly attached.",
                         data={"catalogue_id": "FORGE-AWS-021", "affected": uname,
                               "remediation": "Remove direct AdministratorAccess; use role assumption with least-privilege."},
                         output_file=str(out_dir / f"iam_{uname}_policies.json"))

        log(f"[aws] {uname} — checking access keys...")
        keys_resp = _aws_run(["iam", "list-access-keys", "--user-name", uname],
                               f"iam_{uname}_keys.json", use_region=False) or {}
        access_keys = keys_resp.get("AccessKeyMetadata") or []
        log(f"[aws] {uname} — {len(access_keys)} access key(s)")
        for key in access_keys:
            created = key.get("CreateDate", "")
            if created:
                try:
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
                    if age > 90:
                        log(f"[aws] {uname} — access key {key.get('AccessKeyId', '')} is {age} days old (MEDIUM)")
                        finding(title=f"IAM access key older than 90 days: {uname}/{key.get('AccessKeyId', '')}",
                                 severity="MEDIUM",
                                 description=f"Access key is {age} days old. Rotate keys regularly.",
                                 data={"catalogue_id": "FORGE-AWS-022", "affected": uname},
                                 output_file=str(out_dir / f"iam_{uname}_keys.json"))
                    else:
                        log(f"[aws] {uname} — access key {key.get('AccessKeyId', '')} age OK ({age} days)")
                except Exception:
                    pass
    log(f"[aws] IAM user audit complete — checked {len(iam_users)} user(s)")

    _check_pause()
    log("[aws] Generating credential report...")
    cred_report = _aws_run(["iam", "generate-credential-report"], "iam_cred_gen.json", use_region=False)
    log("[aws] Retrieving credential report...")
    cred_data = _aws_run(["iam", "get-credential-report"], "iam_cred_report.json", use_region=False) or {}
    if cred_data.get("Content"):
        log("[aws] Parsing credential report for root account keys...")
        try:
            csv_text = base64.b64decode(cred_data["Content"]).decode("utf-8")
            for line in csv_text.strip().split("\n")[1:]:
                cols = line.split(",")
                if len(cols) > 1 and cols[0] == "<root_account>":
                    if len(cols) > 8 and cols[8].lower() == "true":
                        log("[aws] Root account has active access keys (CRITICAL)")
                        finding(title="Root account has active access keys",
                                 severity="CRITICAL",
                                 description="The AWS root account has access keys configured. Root keys should never exist.",
                                 data={"catalogue_id": "FORGE-AWS-023", "affected": "root",
                                       "remediation": "Delete root access keys and use IAM users/roles instead."},
                                 output_file=str(out_dir / "iam_cred_report.json"))
                    else:
                        log("[aws] Root account — no active access keys")
        except Exception:
            pass
    else:
        log("[aws] Credential report not available")

    # ── RDS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting RDS audit...")
    status("aws", "RDS audit", "running")
    rds_resp = _aws_run(["rds", "describe-db-instances"], "rds_instances.json") or {}
    rds_instances = rds_resp.get("DBInstances") or []
    log(f"[aws] Found {len(rds_instances)} RDS instance(s)")
    _check_pause()
    for db in rds_instances:
        db_id = db.get("DBInstanceIdentifier", "")
        engine = db.get("Engine", "unknown")
        log(f"[aws] Checking RDS instance {db_id} (engine={engine})...")

        if db.get("PubliclyAccessible"):
            log(f"[aws] {db_id} — publicly accessible (HIGH)")
            finding(title=f"RDS instance publicly accessible: {db_id}",
                     severity="HIGH",
                     description="RDS instance is configured as publicly accessible.",
                     data={"catalogue_id": "FORGE-AWS-030", "affected": db_id,
                           "remediation": "Disable public accessibility unless explicitly required."},
                     output_file=str(out_dir / "rds_instances.json"))
        else:
            log(f"[aws] {db_id} — not publicly accessible")

        if not db.get("StorageEncrypted"):
            log(f"[aws] {db_id} — storage unencrypted (HIGH)")
            finding(title=f"RDS instance unencrypted: {db_id}",
                     severity="HIGH",
                     description="RDS storage encryption is not enabled.",
                     data={"catalogue_id": "FORGE-AWS-031", "affected": db_id,
                           "remediation": "Enable encryption at rest (requires snapshot + restore for existing instances)."},
                     output_file=str(out_dir / "rds_instances.json"))
        else:
            log(f"[aws] {db_id} — storage encrypted")

        if db.get("BackupRetentionPeriod", 0) == 0:
            log(f"[aws] {db_id} — no automated backups (MEDIUM)")
            finding(title=f"RDS instance no automated backups: {db_id}",
                     severity="MEDIUM",
                     description="Automated backups are disabled (retention period is 0 days).",
                     data={"catalogue_id": "FORGE-AWS-032", "affected": db_id},
                     output_file=str(out_dir / "rds_instances.json"))
        else:
            log(f"[aws] {db_id} — backup retention: {db.get('BackupRetentionPeriod')} day(s)")

        # RDS deep: Deletion Protection (FORGE-AWS-033)
        if not db.get("DeletionProtection"):
            log(f"[aws] {db_id} — deletion protection disabled (MEDIUM)")
            finding(title=f"RDS instance deletion protection disabled: {db_id}",
                     severity="MEDIUM",
                     description="Deletion protection is disabled — the database can be deleted without safeguard.",
                     data={"catalogue_id": "FORGE-AWS-033", "affected": db_id,
                           "remediation": "aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection"},
                     output_file=str(out_dir / "rds_instances.json"))
        else:
            log(f"[aws] {db_id} — deletion protection enabled")

        # RDS deep: Multi-AZ (FORGE-AWS-034)
        if not db.get("MultiAZ"):
            log(f"[aws] {db_id} — Multi-AZ disabled (MEDIUM)")
            finding(title=f"RDS instance not Multi-AZ: {db_id}",
                     severity="MEDIUM",
                     description="Multi-AZ deployment is not enabled — no standby replica for automatic failover.",
                     data={"catalogue_id": "FORGE-AWS-034", "affected": db_id,
                           "remediation": "aws rds modify-db-instance --db-instance-identifier <id> --multi-az"},
                     output_file=str(out_dir / "rds_instances.json"))
        else:
            log(f"[aws] {db_id} — Multi-AZ enabled")
    log(f"[aws] RDS audit complete — checked {len(rds_instances)} instance(s)")

    # ── CloudTrail ────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting CloudTrail audit...")
    status("aws", "CloudTrail audit", "running")
    trails_resp = _aws_run(["cloudtrail", "describe-trails"], "cloudtrail_trails.json") or {}
    trails = trails_resp.get("trailList") or []
    log(f"[aws] Found {len(trails)} CloudTrail trail(s)")
    if not trails:
        log("[aws] No CloudTrail trails configured (HIGH)")
        finding(title="No CloudTrail trails configured",
                 severity="HIGH",
                 description="No CloudTrail trails exist in this region/account. API activity is not logged.",
                 data={"catalogue_id": "FORGE-AWS-040",
                       "remediation": "Create a multi-region trail logging to a dedicated S3 bucket."},
                 output_file=str(out_dir / "cloudtrail_trails.json"))
    else:
        _check_pause()
        for trail in trails:
            trail_name = trail.get("Name", "")
            log(f"[aws] Checking trail {trail_name}...")
            trail_status = _aws_run(["cloudtrail", "get-trail-status", "--name", trail_name],
                                      f"cloudtrail_{trail_name}_status.json") or {}
            if not trail_status.get("IsLogging"):
                log(f"[aws] {trail_name} — not actively logging (HIGH)")
                finding(title=f"CloudTrail not actively logging: {trail_name}",
                         severity="HIGH",
                         description=f"Trail {trail_name} exists but is not actively logging.",
                         data={"catalogue_id": "FORGE-AWS-041", "affected": trail_name,
                               "remediation": "aws cloudtrail start-logging --name <trail>"},
                         output_file=str(out_dir / f"cloudtrail_{trail_name}_status.json"))
            else:
                log(f"[aws] {trail_name} — actively logging OK")

            # CloudTrail deep: KMS encryption (FORGE-AWS-042)
            if not trail.get("KmsKeyId"):
                log(f"[aws] {trail_name} — not encrypted with KMS (MEDIUM)")
                finding(title=f"CloudTrail not encrypted with KMS: {trail_name}",
                         severity="MEDIUM",
                         description=f"Trail {trail_name} log files are not encrypted with a customer-managed KMS key.",
                         data={"catalogue_id": "FORGE-AWS-042", "affected": trail_name,
                               "remediation": "aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>"},
                         output_file=str(out_dir / "cloudtrail_trails.json"))
            else:
                log(f"[aws] {trail_name} — KMS encryption configured")

            # CloudTrail deep: CloudWatch Logs integration (FORGE-AWS-043)
            if not trail.get("CloudWatchLogsLogGroupArn"):
                log(f"[aws] {trail_name} — not integrated with CloudWatch Logs (LOW)")
                finding(title=f"CloudTrail not integrated with CloudWatch Logs: {trail_name}",
                         severity="LOW",
                         description=f"Trail {trail_name} does not deliver events to CloudWatch Logs for real-time alerting.",
                         data={"catalogue_id": "FORGE-AWS-043", "affected": trail_name,
                               "remediation": "Configure a CloudWatch Logs log group for the trail."},
                         output_file=str(out_dir / "cloudtrail_trails.json"))
            else:
                log(f"[aws] {trail_name} — CloudWatch Logs integration OK")
    log(f"[aws] CloudTrail audit complete — {len(trails)} trail(s)")

    # ── KMS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting KMS audit...")
    status("aws", "KMS audit", "running")
    keys_resp = _aws_run(["kms", "list-keys"], "kms_keys.json") or {}
    kms_keys = keys_resp.get("Keys") or []
    log(f"[aws] Found {len(kms_keys)} KMS key(s)")
    _check_pause()
    for key in kms_keys:
        _check_pause()
        key_id = key.get("KeyId", "")
        log(f"[aws] Checking KMS key {key_id[:8]}...")
        key_detail = _aws_run(["kms", "describe-key", "--key-id", key_id],
                                f"kms_{key_id[:8]}_detail.json") or {}
        km = key_detail.get("KeyMetadata") or {}
        manager = km.get("KeyManager", "unknown")
        state = km.get("KeyState", "unknown")
        log(f"[aws] KMS {key_id[:8]} — manager={manager}, state={state}")
        if manager == "CUSTOMER" and state == "Enabled":
            log(f"[aws] KMS {key_id[:8]} — customer-managed + enabled, checking rotation...")
            rotation = _aws_run(["kms", "get-key-rotation-status", "--key-id", key_id],
                                  f"kms_{key_id[:8]}_rotation.json") or {}
            if not rotation.get("KeyRotationEnabled"):
                log(f"[aws] KMS {key_id[:8]} — rotation disabled (MEDIUM)")
                finding(title=f"KMS key rotation disabled: {key_id[:8]}...",
                         severity="MEDIUM",
                         description="Automatic key rotation is not enabled for this customer-managed KMS key.",
                         data={"catalogue_id": "FORGE-AWS-050", "affected": key_id,
                               "remediation": "aws kms enable-key-rotation --key-id <key>"},
                         output_file=str(out_dir / f"kms_{key_id[:8]}_rotation.json"))
            else:
                log(f"[aws] KMS {key_id[:8]} — rotation enabled OK")
        else:
            log(f"[aws] KMS {key_id[:8]} — skipped (not customer-managed or not enabled)")
    log(f"[aws] KMS audit complete — checked {len(kms_keys)} key(s)")

    # ── Lambda ────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting Lambda audit...")
    status("aws", "Lambda audit", "running")
    lambda_resp = _aws_run(["lambda", "list-functions"], "lambda_functions.json") or {}
    lambda_fns = lambda_resp.get("Functions") or []
    log(f"[aws] Found {len(lambda_fns)} Lambda function(s)")
    _check_pause()
    for fn in lambda_fns:
        _check_pause()
        fn_name = fn.get("FunctionName", "")
        fn_arn = fn.get("FunctionArn", "")
        log(f"[aws] Checking Lambda function {fn_name}...")

        # FORGE-AWS-060: secrets in environment variables
        env_vars = (fn.get("Environment") or {}).get("Variables") or {}
        if env_vars:
            secret_keys = [k for k in env_vars if _SECRET_PATTERNS.search(k)]
            if secret_keys:
                log(f"[aws] {fn_name} — environment contains secret-like keys: {secret_keys} (CRITICAL)")
                finding(title=f"Lambda function environment contains secrets: {fn_name}",
                         severity="CRITICAL",
                         description=f"Lambda function {fn_name} has environment variables with secret-like names: "
                                     f"{', '.join(secret_keys)}. These are visible to anyone with lambda:GetFunction.",
                         data={"catalogue_id": "FORGE-AWS-060", "affected": fn_name,
                               "remediation": "Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them at runtime."},
                         output_file=str(out_dir / "lambda_functions.json"))
            else:
                log(f"[aws] {fn_name} — environment variables OK (no secret patterns)")
        else:
            log(f"[aws] {fn_name} — no environment variables")

        # FORGE-AWS-061: overly permissive resource policy (Principal=*)
        log(f"[aws] {fn_name} — checking resource policy...")
        policy_resp = _aws_run(["lambda", "get-policy", "--function-name", fn_name],
                                f"lambda_{fn_name}_policy.json")
        if policy_resp:
            try:
                pol_doc = json.loads(policy_resp.get("Policy", "{}"))
                for stmt in pol_doc.get("Statement") or []:
                    principal = stmt.get("Principal", "")
                    condition = stmt.get("Condition") or {}
                    if principal == "*" and not condition:
                        log(f"[aws] {fn_name} — resource policy allows Principal=* without Condition (CRITICAL)")
                        finding(title=f"Lambda function publicly invokable: {fn_name}",
                                 severity="CRITICAL",
                                 description=f"Lambda {fn_name} has a resource-based policy granting Principal=* "
                                             "with no Condition — anyone can invoke this function.",
                                 data={"catalogue_id": "FORGE-AWS-061", "affected": fn_name,
                                       "remediation": "Restrict the Principal to specific accounts/services or add a Condition."},
                                 output_file=str(out_dir / f"lambda_{fn_name}_policy.json"))
                        break
            except (json.JSONDecodeError, TypeError):
                pass
        else:
            log(f"[aws] {fn_name} — no resource policy (OK)")

        # FORGE-AWS-062: function URL with no auth
        log(f"[aws] {fn_name} — checking function URL configs...")
        url_resp = _aws_run(["lambda", "list-function-url-configs", "--function-name", fn_name],
                             f"lambda_{fn_name}_urls.json") or {}
        url_configs = url_resp.get("FunctionUrlConfigs") or []
        for uc in url_configs:
            if uc.get("AuthType") == "NONE":
                furl = uc.get("FunctionUrl", "")
                log(f"[aws] {fn_name} — function URL {furl} has AuthType=NONE (HIGH)")
                finding(title=f"Lambda function URL without authentication: {fn_name}",
                         severity="HIGH",
                         description=f"Lambda {fn_name} has a function URL ({furl}) with AuthType=NONE — "
                                     "anyone on the internet can invoke it without credentials.",
                         data={"catalogue_id": "FORGE-AWS-062", "affected": fn_name,
                               "remediation": "Set AuthType to AWS_IAM or add a CloudFront+WAF layer."},
                         output_file=str(out_dir / f"lambda_{fn_name}_urls.json"))

        # FORGE-AWS-063: deprecated runtime
        runtime = fn.get("Runtime", "")
        if runtime in _DEPRECATED_RUNTIMES:
            log(f"[aws] {fn_name} — uses deprecated runtime {runtime} (MEDIUM)")
            finding(title=f"Lambda function uses deprecated runtime: {fn_name} ({runtime})",
                     severity="MEDIUM",
                     description=f"Lambda {fn_name} runs on {runtime} which is deprecated and no longer receives security patches.",
                     data={"catalogue_id": "FORGE-AWS-063", "affected": fn_name,
                           "remediation": f"Upgrade the function runtime from {runtime} to the latest supported version."},
                     output_file=str(out_dir / "lambda_functions.json"))
        elif runtime:
            log(f"[aws] {fn_name} — runtime {runtime} OK")
    log(f"[aws] Lambda audit complete — checked {len(lambda_fns)} function(s)")

    # ── VPC deep ──────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting VPC deep audit...")
    status("aws", "VPC audit", "running")

    # FORGE-AWS-070: VPCs without flow logs
    vpcs_resp = _aws_run(["ec2", "describe-vpcs"], "ec2_vpcs.json") or {}
    vpcs = vpcs_resp.get("Vpcs") or []
    log(f"[aws] Found {len(vpcs)} VPC(s)")
    flow_logs_resp = _aws_run(["ec2", "describe-flow-logs"], "ec2_flow_logs.json") or {}
    flow_logs = flow_logs_resp.get("FlowLogs") or []
    vpc_ids_with_flow = {fl.get("ResourceId") for fl in flow_logs if fl.get("ResourceType") == "VPC"}
    _check_pause()
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId", "")
        if vpc_id not in vpc_ids_with_flow:
            log(f"[aws] VPC {vpc_id} — no flow logs configured (MEDIUM)")
            finding(title=f"VPC without flow logs: {vpc_id}",
                     severity="MEDIUM",
                     description=f"VPC {vpc_id} does not have VPC Flow Logs enabled — network traffic is not auditable.",
                     data={"catalogue_id": "FORGE-AWS-070", "affected": vpc_id,
                           "remediation": "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs"},
                     output_file=str(out_dir / "ec2_vpcs.json"))
        else:
            log(f"[aws] VPC {vpc_id} — flow logs OK")

    # FORGE-AWS-071: default security group with rules (reuse existing SG data)
    _check_pause()
    for sg in sgs:
        if sg.get("GroupName") == "default":
            sg_id = sg.get("GroupId", "")
            perms = sg.get("IpPermissions") or []
            if perms:
                log(f"[aws] Default SG {sg_id} — has inbound rules (HIGH)")
                finding(title=f"Default security group has inbound rules: {sg_id}",
                         severity="HIGH",
                         description=f"Default security group {sg_id} has non-empty inbound rules. "
                                     "Resources assigned to the default SG inherit these rules.",
                         data={"catalogue_id": "FORGE-AWS-071", "affected": sg_id,
                               "remediation": "Remove all inbound/outbound rules from the default security group."},
                         output_file=str(out_dir / "ec2_security_groups.json"))
            else:
                log(f"[aws] Default SG {sg_id} — no inbound rules (OK)")
    log("[aws] VPC deep audit complete")

    # ── IAM deep ──────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting IAM deep audit...")
    status("aws", "IAM deep audit", "running")

    # FORGE-AWS-024: password policy
    log("[aws] Checking account password policy...")
    pp_resp = _aws_run(["iam", "get-account-password-policy"], "iam_password_policy.json", use_region=False)
    if pp_resp:
        pp = pp_resp.get("PasswordPolicy") or {}
        min_len = pp.get("MinimumPasswordLength", 0)
        req_sym = pp.get("RequireSymbols", False)
        req_num = pp.get("RequireNumbers", False)
        req_upper = pp.get("RequireUppercaseCharacters", False)
        req_lower = pp.get("RequireLowercaseCharacters", False)
        issues = []
        if min_len < 14:
            issues.append(f"MinimumPasswordLength={min_len} (should be >=14)")
        if not req_sym:
            issues.append("RequireSymbols=false")
        if not req_num:
            issues.append("RequireNumbers=false")
        if not req_upper:
            issues.append("RequireUppercaseCharacters=false")
        if not req_lower:
            issues.append("RequireLowercaseCharacters=false")
        if issues:
            log(f"[aws] Password policy weaknesses: {'; '.join(issues)} (MEDIUM)")
            finding(title="IAM password policy does not meet complexity requirements",
                     severity="MEDIUM",
                     description=f"Account password policy has weaknesses: {'; '.join(issues)}.",
                     data={"catalogue_id": "FORGE-AWS-024", "affected": "account",
                           "remediation": "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters"},
                     output_file=str(out_dir / "iam_password_policy.json"))
        else:
            log("[aws] Password policy meets complexity requirements")
    else:
        log("[aws] No account password policy configured (MEDIUM)")
        finding(title="IAM account password policy not configured",
                 severity="MEDIUM",
                 description="No custom IAM password policy is configured — AWS defaults apply (6 char minimum, no complexity).",
                 data={"catalogue_id": "FORGE-AWS-024", "affected": "account",
                       "remediation": "aws iam update-account-password-policy with strong complexity settings."},
                 output_file=str(out_dir / "iam_password_policy.json"))

    # FORGE-AWS-025: expired server certificates
    log("[aws] Checking IAM server certificates...")
    certs_resp = _aws_run(["iam", "list-server-certificates"], "iam_server_certs.json", use_region=False) or {}
    server_certs = certs_resp.get("ServerCertificateMetadataList") or []
    log(f"[aws] Found {len(server_certs)} IAM server certificate(s)")
    now_utc = datetime.now(timezone.utc)
    for cert in server_certs:
        cert_name = cert.get("ServerCertificateName", "")
        expiration = cert.get("Expiration", "")
        if expiration:
            try:
                exp_dt = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
                if exp_dt < now_utc:
                    days_expired = (now_utc - exp_dt).days
                    log(f"[aws] Certificate {cert_name} — expired {days_expired} day(s) ago (CRITICAL)")
                    finding(title=f"IAM server certificate expired: {cert_name}",
                             severity="CRITICAL",
                             description=f"IAM server certificate {cert_name} expired {days_expired} day(s) ago.",
                             data={"catalogue_id": "FORGE-AWS-025", "affected": cert_name,
                                   "remediation": "Replace or delete the expired certificate."},
                             output_file=str(out_dir / "iam_server_certs.json"))
                else:
                    log(f"[aws] Certificate {cert_name} — valid (expires {expiration})")
            except Exception:
                pass
    log("[aws] IAM deep audit complete")

    # ── EFS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting EFS audit...")
    status("aws", "EFS audit", "running")
    efs_resp = _aws_run(["efs", "describe-file-systems"], "efs_filesystems.json") or {}
    efs_list = efs_resp.get("FileSystems") or []
    log(f"[aws] Found {len(efs_list)} EFS file system(s)")
    _check_pause()
    for fs in efs_list:
        fs_id = fs.get("FileSystemId", "")
        fs_name = fs.get("Name", fs_id)
        log(f"[aws] Checking EFS {fs_name} ({fs_id})...")
        # FORGE-AWS-080: public file system policy
        pol_resp = _aws_run(["efs", "describe-file-system-policy", "--file-system-id", fs_id],
                             f"efs_{fs_id}_policy.json")
        if pol_resp:
            try:
                pol_doc = json.loads(pol_resp.get("Policy", "{}"))
                for stmt in pol_doc.get("Statement") or []:
                    principal = stmt.get("Principal", "")
                    p_aws = principal.get("AWS", "") if isinstance(principal, dict) else principal
                    if p_aws == "*":
                        log(f"[aws] EFS {fs_name} — policy allows Principal=* (CRITICAL)")
                        finding(title=f"EFS file system publicly accessible: {fs_name}",
                                 severity="CRITICAL",
                                 description=f"EFS file system {fs_id} has a resource policy granting Principal=* — "
                                             "any AWS principal can mount and access the filesystem.",
                                 data={"catalogue_id": "FORGE-AWS-080", "affected": fs_name,
                                       "remediation": "Restrict the EFS resource policy to specific accounts, VPCs, or IAM roles."},
                                 output_file=str(out_dir / f"efs_{fs_id}_policy.json"))
                        break
            except (json.JSONDecodeError, TypeError):
                pass
        else:
            log(f"[aws] EFS {fs_name} — no resource policy (default access)")
    log(f"[aws] EFS audit complete — checked {len(efs_list)} file system(s)")

    # ── SNS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting SNS audit...")
    status("aws", "SNS audit", "running")
    sns_resp = _aws_run(["sns", "list-topics"], "sns_topics.json") or {}
    sns_topics = sns_resp.get("Topics") or []
    log(f"[aws] Found {len(sns_topics)} SNS topic(s)")
    _check_pause()
    for topic in sns_topics:
        _check_pause()
        topic_arn = topic.get("TopicArn", "")
        topic_name = topic_arn.rsplit(":", 1)[-1] if ":" in topic_arn else topic_arn
        log(f"[aws] Checking SNS topic {topic_name}...")
        attrs = _aws_run(["sns", "get-topic-attributes", "--topic-arn", topic_arn],
                          f"sns_{topic_name}_attrs.json") or {}
        topic_attrs = attrs.get("Attributes") or {}

        # FORGE-AWS-090: no KMS encryption
        if not topic_attrs.get("KmsMasterKeyId"):
            log(f"[aws] SNS {topic_name} — no KMS encryption (HIGH)")
            finding(title=f"SNS topic not encrypted with KMS: {topic_name}",
                     severity="HIGH",
                     description=f"SNS topic {topic_name} does not use a KMS key for server-side encryption.",
                     data={"catalogue_id": "FORGE-AWS-090", "affected": topic_name,
                           "remediation": "aws sns set-topic-attributes --topic-arn <arn> --attribute-name KmsMasterKeyId --attribute-value <key-id>"},
                     output_file=str(out_dir / f"sns_{topic_name}_attrs.json"))
        else:
            log(f"[aws] SNS {topic_name} — KMS encryption OK")

        # FORGE-AWS-091: public access policy
        policy_str = topic_attrs.get("Policy", "")
        if policy_str:
            try:
                pol_doc = json.loads(policy_str)
                for stmt in pol_doc.get("Statement") or []:
                    principal = stmt.get("Principal", "")
                    p_val = principal.get("AWS", "") if isinstance(principal, dict) else principal
                    condition = stmt.get("Condition") or {}
                    if p_val == "*" and not condition:
                        log(f"[aws] SNS {topic_name} — policy allows Principal=* (HIGH)")
                        finding(title=f"SNS topic publicly accessible: {topic_name}",
                                 severity="HIGH",
                                 description=f"SNS topic {topic_name} has a policy granting Principal=* without Condition.",
                                 data={"catalogue_id": "FORGE-AWS-091", "affected": topic_name,
                                       "remediation": "Restrict the topic policy to specific accounts or services."},
                                 output_file=str(out_dir / f"sns_{topic_name}_attrs.json"))
                        break
            except (json.JSONDecodeError, TypeError):
                pass
    log(f"[aws] SNS audit complete — checked {len(sns_topics)} topic(s)")

    # ── SQS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting SQS audit...")
    status("aws", "SQS audit", "running")
    sqs_resp = _aws_run(["sqs", "list-queues"], "sqs_queues.json") or {}
    sqs_urls = sqs_resp.get("QueueUrls") or []
    log(f"[aws] Found {len(sqs_urls)} SQS queue(s)")
    _check_pause()
    for q_url in sqs_urls:
        _check_pause()
        q_name = q_url.rsplit("/", 1)[-1] if "/" in q_url else q_url
        log(f"[aws] Checking SQS queue {q_name}...")
        q_attrs_resp = _aws_run(["sqs", "get-queue-attributes", "--queue-url", q_url,
                                  "--attribute-names", "All"],
                                 f"sqs_{q_name}_attrs.json") or {}
        q_attrs = q_attrs_resp.get("Attributes") or {}

        # FORGE-AWS-092: no encryption
        has_kms = q_attrs.get("KmsMasterKeyId")
        has_sse = q_attrs.get("SqsManagedSseEnabled", "false").lower() == "true"
        if not has_kms and not has_sse:
            log(f"[aws] SQS {q_name} — no encryption configured (MEDIUM)")
            finding(title=f"SQS queue not encrypted: {q_name}",
                     severity="MEDIUM",
                     description=f"SQS queue {q_name} has neither KMS nor SQS-managed SSE encryption enabled.",
                     data={"catalogue_id": "FORGE-AWS-092", "affected": q_name,
                           "remediation": "aws sqs set-queue-attributes --queue-url <url> --attributes SqsManagedSseEnabled=true"},
                     output_file=str(out_dir / f"sqs_{q_name}_attrs.json"))
        else:
            log(f"[aws] SQS {q_name} — encryption OK")

        # FORGE-AWS-093: public access policy
        policy_str = q_attrs.get("Policy", "")
        if policy_str:
            try:
                pol_doc = json.loads(policy_str)
                for stmt in pol_doc.get("Statement") or []:
                    principal = stmt.get("Principal", "")
                    p_val = principal.get("AWS", "") if isinstance(principal, dict) else principal
                    condition = stmt.get("Condition") or {}
                    if p_val == "*" and not condition:
                        log(f"[aws] SQS {q_name} — policy allows Principal=* without Condition (CRITICAL)")
                        finding(title=f"SQS queue publicly accessible: {q_name}",
                                 severity="CRITICAL",
                                 description=f"SQS queue {q_name} has a policy granting Principal=* without Condition.",
                                 data={"catalogue_id": "FORGE-AWS-093", "affected": q_name,
                                       "remediation": "Restrict the queue policy Principal to specific accounts or services."},
                                 output_file=str(out_dir / f"sqs_{q_name}_attrs.json"))
                        break
            except (json.JSONDecodeError, TypeError):
                pass
    log(f"[aws] SQS audit complete — checked {len(sqs_urls)} queue(s)")

    # ── GuardDuty ─────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting GuardDuty audit...")
    status("aws", "GuardDuty audit", "running")
    gd_resp = _aws_run(["guardduty", "list-detectors"], "guardduty_detectors.json") or {}
    gd_detectors = gd_resp.get("DetectorIds") or []
    if not gd_detectors:
        log("[aws] GuardDuty not enabled — no detectors found (MEDIUM)")
        finding(title="GuardDuty not enabled",
                 severity="MEDIUM",
                 description="Amazon GuardDuty is not enabled in this region — threat detection for the account is absent.",
                 data={"catalogue_id": "FORGE-AWS-100",
                       "remediation": "aws guardduty create-detector --enable"},
                 output_file=str(out_dir / "guardduty_detectors.json"))
    else:
        log(f"[aws] GuardDuty enabled — {len(gd_detectors)} detector(s)")
    log("[aws] GuardDuty audit complete")

    # ── Security Hub ──────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting Security Hub audit...")
    status("aws", "Security Hub audit", "running")
    sh_resp = _aws_run(["securityhub", "describe-hub"], "securityhub_hub.json")
    if not sh_resp or not sh_resp.get("HubArn"):
        log("[aws] Security Hub not enabled (MEDIUM)")
        finding(title="Security Hub not enabled",
                 severity="MEDIUM",
                 description="AWS Security Hub is not enabled in this region — centralized security posture management is absent.",
                 data={"catalogue_id": "FORGE-AWS-101",
                       "remediation": "aws securityhub enable-security-hub"},
                 output_file=str(out_dir / "securityhub_hub.json"))
    else:
        log(f"[aws] Security Hub enabled — {sh_resp.get('HubArn', '')}")
    log("[aws] Security Hub audit complete")

    # ── ACM ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting ACM certificate audit...")
    status("aws", "ACM audit", "running")
    acm_resp = _aws_run(["acm", "list-certificates"], "acm_certificates.json") or {}
    acm_certs = acm_resp.get("CertificateSummaryList") or []
    log(f"[aws] Found {len(acm_certs)} ACM certificate(s)")
    _check_pause()
    for cert in acm_certs:
        cert_arn = cert.get("CertificateArn", "")
        domain = cert.get("DomainName", cert_arn)
        not_after = cert.get("NotAfter", "")
        if not_after:
            try:
                exp_str = not_after if isinstance(not_after, str) else str(not_after)
                exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                days_left = (exp_dt - now_utc).days
                if days_left < 0:
                    log(f"[aws] ACM {domain} — expired {abs(days_left)} day(s) ago (HIGH)")
                    finding(title=f"ACM certificate expired: {domain}",
                             severity="HIGH",
                             description=f"ACM certificate for {domain} expired {abs(days_left)} day(s) ago.",
                             data={"catalogue_id": "FORGE-AWS-110", "affected": domain,
                                   "remediation": "Renew or replace the expired ACM certificate."},
                             output_file=str(out_dir / "acm_certificates.json"))
                elif days_left <= 30:
                    log(f"[aws] ACM {domain} — expires in {days_left} day(s) (HIGH)")
                    finding(title=f"ACM certificate expiring soon: {domain}",
                             severity="HIGH",
                             description=f"ACM certificate for {domain} expires in {days_left} day(s).",
                             data={"catalogue_id": "FORGE-AWS-110", "affected": domain,
                                   "remediation": "Renew the certificate or verify auto-renewal is working."},
                             output_file=str(out_dir / "acm_certificates.json"))
                else:
                    log(f"[aws] ACM {domain} — valid ({days_left} days remaining)")
            except Exception:
                log(f"[aws] ACM {domain} — could not parse expiration date")
    log(f"[aws] ACM audit complete — checked {len(acm_certs)} certificate(s)")

    # ── CloudWatch Logs ───────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting CloudWatch Logs audit...")
    status("aws", "CloudWatch Logs audit", "running")
    cw_resp = _aws_run(["logs", "describe-log-groups", "--limit", "200"],
                        "cloudwatch_log_groups.json") or {}
    log_groups = cw_resp.get("logGroups") or []
    log(f"[aws] Found {len(log_groups)} CloudWatch log group(s) (max 200)")
    _check_pause()
    cw_no_kms = 0
    cw_no_retention = 0
    for lg in log_groups:
        lg_name = lg.get("logGroupName", "")
        # FORGE-AWS-120: no KMS encryption
        if not lg.get("kmsKeyId"):
            cw_no_kms += 1
        # FORGE-AWS-121: no retention period
        if not lg.get("retentionInDays"):
            cw_no_retention += 1
    if cw_no_kms > 0:
        log(f"[aws] {cw_no_kms} CloudWatch log group(s) not encrypted with KMS (MEDIUM)")
        finding(title=f"CloudWatch log groups without KMS encryption ({cw_no_kms} group(s))",
                 severity="MEDIUM",
                 description=f"{cw_no_kms} of {len(log_groups)} CloudWatch log groups are not encrypted with a customer-managed KMS key.",
                 data={"catalogue_id": "FORGE-AWS-120",
                       "affected": f"{cw_no_kms} log group(s)",
                       "remediation": "aws logs associate-kms-key --log-group-name <name> --kms-key-id <key-arn>"},
                 output_file=str(out_dir / "cloudwatch_log_groups.json"))
    else:
        log("[aws] All CloudWatch log groups have KMS encryption")
    if cw_no_retention > 0:
        log(f"[aws] {cw_no_retention} CloudWatch log group(s) have no retention period (MEDIUM)")
        finding(title=f"CloudWatch log groups without retention policy ({cw_no_retention} group(s))",
                 severity="MEDIUM",
                 description=f"{cw_no_retention} of {len(log_groups)} CloudWatch log groups have no retention policy set (logs retained indefinitely).",
                 data={"catalogue_id": "FORGE-AWS-121",
                       "affected": f"{cw_no_retention} log group(s)",
                       "remediation": "aws logs put-retention-policy --log-group-name <name> --retention-in-days <days>"},
                 output_file=str(out_dir / "cloudwatch_log_groups.json"))
    else:
        log("[aws] All CloudWatch log groups have retention policies")
    log("[aws] CloudWatch Logs audit complete")

    # ── OpenSearch ────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting OpenSearch audit...")
    status("aws", "OpenSearch audit", "running")
    os_resp = _aws_run(["opensearch", "list-domain-names"], "opensearch_domains.json") or {}
    os_domains = os_resp.get("DomainNames") or []
    log(f"[aws] Found {len(os_domains)} OpenSearch domain(s)")
    _check_pause()
    for dom in os_domains:
        _check_pause()
        dom_name = dom.get("DomainName", "")
        log(f"[aws] Checking OpenSearch domain {dom_name}...")
        dom_detail = _aws_run(["opensearch", "describe-domain", "--domain-name", dom_name],
                               f"opensearch_{dom_name}_detail.json") or {}
        ds = dom_detail.get("DomainStatus") or {}

        # FORGE-AWS-140: public domain (no VPC)
        vpc_opts = ds.get("VPCOptions") or {}
        if not vpc_opts.get("VPCId"):
            log(f"[aws] OpenSearch {dom_name} — not in a VPC (public endpoint) (CRITICAL)")
            finding(title=f"OpenSearch domain publicly accessible: {dom_name}",
                     severity="CRITICAL",
                     description=f"OpenSearch domain {dom_name} is not deployed inside a VPC — "
                                 "the endpoint is accessible from the public internet.",
                     data={"catalogue_id": "FORGE-AWS-140", "affected": dom_name,
                           "remediation": "Migrate the domain into a VPC (requires recreation for existing domains)."},
                     output_file=str(out_dir / f"opensearch_{dom_name}_detail.json"))
        else:
            log(f"[aws] OpenSearch {dom_name} — in VPC {vpc_opts.get('VPCId')}")

        # FORGE-AWS-141: encryption at rest not enabled
        enc_conf = ds.get("EncryptionAtRestOptions") or {}
        if not enc_conf.get("Enabled"):
            log(f"[aws] OpenSearch {dom_name} — encryption at rest disabled (HIGH)")
            finding(title=f"OpenSearch domain encryption at rest disabled: {dom_name}",
                     severity="HIGH",
                     description=f"OpenSearch domain {dom_name} does not have encryption at rest enabled.",
                     data={"catalogue_id": "FORGE-AWS-141", "affected": dom_name,
                           "remediation": "Enable encryption at rest in the domain configuration."},
                     output_file=str(out_dir / f"opensearch_{dom_name}_detail.json"))
        else:
            log(f"[aws] OpenSearch {dom_name} — encryption at rest enabled")
    log(f"[aws] OpenSearch audit complete — checked {len(os_domains)} domain(s)")

    # ── Secrets Manager ───────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting Secrets Manager audit...")
    status("aws", "Secrets Manager audit", "running")
    sm_resp = _aws_run(["secretsmanager", "list-secrets"], "secretsmanager_secrets.json") or {}
    sm_secrets = sm_resp.get("SecretList") or []
    log(f"[aws] Found {len(sm_secrets)} secret(s)")
    _check_pause()
    for secret in sm_secrets:
        s_name = secret.get("Name", "")
        # FORGE-AWS-150: rotation not enabled
        if not secret.get("RotationEnabled"):
            log(f"[aws] Secret {s_name} — rotation not enabled (MEDIUM)")
            finding(title=f"Secrets Manager secret rotation disabled: {s_name}",
                     severity="MEDIUM",
                     description=f"Secret {s_name} does not have automatic rotation enabled.",
                     data={"catalogue_id": "FORGE-AWS-150", "affected": s_name,
                           "remediation": "Configure automatic rotation with a Lambda rotation function."},
                     output_file=str(out_dir / "secretsmanager_secrets.json"))
        else:
            log(f"[aws] Secret {s_name} — rotation enabled")
    log(f"[aws] Secrets Manager audit complete — checked {len(sm_secrets)} secret(s)")

    # ── CloudFront ────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting CloudFront audit...")
    status("aws", "CloudFront audit", "running")
    cf_resp = _aws_run(["cloudfront", "list-distributions"], "cloudfront_distributions.json", use_region=False) or {}
    dist_list = (cf_resp.get("DistributionList") or {}).get("Items") or []
    log(f"[aws] Found {len(dist_list)} CloudFront distribution(s)")
    _check_pause()
    for dist in dist_list:
        _check_pause()
        dist_id = dist.get("Id", "")
        aliases = (dist.get("Aliases") or {}).get("Items") or []
        dist_label = aliases[0] if aliases else dist_id
        log(f"[aws] Checking CloudFront distribution {dist_label} ({dist_id})...")

        # FORGE-AWS-160: access logging not enabled
        logging_cfg = dist.get("Logging") or {}
        if not logging_cfg.get("Enabled"):
            log(f"[aws] CloudFront {dist_label} — access logging disabled (MEDIUM)")
            finding(title=f"CloudFront distribution access logging disabled: {dist_label}",
                     severity="MEDIUM",
                     description=f"CloudFront distribution {dist_id} does not have access logging enabled.",
                     data={"catalogue_id": "FORGE-AWS-160", "affected": dist_label,
                           "remediation": "Enable access logging to an S3 bucket."},
                     output_file=str(out_dir / "cloudfront_distributions.json"))
        else:
            log(f"[aws] CloudFront {dist_label} — access logging enabled")

        # FORGE-AWS-161: no WAF WebACL attached
        if not dist.get("WebACLId"):
            log(f"[aws] CloudFront {dist_label} — no WAF WebACL attached (MEDIUM)")
            finding(title=f"CloudFront distribution without WAF: {dist_label}",
                     severity="MEDIUM",
                     description=f"CloudFront distribution {dist_id} does not have an AWS WAF WebACL attached.",
                     data={"catalogue_id": "FORGE-AWS-161", "affected": dist_label,
                           "remediation": "Associate an AWS WAF WebACL with the distribution."},
                     output_file=str(out_dir / "cloudfront_distributions.json"))
        else:
            log(f"[aws] CloudFront {dist_label} — WAF WebACL attached")

        # FORGE-AWS-162: viewer protocol policy allows HTTP
        default_cb = dist.get("DefaultCacheBehavior") or {}
        vpp = default_cb.get("ViewerProtocolPolicy", "")
        if vpp == "allow-all":
            log(f"[aws] CloudFront {dist_label} — allows HTTP viewer connections (MEDIUM)")
            finding(title=f"CloudFront distribution allows HTTP: {dist_label}",
                     severity="MEDIUM",
                     description=f"CloudFront distribution {dist_id} default cache behavior allows HTTP (ViewerProtocolPolicy=allow-all).",
                     data={"catalogue_id": "FORGE-AWS-162", "affected": dist_label,
                           "remediation": "Set ViewerProtocolPolicy to redirect-to-https or https-only."},
                     output_file=str(out_dir / "cloudfront_distributions.json"))
        else:
            log(f"[aws] CloudFront {dist_label} — viewer protocol OK ({vpp})")
    log(f"[aws] CloudFront audit complete — checked {len(dist_list)} distribution(s)")

    # ── DynamoDB ──────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting DynamoDB audit...")
    status("aws", "DynamoDB audit", "running")
    ddb_resp = _aws_run(["dynamodb", "list-tables"], "dynamodb_tables.json") or {}
    ddb_tables = ddb_resp.get("TableNames") or []
    log(f"[aws] Found {len(ddb_tables)} DynamoDB table(s)")
    _check_pause()
    for tbl_name in ddb_tables:
        _check_pause()
        log(f"[aws] Checking DynamoDB table {tbl_name}...")
        tbl_resp = _aws_run(["dynamodb", "describe-table", "--table-name", tbl_name],
                             f"dynamodb_{tbl_name}_detail.json") or {}
        tbl = tbl_resp.get("Table") or {}
        # FORGE-AWS-170: encryption not configured / DEFAULT only
        sse = tbl.get("SSEDescription") or {}
        sse_status = sse.get("Status", "")
        if sse_status not in ("ENABLED", "ENABLING"):
            log(f"[aws] DynamoDB {tbl_name} — SSE not enabled / using default encryption (MEDIUM)")
            finding(title=f"DynamoDB table not using customer-managed encryption: {tbl_name}",
                     severity="MEDIUM",
                     description=f"DynamoDB table {tbl_name} is either using default AWS-owned encryption or has no "
                                 "explicit SSE configuration. Customer-managed KMS keys provide better audit control.",
                     data={"catalogue_id": "FORGE-AWS-170", "affected": tbl_name,
                           "remediation": "aws dynamodb update-table --table-name <table> --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<key-arn>"},
                     output_file=str(out_dir / f"dynamodb_{tbl_name}_detail.json"))
        else:
            log(f"[aws] DynamoDB {tbl_name} — customer-managed SSE enabled")
    log(f"[aws] DynamoDB audit complete — checked {len(ddb_tables)} table(s)")

    # ── ECS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting ECS task definition audit...")
    status("aws", "ECS audit", "running")
    ecs_resp = _aws_run(["ecs", "list-task-definitions", "--max-items", "50"],
                         "ecs_task_definitions.json") or {}
    ecs_arns = ecs_resp.get("taskDefinitionArns") or []
    log(f"[aws] Found {len(ecs_arns)} ECS task definition(s) (max 50)")
    _check_pause()
    for td_arn in ecs_arns:
        _check_pause()
        td_name = td_arn.rsplit("/", 1)[-1] if "/" in td_arn else td_arn
        log(f"[aws] Checking ECS task definition {td_name}...")
        td_resp = _aws_run(["ecs", "describe-task-definition", "--task-definition", td_arn],
                            f"ecs_{td_name}_detail.json") or {}
        td = td_resp.get("taskDefinition") or {}
        containers = td.get("containerDefinitions") or []
        for cdef in containers:
            c_name = cdef.get("name", "")
            env_list = cdef.get("environment") or []
            secret_keys = [e.get("name", "") for e in env_list
                           if _SECRET_PATTERNS.search(e.get("name", ""))]
            if secret_keys:
                log(f"[aws] ECS {td_name}/{c_name} — environment contains secret-like keys: {secret_keys} (CRITICAL)")
                finding(title=f"ECS task definition contains secrets in environment: {td_name}/{c_name}",
                         severity="CRITICAL",
                         description=f"ECS task definition {td_name}, container {c_name} has environment variables "
                                     f"with secret-like names: {', '.join(secret_keys)}.",
                         data={"catalogue_id": "FORGE-AWS-130", "affected": f"{td_name}/{c_name}",
                               "remediation": "Use ECS secrets (valueFrom) with Secrets Manager or SSM Parameter Store instead of plaintext environment variables."},
                         output_file=str(out_dir / f"ecs_{td_name}_detail.json"))
    log(f"[aws] ECS audit complete — checked {len(ecs_arns)} task definition(s)")

    log(f"[aws] AWS audit complete — profile={profile or 'default'}, region={region or 'default'}")
    status("aws", "AWS Account Audit", "complete")


# ── Output helpers (§13b) ──────────────────────────────────────────────────────

def _risk_counts(findings: list) -> dict:
    rc = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        r = str(f.get("risk", "")).upper()
        if r in rc:
            rc[r] += 1
    return rc


def _write_findings_csv(path: Path, findings: list) -> None:
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=_CSV_FIELDS, extrasaction="ignore")
            w.writeheader()
            for fd in findings:
                w.writerow({k: fd.get(k, "") for k in _CSV_FIELDS})
    except Exception as exc:
        err(f"findings.csv write failed: {exc}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    global _pause

    parser = argparse.ArgumentParser(
        prog="forge",
        description="Forge — AWS / Azure / GCP cloud control-plane security auditor"
    )
    parser.add_argument("--azure-subscription", help="Azure subscription ID to audit")
    parser.add_argument("--gcp-project", help="GCP project ID to audit")
    parser.add_argument("--aws-profile", default="", help="AWS CLI profile name (default: default profile)")
    parser.add_argument("--aws-region", default="", help="AWS region (leave blank for default region)")
    parser.add_argument("--aws-access-key-id", default="",
                        help="AWS access key ID (overrides --aws-profile; prefer env FORGE_AWS_ACCESS_KEY_ID)")
    parser.add_argument("--aws-secret-key", default="",
                        help="AWS secret access key (prefer env FORGE_AWS_SECRET_KEY)")
    parser.add_argument("--aws-console-url", default="",
                        help="IAM sign-in URL (e.g. https://123456789012.signin.aws.amazon.com/console)")
    parser.add_argument("--aws-console-user", default="",
                        help="IAM username for console login")
    parser.add_argument("--aws-console-pass", default="",
                        help="IAM password for console login (prefer env FORGE_AWS_CONSOLE_PASS)")
    parser.add_argument("--client-short", default="default", help="Short client identifier")
    parser.add_argument("--client-name", default="", help="Full client name (defaults to --client-short)")
    parser.add_argument("--engagement-name", default="forge run", help="Engagement name for meta.json")
    parser.add_argument("--project", help="Override project output directory")
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return 0

    # Resolve AWS credentials from env vars (preferred for secrets) or CLI args
    aws_access_key = os.environ.get("FORGE_AWS_ACCESS_KEY_ID", "") or args.aws_access_key_id
    aws_secret_key = os.environ.get("FORGE_AWS_SECRET_KEY", "") or args.aws_secret_key
    aws_console_url = os.environ.get("FORGE_AWS_CONSOLE_URL", "") or args.aws_console_url
    aws_console_user = os.environ.get("FORGE_AWS_CONSOLE_USER", "") or args.aws_console_user
    aws_console_pass = os.environ.get("FORGE_AWS_CONSOLE_PASS", "") or args.aws_console_pass

    has_aws_keys = aws_access_key and aws_secret_key
    has_aws_console = aws_console_url and aws_console_user and aws_console_pass
    has_aws = args.aws_profile or args.aws_region or has_aws_keys or has_aws_console
    if not (args.azure_subscription or args.gcp_project or has_aws):
        parser.error("provide at least one of --azure-subscription / --gcp-project / --aws-profile / --aws-region / --aws-access-key-id")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.project:
        project_dir = Path(args.project)
    elif _us is not None:
        project_dir = _us.universal_run_dir(args.client_short, "forge",
                                              year=datetime.now().strftime("%Y"),
                                              ts=ts)
    else:
        project_dir = Path.cwd() / f"forge_{args.client_short}_{ts}"
    project_dir.mkdir(parents=True, exist_ok=True)

    global _RUN_DIR, _RUNLOG
    _RUN_DIR = project_dir
    if _el is not None:
        try:
            _RUNLOG = _el.EventLogger(project_dir / "scan.log",
                                       errors_path=project_dir / "errors.log")
        except Exception:
            _RUNLOG = None

    if _PP is not None:
        _pause = _PP(project_dir, "forge")
        _pause.start_watcher(
            checkpoint_callback=_save_checkpoint,
            grace_period=30,
        )

    target_desc = args.azure_subscription or args.gcp_project or args.aws_profile or "aws-default"
    clouds = []
    if args.azure_subscription:
        clouds.append(f"Azure (subscription={args.azure_subscription})")
    if args.gcp_project:
        clouds.append(f"GCP (project={args.gcp_project})")
    if has_aws or (not args.azure_subscription and not args.gcp_project):
        auth_method = "profile"
        if has_aws_keys:
            auth_method = "access-keys"
        elif has_aws_console:
            auth_method = "console-login"
        clouds.append(f"AWS (auth={auth_method}, region={args.aws_region or 'default'})")
    log(f"Forge v{VERSION} starting — project: {project_dir}")
    log(f"Cloud targets: {', '.join(clouds)}")
    if _us is not None:
        meta = _us.make_meta(tool="forge", version=VERSION,
                              client_short=args.client_short,
                              client_name=(args.client_name or args.client_short),
                              engagement_name=args.engagement_name,
                              target=target_desc)
        _us.write_meta(project_dir, meta)
        try:
            import pr0t31n_dep_snapshot as _ds
            _ds.write_snapshot(
                project_dir, "forge", VERSION,
                binaries=["aws", "az", "gcloud"],
                pip_packages=[],
            )
        except Exception:
            pass

    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    _check_pause()
    if args.azure_subscription:
        audit_azure(args.azure_subscription, project_dir)
    _check_pause()
    if args.gcp_project:
        audit_gcp(args.gcp_project, project_dir)
    _check_pause()
    if has_aws or (not args.azure_subscription and not args.gcp_project):
        aws_profile = args.aws_profile
        # Priority: explicit keys > console login > named profile
        if has_aws_keys:
            log("[aws] Configuring from provided access keys")
            aws_profile = _aws_configure_from_keys(aws_access_key, aws_secret_key, args.aws_region)
        elif has_aws_console:
            log("[aws] Attempting AWS Console login to create temp access key...")
            try:
                aws_profile = _aws_console_login(
                    aws_console_url, aws_console_user, aws_console_pass,
                    region=args.aws_region)
            except RuntimeError as exc:
                err(f"[aws-console] {exc}")
                if not aws_profile:
                    err("[aws] No fallback profile — skipping AWS audit")
                    status("aws", "AWS Account Audit", "skipped")
                    aws_profile = None
        if aws_profile is not None:
            audit_aws(aws_profile, args.aws_region, project_dir)

    # Cleanup temp AWS credentials from ~/.aws/ (copy lives in run dir)
    if _aws_tmp_cleanup:
        try:
            _aws_tmp_cleanup()
        except Exception as exc:
            err(f"[aws] Credential cleanup: {exc}")

    ended_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    log(f"All audits finished — writing output files...")
    rc = _risk_counts(_findings)
    log(f"Findings summary: {rc['CRITICAL']} CRITICAL, {rc['HIGH']} HIGH, "
        f"{rc['MEDIUM']} MEDIUM, {rc['LOW']} LOW, {rc['INFO']} INFO")
    if _us is not None:
        out = [_us.augment_finding(dict(f), tool="forge") for f in _findings]
        _us.atomic_write_json(project_dir / "findings.json", out)
        log(f"Wrote findings.json ({len(out)} finding(s))")
        _write_findings_csv(project_dir / "findings.csv", out)
        log("Wrote findings.csv")
        try:
            summary = _us.make_summary(
                tool="forge", version=VERSION,
                scan_start=started_at, scan_end=ended_at,
                target=target_desc,
                success=True, total_findings=len(out),
                risk_counts=_risk_counts(out))
            _us.write_summary(project_dir, summary)
            log("Wrote summary.json")
        except Exception as exc:
            err(f"summary.json write failed: {exc}")
    else:
        (project_dir / "findings.json").write_text(
            json.dumps(_findings, indent=2), encoding="utf-8")
        log(f"Wrote findings.json ({len(_findings)} finding(s)) — legacy mode")
        _write_findings_csv(project_dir / "findings.csv", _findings)
        log("Wrote findings.csv — legacy mode")

    if _pause is not None:
        _pause.write_stop_reason("completed", "all_phases_done")
    log(f"Forge v{VERSION} complete — {len(_findings)} finding(s) — output: {project_dir}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
