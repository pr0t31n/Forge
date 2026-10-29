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

_ACCESS_DENIED = "__ACCESS_DENIED__"

def _is_access_denied(stderr_text: str) -> bool:
    """Return True if stderr indicates an AWS AccessDenied / permission error."""
    if not stderr_text:
        return False
    lower = stderr_text.lower()
    return any(p.lower() in lower for p in _IAM_DENY_PATTERNS)


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

def _build_aws_intelligence(out_dir: Path, region: str, findings: list,
                             cred_report: dict, denied_services: set,
                             iam_users_raw: list) -> None:
    """Build intelligence files for Crucible's cloud intelligence tabs."""
    def _safe_load(name):
        p = out_dir / name
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                pass
        return None

    def _findings_for(service_prefix: str) -> list:
        return [f for f in findings if (f.get("catalogue_id") or "").startswith(service_prefix)]

    def _max_risk(flist: list) -> str:
        order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        best = ""
        for f in flist:
            r = str(f.get("risk", "")).upper()
            if order.get(r, 0) > order.get(best, 0):
                best = r
        return best or "OK"

    def _risk_breakdown(flist: list) -> dict:
        rc = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in flist:
            k = str(f.get("risk", "")).lower()
            if k in rc:
                rc[k] += 1
        return rc

    # ── cloud_inventory.json ─────────────────────────────────────────────────
    inventory = []

    # S3 buckets
    s3_data = _safe_load("s3_buckets.json")
    if s3_data and isinstance(s3_data, dict):
        for b in s3_data.get("Buckets") or []:
            name = b.get("Name", "")
            bf = [f for f in findings if name in str(f.get("affected", ""))
                  and "S3" in str(f.get("title", ""))]
            inventory.append({
                "service": "S3", "resource_type": "Bucket",
                "resource_id": name, "name": name,
                "region": "global", "status": "active",
                "findings": len(bf), "risk": _max_risk(bf),
            })

    # EC2 instances
    ec2_data = _safe_load("ec2_instances.json")
    if ec2_data and isinstance(ec2_data, dict):
        for res in ec2_data.get("Reservations") or []:
            for inst in res.get("Instances") or []:
                iid = inst.get("InstanceId", "")
                name_tag = ""
                for tag in inst.get("Tags") or []:
                    if tag.get("Key") == "Name":
                        name_tag = tag.get("Value", "")
                label = name_tag or iid
                state = (inst.get("State") or {}).get("Name", "unknown")
                bf = [f for f in findings if iid in str(f.get("title", ""))
                      or iid in str(f.get("affected", ""))]
                inventory.append({
                    "service": "EC2", "resource_type": "Instance",
                    "resource_id": iid, "name": label,
                    "region": region, "status": state,
                    "findings": len(bf), "risk": _max_risk(bf),
                })

    # EBS volumes
    ebs_data = _safe_load("ec2_volumes.json")
    if ebs_data and isinstance(ebs_data, dict):
        for vol in ebs_data.get("Volumes") or []:
            vid = vol.get("VolumeId", "")
            bf = [f for f in findings if vid in str(f.get("affected", ""))]
            inventory.append({
                "service": "EC2", "resource_type": "EBS Volume",
                "resource_id": vid, "name": vid,
                "region": region, "status": vol.get("State", "unknown"),
                "findings": len(bf), "risk": _max_risk(bf),
            })

    # RDS instances
    rds_data = _safe_load("rds_instances.json")
    if rds_data and isinstance(rds_data, dict):
        for db in rds_data.get("DBInstances") or []:
            db_id = db.get("DBInstanceIdentifier", "")
            bf = [f for f in findings if db_id in str(f.get("affected", ""))]
            inventory.append({
                "service": "RDS", "resource_type": f"Instance ({db.get('Engine', '')})",
                "resource_id": db_id, "name": db_id,
                "region": region, "status": db.get("DBInstanceStatus", "unknown"),
                "findings": len(bf), "risk": _max_risk(bf),
            })

    # Lambda functions
    lam_data = _safe_load("lambda_functions.json")
    if lam_data and isinstance(lam_data, dict):
        for fn in lam_data.get("Functions") or []:
            fn_name = fn.get("FunctionName", "")
            bf = [f for f in findings if fn_name in str(f.get("affected", ""))]
            inventory.append({
                "service": "Lambda", "resource_type": f"Function ({fn.get('Runtime', '')})",
                "resource_id": fn_name, "name": fn_name,
                "region": region, "status": "active",
                "findings": len(bf), "risk": _max_risk(bf),
            })

    # KMS keys
    kms_data = _safe_load("kms_keys.json")
    if kms_data and isinstance(kms_data, dict):
        for k in kms_data.get("Keys") or []:
            kid = k.get("KeyId", "")
            bf = [f for f in findings if kid[:8] in str(f.get("affected", ""))]
            inventory.append({
                "service": "KMS", "resource_type": "Key",
                "resource_id": kid[:8] + "...", "name": kid[:8] + "...",
                "region": region, "status": "active",
                "findings": len(bf), "risk": _max_risk(bf),
            })

    # DynamoDB tables
    ddb_data = _safe_load("dynamodb_tables.json")
    if ddb_data and isinstance(ddb_data, dict):
        for tname in ddb_data.get("TableNames") or []:
            bf = [f for f in findings if tname in str(f.get("affected", ""))]
            inventory.append({
                "service": "DynamoDB", "resource_type": "Table",
                "resource_id": tname, "name": tname,
                "region": region, "status": "active",
                "findings": len(bf), "risk": _max_risk(bf),
            })

    try:
        (out_dir.parent / "cloud_inventory.json").write_text(
            json.dumps(inventory, indent=2), encoding="utf-8")
        log(f"[aws] Wrote cloud_inventory.json ({len(inventory)} resource(s))")
    except Exception as exc:
        err(f"[aws] cloud_inventory.json write failed: {exc}")

    # ── iam_matrix.json ──────────────────────────────────────────────────────
    iam_matrix = []
    for user in iam_users_raw:
        uname = user.get("UserName", "")
        cr = cred_report.get(uname, {})
        uf = [f for f in findings if uname in str(f.get("affected", ""))
              and "IAM" in str(f.get("title", ""))]
        # load policies from evidence
        pol_data = _safe_load(f"iam_{uname}_policies.json")
        pols = []
        if pol_data and isinstance(pol_data, dict):
            pols = [p.get("PolicyName", p.get("PolicyArn", "").rsplit("/", 1)[-1])
                    for p in pol_data.get("AttachedPolicies") or []]
        keys_data = _safe_load(f"iam_{uname}_keys.json")
        n_keys = len((keys_data or {}).get("AccessKeyMetadata") or []) if isinstance(keys_data, dict) else 0
        active_keys = sum(1 for k in ((keys_data or {}).get("AccessKeyMetadata") or [])
                         if k.get("Status") == "Active") if isinstance(keys_data, dict) else 0
        iam_matrix.append({
            "user": uname,
            "arn": user.get("Arn", ""),
            "password_enabled": cr.get("password_enabled", "N/A"),
            "mfa_active": cr.get("mfa_active", "N/A"),
            "access_keys": n_keys,
            "active_keys": active_keys,
            "last_login": cr.get("password_last_used", "N/A"),
            "policies": ", ".join(pols) if pols else "none",
            "findings": len(uf),
            "risk": _max_risk(uf) if uf else "OK",
        })
    try:
        (out_dir.parent / "iam_matrix.json").write_text(
            json.dumps(iam_matrix, indent=2), encoding="utf-8")
        log(f"[aws] Wrote iam_matrix.json ({len(iam_matrix)} user(s))")
    except Exception as exc:
        err(f"[aws] iam_matrix.json write failed: {exc}")

    # ── service_dashboard.json ───────────────────────────────────────────────
    svc_map = {
        "S3": ("FORGE-AWS-00", "s3api"),
        "EC2": ("FORGE-AWS-01", "ec2"),
        "IAM": ("FORGE-AWS-02", "iam"),
        "RDS": ("FORGE-AWS-03", "rds"),
        "CloudTrail": ("FORGE-AWS-04", "cloudtrail"),
        "KMS": ("FORGE-AWS-05", "kms"),
        "Lambda": ("FORGE-AWS-06", "lambda"),
        "VPC": ("FORGE-AWS-07", "ec2"),
        "EFS": ("FORGE-AWS-08", "efs"),
        "SNS": ("FORGE-AWS-09", "sns"),
        "SQS": ("FORGE-AWS-09", "sqs"),
        "GuardDuty": ("FORGE-AWS-100", "guardduty"),
        "Security Hub": ("FORGE-AWS-101", "securityhub"),
        "ACM": ("FORGE-AWS-11", "acm"),
        "CloudWatch Logs": ("FORGE-AWS-12", "logs"),
        "ECS": ("FORGE-AWS-13", "ecs"),
        "OpenSearch": ("FORGE-AWS-14", "opensearch"),
        "Secrets Manager": ("FORGE-AWS-15", "secretsmanager"),
        "CloudFront": ("FORGE-AWS-16", "cloudfront"),
        "DynamoDB": ("FORGE-AWS-17", "dynamodb"),
    }
    dashboard = []
    for svc_name, (prefix, cli_svc) in svc_map.items():
        sf = [f for f in findings
              if str(f.get("catalogue_id", "")).startswith(prefix)]
        rb = _risk_breakdown(sf)
        # count resources from inventory
        n_res = sum(1 for r in inventory if r.get("service") == svc_name)
        denied = cli_svc in denied_services
        has_data = bool(sf) or n_res > 0
        access = "Access Denied" if denied and not has_data else "Allowed"
        if sf:
            st = "Issues Found"
        elif denied and not has_data:
            st = "Access Denied"
        elif n_res == 0:
            st = "No Resources"
        else:
            st = "OK"
        dashboard.append({
            "service": svc_name, "resources": n_res,
            "findings": len(sf), "status": st, "access": access,
            **rb,
        })
    try:
        (out_dir.parent / "service_dashboard.json").write_text(
            json.dumps(dashboard, indent=2), encoding="utf-8")
        log(f"[aws] Wrote service_dashboard.json ({len(dashboard)} service(s))")
    except Exception as exc:
        err(f"[aws] service_dashboard.json write failed: {exc}")


def _detect_aws_region(aws: str, profile: str) -> str:
    """Auto-detect AWS region from profile config or STS caller identity."""
    # 1) Try aws configure get region
    cmd = [aws, "configure", "get", "region"]
    if profile:
        cmd += ["--profile", profile]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        val = (cp.stdout or "").strip()
        if val and cp.returncode == 0:
            log(f"[aws] Auto-detected region from profile config: {val}")
            return val
    except Exception:
        pass

    # 2) Try STS get-caller-identity — extract region from ARN partition hint
    #    or fall back to the default region in the response metadata
    cmd = [aws, "sts", "get-caller-identity", "--output", "json"]
    if profile:
        cmd += ["--profile", profile]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if cp.returncode == 0 and cp.stdout:
            data = json.loads(cp.stdout)
            arn = data.get("Arn", "")
            # ARN format: arn:aws:iam::ACCOUNT:...
            # The partition (aws, aws-cn, aws-us-gov) hints at region family
            if ":aws-cn:" in arn:
                log("[aws] Auto-detected region from ARN partition: cn-north-1")
                return "cn-north-1"
            elif ":aws-us-gov:" in arn:
                log("[aws] Auto-detected region from ARN partition: us-gov-west-1")
                return "us-gov-west-1"
    except Exception:
        pass

    # 3) Try EC2 IMDS (works on EC2 instances)
    try:
        import urllib.request
        req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/placement/region",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "5"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            val = resp.read().decode().strip()
            if val:
                log(f"[aws] Auto-detected region from EC2 IMDS: {val}")
                return val
    except Exception:
        pass

    # 4) Fall back to us-east-1 (broadest service coverage)
    log("[aws] Could not auto-detect region — defaulting to us-east-1")
    return "us-east-1"


def audit_aws(profile: str, region: str, output_dir: Path) -> None:
    _check_pause()
    aws = shutil.which("aws")
    if not aws:
        err("aws CLI not installed — skipping AWS audit")
        status("aws", "AWS Account Audit", "skipped")
        return
    log(f"[aws] aws CLI found at {aws}")

    if not region:
        region = _detect_aws_region(aws, profile)

    log(f"[aws] Starting AWS audit — profile={profile or 'default'}, region={region}")
    status("aws", "AWS Account Audit", "running")

    out_dir = output_dir / "aws"
    out_dir.mkdir(parents=True, exist_ok=True)

    _denied_services: set = set()
    _cred_report: dict = {}
    _iam_users_raw: list = []

    def _refresh_intel():
        try:
            _build_aws_intelligence(
                out_dir, region, _findings, _cred_report,
                _denied_services, _iam_users_raw)
        except Exception:
            pass

    def _aws_run(args: list, out_name: str, use_region: bool = True) -> dict | list | None:
        """Run an AWS CLI command.  Returns parsed JSON, or None on failure.
        When the API returns AccessDenied, the service name (args[0]) is added
        to ``_denied_services`` and None is returned — callers treat it the
        same as empty data but the denial is tracked for intelligence/reporting."""
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
            stderr = cp.stderr or ""
            if not raw.strip() and stderr.strip():
                out_file.write_text(stderr, encoding="utf-8")
            else:
                out_file.write_text(raw, encoding="utf-8")
            if _is_access_denied(stderr):
                svc = args[0] if args else "unknown"
                _denied_services.add(svc)
                log(f"[aws] AccessDenied on: aws {' '.join(args[:2])} — "
                    f"insufficient permissions for {svc}")
                return None
            try:
                return json.loads(raw) if raw.strip() else None
            except json.JSONDecodeError:
                return None
        except Exception as exc:
            err(f"aws {' '.join(args[:2])} failed: {exc}")
            return None

    def _normalize_stmts(doc: dict, key: str = "Statement") -> list:
        raw = doc.get(key) or []
        if isinstance(raw, dict):
            return [raw]
        if not isinstance(raw, list):
            return []
        return [s for s in raw if isinstance(s, dict)]

    # ── Resolve account ID (needed for s3control, etc.) ─────────────────────
    _aws_account_id = ""
    _sts_resp = _aws_run(["sts", "get-caller-identity"], "sts_identity.json", use_region=False)
    if _sts_resp:
        _aws_account_id = _sts_resp.get("Account", "")
        log(f"[aws] Account ID: {_aws_account_id}")

    # ── S3 ────────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting S3 bucket audit...")
    status("aws", "S3 bucket audit", "running")
    # --- FORGE-AWS-300 — S3 account-level public access blocks ---
    log("[aws] Checking S3 account-level public access block...")
    acct_pab = None
    if _aws_account_id:
        acct_pab = _aws_run(["s3control", "get-public-access-block",
                              "--account-id", _aws_account_id],
                             "s3_account_public_access.json", use_region=False)
    if acct_pab:
        acct_pab_cfg = acct_pab.get("PublicAccessBlockConfiguration") or {}
        if not all(acct_pab_cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                                    "BlockPublicPolicy", "RestrictPublicBuckets")):
            log("[aws] Account-level S3 public access block incomplete (HIGH)")
            finding(title="S3 account-level Block Public Access not fully enabled",
                     severity="HIGH",
                     description="The AWS account does not have all four S3 Block Public Access settings enabled at the account level. "
                                 "This allows individual buckets to be made public.",
                     data={"catalogue_id": "FORGE-AWS-300", "affected": "AWS Account",
                           "remediation": "aws s3control put-public-access-block --account-id <ACCT> "
                                          "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                                          "BlockPublicPolicy=true,RestrictPublicBuckets=true"},
                     output_file=str(out_dir / "s3_account_public_access.json"))
        else:
            log("[aws] Account-level S3 public access block OK")
    else:
        log("[aws] Account-level S3 public access block not configured (HIGH)")
        finding(title="S3 account-level Block Public Access not configured",
                 severity="HIGH",
                 description="No account-level S3 Block Public Access configuration found — individual buckets may be publicly accessible.",
                 data={"catalogue_id": "FORGE-AWS-300", "affected": "AWS Account",
                       "remediation": "Enable account-level S3 Block Public Access via the S3 console or CLI."},
                 output_file=str(out_dir / "s3_account_public_access.json"))

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

        # --- FORGE-AWS-200 — S3 bucket ACL prohibited ---
        log(f"[aws] {name} — checking ownership controls...")
        own_resp = _aws_run(["s3api", "get-bucket-ownership-controls", "--bucket", name],
                             f"s3_{name}_ownership.json", use_region=False)
        if own_resp:
            rules = (own_resp.get("OwnershipControls") or {}).get("Rules") or []
            if not any(r.get("ObjectOwnership") == "BucketOwnerEnforced" for r in rules):
                log(f"[aws] {name} — bucket ACLs not disabled (MEDIUM)")
                finding(title=f"S3 bucket ACLs not disabled: {name}",
                         severity="MEDIUM",
                         description=f"S3 bucket {name} does not have ObjectOwnership=BucketOwnerEnforced. "
                                     "ACLs can grant access independently of bucket policies.",
                         data={"catalogue_id": "FORGE-AWS-200", "affected": name,
                               "remediation": "Set bucket ownership to BucketOwnerEnforced to disable ACLs."},
                         output_file=str(out_dir / f"s3_{name}_ownership.json"))
            else:
                log(f"[aws] {name} — ACLs disabled (BucketOwnerEnforced)")
        else:
            log(f"[aws] {name} — no ownership controls (ACLs may be active)")
            finding(title=f"S3 bucket ACLs not disabled: {name}",
                     severity="MEDIUM",
                     description=f"S3 bucket {name} has no ownership controls configured — ACLs are active by default.",
                     data={"catalogue_id": "FORGE-AWS-200", "affected": name,
                           "remediation": "Set bucket ownership to BucketOwnerEnforced to disable ACLs."},
                     output_file=str(out_dir / f"s3_{name}_ownership.json"))

        # --- FORGE-AWS-201 + FORGE-AWS-207 — S3 bucket cross-account access + secure transport ---
        log(f"[aws] {name} — checking bucket policy for cross-account access and transport security...")
        bp_resp = _aws_run(["s3api", "get-bucket-policy", "--bucket", name],
                            f"s3_{name}_policy.json", use_region=False)
        _s3_has_ssl_deny = False
        if bp_resp and bp_resp.get("Policy"):
            try:
                pol_doc = json.loads(bp_resp["Policy"])
                for stmt in _normalize_stmts(pol_doc):
                    # Cross-account check
                    principal = stmt.get("Principal", "")
                    p_aws = principal.get("AWS", []) if isinstance(principal, dict) else []
                    if isinstance(p_aws, str):
                        p_aws = [p_aws]
                    for p in p_aws:
                        if "::" in p and "root" not in p.lower():
                            cond = stmt.get("Condition") or {}
                            if not cond and stmt.get("Effect") == "Allow":
                                log(f"[aws] {name} — cross-account access in policy (HIGH)")
                                finding(title=f"S3 bucket cross-account access: {name}",
                                         severity="HIGH",
                                         description=f"S3 bucket {name} policy grants access to external account principal {p} "
                                                     "without restrictive conditions.",
                                         data={"catalogue_id": "FORGE-AWS-201", "affected": name,
                                               "remediation": "Add Condition restrictions or remove cross-account grants."},
                                         output_file=str(out_dir / f"s3_{name}_policy.json"))
                                break
                    # Secure transport check
                    cond = stmt.get("Condition") or {}
                    bool_cond = cond.get("Bool") or {}
                    if (bool_cond.get("aws:SecureTransport") == "false" and
                            stmt.get("Effect") == "Deny"):
                        _s3_has_ssl_deny = True
            except (json.JSONDecodeError, TypeError):
                pass
        if not _s3_has_ssl_deny:
            log(f"[aws] {name} — no SSL-only transport policy (MEDIUM)")
            finding(title=f"S3 bucket missing secure transport policy: {name}",
                     severity="MEDIUM",
                     description=f"S3 bucket {name} does not have a bucket policy denying non-HTTPS requests (aws:SecureTransport=false).",
                     data={"catalogue_id": "FORGE-AWS-207", "affected": name,
                           "remediation": "Add a bucket policy statement: Effect=Deny, Condition: aws:SecureTransport=false, Action: s3:*, Resource: bucket ARN."},
                     output_file=str(out_dir / f"s3_{name}_policy.json"))
        else:
            log(f"[aws] {name} — secure transport policy OK")

        # --- FORGE-AWS-202 — S3 cross-region replication ---
        log(f"[aws] {name} — checking cross-region replication...")
        rep_resp = _aws_run(["s3api", "get-bucket-replication", "--bucket", name],
                             f"s3_{name}_replication.json", use_region=False)
        if not rep_resp or not (rep_resp.get("ReplicationConfiguration") or {}).get("Rules"):
            log(f"[aws] {name} — no cross-region replication (LOW)")
            finding(title=f"S3 bucket cross-region replication not configured: {name}",
                     severity="LOW",
                     description=f"S3 bucket {name} does not have cross-region replication configured for disaster recovery.",
                     data={"catalogue_id": "FORGE-AWS-202", "affected": name,
                           "remediation": "Configure cross-region replication to a bucket in a different region."},
                     output_file=str(out_dir / f"s3_{name}_replication.json"))
        else:
            log(f"[aws] {name} — cross-region replication configured")

        # --- FORGE-AWS-203 — S3 event notifications ---
        log(f"[aws] {name} — checking event notifications...")
        notif_resp = _aws_run(["s3api", "get-bucket-notification-configuration", "--bucket", name],
                               f"s3_{name}_notifications.json", use_region=False) or {}
        has_notif = any(notif_resp.get(k) for k in ("TopicConfigurations", "QueueConfigurations",
                                                      "LambdaFunctionConfigurations", "EventBridgeConfiguration"))
        if not has_notif:
            log(f"[aws] {name} — no event notifications (LOW)")
            finding(title=f"S3 bucket event notifications not configured: {name}",
                     severity="LOW",
                     description=f"S3 bucket {name} has no event notification configuration — changes to objects are not monitored.",
                     data={"catalogue_id": "FORGE-AWS-203", "affected": name,
                           "remediation": "Configure S3 event notifications to SNS, SQS, Lambda, or EventBridge."},
                     output_file=str(out_dir / f"s3_{name}_notifications.json"))
        else:
            log(f"[aws] {name} — event notifications configured")

        # --- FORGE-AWS-204 — S3 KMS encryption (uses existing `enc` variable) ---
        if enc is not None:
            _enc_rules = (enc.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []
            _uses_kms = any(
                (r.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm") == "aws:kms"
                for r in _enc_rules)
            if not _uses_kms:
                log(f"[aws] {name} — encrypted but not with KMS (MEDIUM)")
                finding(title=f"S3 bucket not using KMS encryption: {name}",
                         severity="MEDIUM",
                         description=f"S3 bucket {name} uses SSE-S3 (AES-256) instead of SSE-KMS. "
                                     "KMS provides better key management, auditing, and access control.",
                         data={"catalogue_id": "FORGE-AWS-204", "affected": name,
                               "remediation": "Configure default encryption with SSE-KMS using a customer-managed or AWS-managed KMS key."},
                         output_file=str(out_dir / f"s3_{name}_encryption.json"))
            else:
                log(f"[aws] {name} — KMS encryption OK")

        # --- FORGE-AWS-205 — S3 lifecycle ---
        log(f"[aws] {name} — checking lifecycle configuration...")
        lc_resp = _aws_run(["s3api", "get-bucket-lifecycle-configuration", "--bucket", name],
                            f"s3_{name}_lifecycle.json", use_region=False)
        if not lc_resp or not (lc_resp.get("Rules") or []):
            log(f"[aws] {name} — no lifecycle rules (LOW)")
            finding(title=f"S3 bucket lifecycle not configured: {name}",
                     severity="LOW",
                     description=f"S3 bucket {name} has no lifecycle rules — data is retained indefinitely with no automated transitions or expiration.",
                     data={"catalogue_id": "FORGE-AWS-205", "affected": name,
                           "remediation": "Configure lifecycle rules for data retention, transition to cheaper storage classes, or expiration."},
                     output_file=str(out_dir / f"s3_{name}_lifecycle.json"))
        else:
            log(f"[aws] {name} — lifecycle rules configured")

        # --- FORGE-AWS-206 — S3 Object Lock ---
        log(f"[aws] {name} — checking object lock configuration...")
        ol_resp = _aws_run(["s3api", "get-object-lock-configuration", "--bucket", name],
                            f"s3_{name}_object_lock.json", use_region=False)
        if not ol_resp or (ol_resp.get("ObjectLockConfiguration") or {}).get("ObjectLockEnabled") != "Enabled":
            log(f"[aws] {name} — object lock not enabled (MEDIUM)")
            finding(title=f"S3 bucket object lock not enabled: {name}",
                     severity="MEDIUM",
                     description=f"S3 bucket {name} does not have Object Lock enabled — objects can be deleted or overwritten.",
                     data={"catalogue_id": "FORGE-AWS-206", "affected": name,
                           "remediation": "Enable Object Lock (requires creating a new bucket with lock enabled, then migrating data)."},
                     output_file=str(out_dir / f"s3_{name}_object_lock.json"))
        else:
            log(f"[aws] {name} — object lock enabled")

    log(f"[aws] S3 audit complete — checked {len(buckets)} bucket(s)")
    _refresh_intel()

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

            # --- FORGE-AWS-208 — Detailed monitoring ---
            _mon_state = (inst.get("Monitoring") or {}).get("State", "")
            if _mon_state != "enabled":
                log(f"[aws] {label} — detailed monitoring not enabled (LOW)")
                finding(title=f"EC2 instance detailed monitoring disabled: {label}",
                         severity="LOW",
                         description=f"Instance {iid} does not have detailed monitoring enabled (1-minute CloudWatch metrics).",
                         data={"catalogue_id": "FORGE-AWS-208", "affected": label,
                               "remediation": "aws ec2 monitor-instances --instance-ids <id>"},
                         output_file=str(out_dir / "ec2_instances.json"))
            else:
                log(f"[aws] {label} — detailed monitoring enabled")

            # --- FORGE-AWS-209 — Internet-facing with instance profile ---
            if inst.get("PublicIpAddress") and inst.get("IamInstanceProfile"):
                log(f"[aws] {label} — internet-facing with instance profile (HIGH)")
                finding(title=f"EC2 instance internet-facing with IAM role: {label}",
                         severity="HIGH",
                         description=f"Instance {iid} has a public IP address and an IAM instance profile attached. "
                                     "SSRF vulnerabilities could allow credential theft from the instance metadata service.",
                         data={"catalogue_id": "FORGE-AWS-209", "affected": label,
                               "remediation": "Remove public IP or move behind a load balancer. Enforce IMDSv2."},
                         output_file=str(out_dir / "ec2_instances.json"))

            # --- FORGE-AWS-210 — Instance age ---
            _launch = inst.get("LaunchTime", "")
            if _launch:
                try:
                    _launch_dt = datetime.fromisoformat(_launch.replace("Z", "+00:00"))
                    _inst_age = (datetime.now(timezone.utc) - _launch_dt).days
                    if _inst_age > 365:
                        log(f"[aws] {label} — running for {_inst_age} days (MEDIUM)")
                        finding(title=f"EC2 instance older than 365 days: {label}",
                                 severity="MEDIUM",
                                 description=f"Instance {iid} has been running for {_inst_age} days. "
                                             "Long-running instances may have outdated AMIs and unpatched software.",
                                 data={"catalogue_id": "FORGE-AWS-210", "affected": label,
                                       "remediation": "Review the instance — consider replacing with a fresh AMI or rebuilding from infrastructure-as-code."},
                                 output_file=str(out_dir / "ec2_instances.json"))
                except Exception:
                    pass

            # --- FORGE-AWS-211 — Multiple ENIs ---
            _enis = inst.get("NetworkInterfaces") or []
            if len(_enis) > 1:
                log(f"[aws] {label} — has {len(_enis)} ENIs attached (LOW)")
                finding(title=f"EC2 instance has multiple ENIs: {label}",
                         severity="LOW",
                         description=f"Instance {iid} has {len(_enis)} network interfaces. Multiple ENIs can complicate "
                                     "security group management and network routing.",
                         data={"catalogue_id": "FORGE-AWS-211", "affected": label,
                               "remediation": "Review whether multiple ENIs are required."},
                         output_file=str(out_dir / "ec2_instances.json"))


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
            _all_cidrs = [(r.get("CidrIp", ""), "IPv4") for r in perm.get("IpRanges") or []]
            _all_cidrs += [(r.get("CidrIpv6", ""), "IPv6") for r in perm.get("Ipv6Ranges") or []]
            for cidr, _af in _all_cidrs:
                if cidr in ("0.0.0.0/0", "::/0"):
                    exposed = {p for p in sensitive_ports if from_port <= p <= to_port}
                    if exposed:
                        log(f"[aws] {sg_name} ({sg_id}) — exposes ports {sorted(exposed)} to {cidr} (HIGH)")
                        finding(title=f"Security group {sg_name} ({sg_id}) exposes sensitive ports to {cidr}",
                                 severity="HIGH",
                                 description=f"Inbound rule allows {cidr} access to port(s) {', '.join(str(p) for p in sorted(exposed))}.",
                                 data={"catalogue_id": "FORGE-AWS-012",
                                       "affected": f"{sg_name} ({sg_id})",
                                       "remediation": "Restrict source CIDR to known IP ranges."},
                                 output_file=str(out_dir / "ec2_security_groups.json"))
                    elif from_port == 0 and to_port == 65535:
                        log(f"[aws] {sg_name} ({sg_id}) — allows ALL ports from {cidr} (CRITICAL)")
                        finding(title=f"Security group {sg_name} ({sg_id}) allows all ports from {cidr}",
                                 severity="CRITICAL",
                                 description=f"Inbound rule allows unrestricted access (all ports) from {cidr}.",
                                 data={"catalogue_id": "FORGE-AWS-013",
                                       "affected": f"{sg_name} ({sg_id})"},
                                 output_file=str(out_dir / "ec2_security_groups.json"))
                elif _af == "IPv4" and cidr != "0.0.0.0/0" and not cidr.startswith("10.") \
                     and not cidr.startswith("172.16.") and not cidr.startswith("192.168.") \
                     and not cidr.startswith("127."):
                    import ipaddress as _ipa
                    try:
                        _net = _ipa.ip_network(cidr, strict=False)
                        if _net.is_global:
                            log(f"[aws] {sg_name} ({sg_id}) — open to specific public IP {cidr} (MEDIUM)")
                            finding(title=f"Security group open to specific public IP: {sg_name} ({sg_id})",
                                     severity="MEDIUM",
                                     description=f"Security group {sg_name} ({sg_id}) allows ingress from specific public IP {cidr} "
                                                 f"on port(s) {from_port}-{to_port}.",
                                     data={"catalogue_id": "FORGE-AWS-504", "affected": f"{sg_name} ({sg_id})",
                                           "remediation": "Verify this public IP is expected; prefer VPN or private connectivity."},
                                     output_file=str(out_dir / "ec2_security_groups.json"))
                    except (ValueError, TypeError):
                        pass

    # --- FORGE-AWS-212 — Unused security groups ---
    _check_pause()
    log("[aws] Checking for unused security groups...")
    _used_sgs = set()
    eni_resp = _aws_run(["ec2", "describe-network-interfaces"], "ec2_network_interfaces.json") or {}
    for eni in eni_resp.get("NetworkInterfaces") or []:
        for g in eni.get("Groups") or []:
            _used_sgs.add(g.get("GroupId", ""))
    _unused_count = 0
    for sg in sgs:
        sg_id = sg.get("GroupId", "")
        sg_name = sg.get("GroupName", "")
        if sg_name == "default":
            continue
        if sg_id not in _used_sgs:
            _unused_count += 1
    if _unused_count > 0:
        log(f"[aws] {_unused_count} unused non-default security group(s) found (LOW)")
        finding(title=f"Unused security groups detected ({_unused_count} group(s))",
                 severity="LOW",
                 description=f"{_unused_count} non-default security groups are not attached to any network interface. "
                             "Unused security groups increase management overhead.",
                 data={"catalogue_id": "FORGE-AWS-212",
                       "affected": f"{_unused_count} security group(s)",
                       "remediation": "Review and delete unused security groups."},
                 output_file=str(out_dir / "ec2_network_interfaces.json"))
    else:
        log("[aws] All non-default security groups are in use")

    # --- FORGE-AWS-213 — EBS snapshot public access block ---
    _check_pause()
    log("[aws] Checking EBS snapshot public access block...")
    snap_block = _aws_run(["ec2", "get-snapshot-block-public-access-state"],
                           "ec2_snapshot_block_public_access.json") or {}
    if snap_block.get("State") != "block-all-sharing":
        log(f"[aws] EBS snapshot public access not fully blocked (HIGH)")
        finding(title="EBS snapshot public access not blocked",
                 severity="HIGH",
                 description=f"EBS snapshot sharing is not fully blocked (state: {snap_block.get('State', 'unknown')}). "
                             "Snapshots may be shared publicly, exposing volume data.",
                 data={"catalogue_id": "FORGE-AWS-213",
                       "remediation": "aws ec2 enable-snapshot-block-public-access --state block-all-sharing"},
                 output_file=str(out_dir / "ec2_snapshot_block_public_access.json"))
    else:
        log("[aws] EBS snapshot public access blocked")

    # --- FORGE-AWS-214 — EBS volume snapshots exist ---
    _check_pause()
    log("[aws] Checking EBS volume snapshot coverage...")
    all_snaps = _aws_run(["ec2", "describe-snapshots", "--owner-ids", "self", "--max-results", "1000"],
                          "ec2_snapshots.json") or {}
    _snapped_vols = {s.get("VolumeId") for s in all_snaps.get("Snapshots") or [] if s.get("VolumeId")}
    _no_snap_count = 0
    for vol in volumes:
        vid = vol.get("VolumeId", "")
        if vid and vid not in _snapped_vols:
            _no_snap_count += 1
    if _no_snap_count > 0:
        log(f"[aws] {_no_snap_count} EBS volume(s) have no snapshots (HIGH)")
        finding(title=f"EBS volumes without snapshots ({_no_snap_count} volume(s))",
                 severity="HIGH",
                 description=f"{_no_snap_count} of {len(volumes)} EBS volumes have no snapshots. "
                             "Data on these volumes is not backed up.",
                 data={"catalogue_id": "FORGE-AWS-214",
                       "affected": f"{_no_snap_count} volume(s)",
                       "remediation": "Create snapshots or configure AWS Backup plans for these volumes."},
                 output_file=str(out_dir / "ec2_snapshots.json"))
    else:
        log("[aws] All EBS volumes have snapshots")

    # --- FORGE-AWS-400 — EBS volumes protected by backup plan ---
    _check_pause()
    log("[aws] Checking EBS volumes in AWS Backup plans...")
    _backup_plans = _aws_run(["backup", "list-backup-plans"], "backup_plans.json") or {}
    _backup_protected_arns = set()
    for plan in (_backup_plans.get("BackupPlansList") or []):
        plan_id = plan.get("BackupPlanId", "")
        sel_resp = _aws_run(["backup", "list-backup-selections", "--backup-plan-id", plan_id],
                             f"backup_selections_{plan_id}.json") or {}
        for sel in (sel_resp.get("BackupSelectionsList") or []):
            sel_id = sel.get("SelectionId", "")
            sel_detail = _aws_run(["backup", "get-backup-selection",
                                    "--backup-plan-id", plan_id, "--selection-id", sel_id],
                                   f"backup_selection_{plan_id}_{sel_id}.json") or {}
            bs = sel_detail.get("BackupSelection") or {}
            for res in bs.get("Resources") or []:
                _backup_protected_arns.add(res)
    _unprotected_vols = 0
    for vol in volumes:
        vid = vol.get("VolumeId", "")
        vol_arn = f"arn:aws:ec2:{region}:{_aws_account_id}:volume/{vid}"
        if vol_arn not in _backup_protected_arns and "*" not in _backup_protected_arns:
            _unprotected_vols += 1
    if _unprotected_vols > 0:
        log(f"[aws] {_unprotected_vols} EBS volume(s) not in any backup plan (MEDIUM)")
        finding(title=f"EBS volumes not protected by backup plan ({_unprotected_vols} volume(s))",
                 severity="MEDIUM",
                 description=f"{_unprotected_vols} of {len(volumes)} EBS volumes are not explicitly included in any AWS Backup plan.",
                 data={"catalogue_id": "FORGE-AWS-400",
                       "affected": f"{_unprotected_vols} volume(s)",
                       "remediation": "Add EBS volumes to an AWS Backup plan for automated backup protection."},
                 output_file=str(out_dir / "backup_plans.json"))
    else:
        log("[aws] All EBS volumes are in backup plans (or wildcard-protected)")

    # --- FORGE-AWS-215 — Account-level IMDSv2 default ---
    _check_pause()
    log("[aws] Checking account-level IMDSv2 default...")
    imds_defaults = _aws_run(["ec2", "get-instance-metadata-defaults"],
                              "ec2_imds_defaults.json") or {}
    _acct_defaults = imds_defaults.get("AccountLevel") or {}
    if _acct_defaults.get("HttpTokens") != "required":
        log("[aws] Account-level IMDSv2 not enforced as default (HIGH)")
        finding(title="EC2 account-level IMDSv2 not enforced by default",
                 severity="HIGH",
                 description="The account does not require IMDSv2 by default for new EC2 instances. "
                             "New instances will default to IMDSv1 which is vulnerable to SSRF attacks.",
                 data={"catalogue_id": "FORGE-AWS-215",
                       "remediation": "aws ec2 modify-instance-metadata-defaults --http-tokens required"},
                 output_file=str(out_dir / "ec2_imds_defaults.json"))
    else:
        log("[aws] Account-level IMDSv2 default enforced")

    # --- FORGE-AWS-216/217/218 — NACL checks ---
    _check_pause()
    log("[aws] Checking network ACLs...")
    nacl_resp = _aws_run(["ec2", "describe-network-acls"], "ec2_network_acls.json") or {}
    nacls = nacl_resp.get("NetworkAcls") or []
    log(f"[aws] Found {len(nacls)} network ACL(s)")
    for nacl in nacls:
        nacl_id = nacl.get("NetworkAclId", "")
        for entry in nacl.get("Entries") or []:
            if entry.get("Egress"):
                continue
            if entry.get("RuleAction") != "allow":
                continue
            cidr = entry.get("CidrBlock", "")
            cidr6 = entry.get("Ipv6CidrBlock", "")
            if cidr != "0.0.0.0/0" and cidr6 != "::/0":
                continue
            pr = entry.get("PortRange") or {}
            from_p = pr.get("From", 0)
            to_p = pr.get("To", 65535)
            if from_p == 0 and to_p == 65535:
                log(f"[aws] NACL {nacl_id} — allows all ports from 0.0.0.0/0 (HIGH)")
                finding(title=f"Network ACL allows all inbound from internet: {nacl_id}",
                         severity="HIGH",
                         description=f"NACL {nacl_id} has an allow rule for all ports from {cidr or cidr6}.",
                         data={"catalogue_id": "FORGE-AWS-216", "affected": nacl_id,
                               "remediation": "Restrict NACL rules to specific ports and source CIDRs."},
                         output_file=str(out_dir / "ec2_network_acls.json"))
            else:
                if from_p <= 22 <= to_p:
                    log(f"[aws] NACL {nacl_id} — allows SSH (port 22) from internet (MEDIUM)")
                    finding(title=f"Network ACL allows SSH from internet: {nacl_id}",
                             severity="MEDIUM",
                             description=f"NACL {nacl_id} allows inbound SSH (port 22) from {cidr or cidr6}.",
                             data={"catalogue_id": "FORGE-AWS-217", "affected": nacl_id,
                                   "remediation": "Restrict SSH access to specific source CIDRs."},
                             output_file=str(out_dir / "ec2_network_acls.json"))
                if from_p <= 3389 <= to_p:
                    log(f"[aws] NACL {nacl_id} — allows RDP (port 3389) from internet (MEDIUM)")
                    finding(title=f"Network ACL allows RDP from internet: {nacl_id}",
                             severity="MEDIUM",
                             description=f"NACL {nacl_id} allows inbound RDP (port 3389) from {cidr or cidr6}.",
                             data={"catalogue_id": "FORGE-AWS-218", "affected": nacl_id,
                                   "remediation": "Restrict RDP access to specific source CIDRs."},
                             output_file=str(out_dir / "ec2_network_acls.json"))
    log("[aws] NACL audit complete")

    # --- FORGE-AWS-219 — Subnets auto-assign public IP ---
    _check_pause()
    log("[aws] Checking subnet public IP auto-assignment...")
    subnets_resp = _aws_run(["ec2", "describe-subnets"], "ec2_subnets.json") or {}
    subnets = subnets_resp.get("Subnets") or []
    for subnet in subnets:
        subnet_id = subnet.get("SubnetId", "")
        if subnet.get("MapPublicIpOnLaunch"):
            log(f"[aws] Subnet {subnet_id} — auto-assigns public IP (HIGH)")
            finding(title=f"VPC subnet auto-assigns public IP: {subnet_id}",
                     severity="HIGH",
                     description=f"Subnet {subnet_id} automatically assigns public IP addresses to launched instances. "
                                 "Instances may unintentionally be exposed to the internet.",
                     data={"catalogue_id": "FORGE-AWS-219", "affected": subnet_id,
                           "remediation": "aws ec2 modify-subnet-attribute --subnet-id <id> --no-map-public-ip-on-launch"},
                     output_file=str(out_dir / "ec2_subnets.json"))

    # --- FORGE-AWS-220 — VPC EC2 endpoint ---
    _check_pause()
    log("[aws] Checking VPC endpoints...")
    _vpcs_resp_ep = _aws_run(["ec2", "describe-vpcs"], "ec2_vpcs.json") or {}
    vpcs = _vpcs_resp_ep.get("Vpcs") or []
    endpoints_resp = _aws_run(["ec2", "describe-vpc-endpoints"], "ec2_vpc_endpoints.json") or {}
    _endpoints = endpoints_resp.get("VpcEndpoints") or []
    _vpc_ep_map = {}
    for ep in _endpoints:
        _vpc_ep_map.setdefault(ep.get("VpcId", ""), []).append(ep.get("ServiceName", ""))
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId", "")
        ep_services = _vpc_ep_map.get(vpc_id, [])
        if not any("ec2" in svc for svc in ep_services):
            log(f"[aws] VPC {vpc_id} — no EC2 VPC endpoint (MEDIUM)")
            finding(title=f"VPC missing EC2 endpoint: {vpc_id}",
                     severity="MEDIUM",
                     description=f"VPC {vpc_id} does not have a VPC endpoint for EC2. "
                                 "EC2 API calls traverse the public internet instead of staying within the AWS network.",
                     data={"catalogue_id": "FORGE-AWS-220", "affected": vpc_id,
                           "remediation": "Create a VPC endpoint for com.amazonaws.<region>.ec2"},
                     output_file=str(out_dir / "ec2_vpc_endpoints.json"))

    # --- FORGE-AWS-221 — VPC peering route tables ---
    _check_pause()
    log("[aws] Checking VPC peering route tables...")
    rt_resp = _aws_run(["ec2", "describe-route-tables"], "ec2_route_tables.json") or {}
    rts = rt_resp.get("RouteTables") or []
    for rt in rts:
        rt_id = rt.get("RouteTableId", "")
        for route in rt.get("Routes") or []:
            if route.get("VpcPeeringConnectionId"):
                dest = route.get("DestinationCidrBlock", "")
                if dest == "0.0.0.0/0":
                    log(f"[aws] Route table {rt_id} — peering route with 0.0.0.0/0 (MEDIUM)")
                    finding(title=f"VPC peering route with unrestricted CIDR: {rt_id}",
                             severity="MEDIUM",
                             description=f"Route table {rt_id} has a route to peering connection "
                                         f"{route['VpcPeeringConnectionId']} with destination 0.0.0.0/0. "
                                         "This routes all traffic through the peering connection.",
                             data={"catalogue_id": "FORGE-AWS-221", "affected": rt_id,
                                   "remediation": "Replace the 0.0.0.0/0 route with specific CIDR ranges for the peer VPC."},
                             output_file=str(out_dir / "ec2_route_tables.json"))

    # --- FORGE-AWS-222 — VPC endpoint trust boundaries ---
    for ep in _endpoints:
        ep_id = ep.get("VpcEndpointId", "")
        ep_policy = ep.get("PolicyDocument", "")
        if ep_policy:
            try:
                pol_doc = json.loads(ep_policy) if isinstance(ep_policy, str) else ep_policy
                for stmt in _normalize_stmts(pol_doc):
                    principal = stmt.get("Principal", "")
                    if principal == "*" and not (stmt.get("Condition") or {}):
                        log(f"[aws] VPC endpoint {ep_id} — allows Principal=* without condition (HIGH)")
                        finding(title=f"VPC endpoint allows unrestricted access: {ep_id}",
                                 severity="HIGH",
                                 description=f"VPC endpoint {ep_id} has a policy granting Principal=* without conditions. "
                                             "Any AWS account could use this endpoint.",
                                 data={"catalogue_id": "FORGE-AWS-222", "affected": ep_id,
                                       "remediation": "Restrict the VPC endpoint policy to specific accounts, users, or roles."},
                                 output_file=str(out_dir / "ec2_vpc_endpoints.json"))
                        break
            except (json.JSONDecodeError, TypeError):
                pass

    log(f"[aws] EC2 audit complete — {total_instances} instance(s), {len(volumes)} volume(s), {len(sgs)} SG(s)")
    _refresh_intel()

    # ── IAM ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting IAM audit...")
    status("aws", "IAM audit", "running")
    users_resp = _aws_run(["iam", "list-users"], "iam_users.json", use_region=False) or {}
    iam_users = users_resp.get("Users") or []
    _iam_users_raw.extend(iam_users)
    log(f"[aws] Found {len(iam_users)} IAM user(s)")

    # Generate + parse credential report FIRST — used by per-user MFA check
    _check_pause()
    log("[aws] Generating credential report...")
    _aws_run(["iam", "generate-credential-report"], "iam_cred_gen.json", use_region=False)
    time.sleep(3)
    log("[aws] Retrieving credential report...")
    cred_data = _aws_run(["iam", "get-credential-report"], "iam_cred_report.json", use_region=False) or {}
    if cred_data.get("Content"):
        log("[aws] Parsing credential report...")
        try:
            csv_text = base64.b64decode(cred_data["Content"]).decode("utf-8")
            lines = csv_text.strip().split("\n")
            if lines:
                headers = [h.strip() for h in lines[0].split(",")]
                for line in lines[1:]:
                    cols = line.split(",")
                    if len(cols) >= len(headers):
                        row = dict(zip(headers, cols))
                        _cred_report[row.get("user", "")] = row
        except Exception:
            pass
    else:
        log("[aws] Credential report not available")

    # Root account checks from credential report
    root_row = _cred_report.get("<root_account>", {})
    if root_row:
        if root_row.get("mfa_active", "").lower() != "true":
            log("[aws] Root account does NOT have MFA enabled (CRITICAL)")
            finding(title="IAM: Root account without MFA",
                     severity="CRITICAL",
                     description="The AWS root account does not have MFA enabled. The root account "
                                 "has unrestricted access to all AWS services and resources — "
                                 "without MFA, a compromised password grants full account takeover.",
                     data={"catalogue_id": "FORGE-AWS-026", "affected": "root",
                           "remediation": "Enable MFA on the root account: AWS Console → My Security Credentials → MFA → Activate MFA."},
                     output_file=str(out_dir / "iam_cred_report.json"))
        else:
            log("[aws] Root account — MFA enabled")

        if root_row.get("access_key_1_active", "").lower() == "true":
            log("[aws] Root account has active access keys (CRITICAL)")
            finding(title="IAM: Root account has active access keys",
                     severity="CRITICAL",
                     description="The AWS root account has access keys configured. Root keys should never exist.",
                     data={"catalogue_id": "FORGE-AWS-023", "affected": "root",
                           "remediation": "Delete root access keys and use IAM users/roles instead."},
                     output_file=str(out_dir / "iam_cred_report.json"))
        else:
            log("[aws] Root account — no active access keys")
    elif _cred_report:
        log("[aws] Root account row not found in credential report")

    # Overly-permissive managed policies to flag
    _OVERPERM_POLICIES = {
        "AdministratorAccess", "IAMFullAccess", "PowerUserAccess",
        "AmazonS3FullAccess", "AmazonEC2FullAccess", "AmazonRDSFullAccess",
        "AmazonDynamoDBFullAccess", "AmazonVPCFullAccess",
        "AWSLambda_FullAccess", "AmazonSQSFullAccess", "AmazonSNSFullAccess",
    }

    _check_pause()
    for user in iam_users:
        _check_pause()
        uname = user.get("UserName", "")
        log(f"[aws] Checking IAM user {uname}...")

        # MFA check — consult credential report for password_enabled
        log(f"[aws] {uname} — checking MFA devices...")
        mfa_resp = _aws_run(["iam", "list-mfa-devices", "--user-name", uname],
                              f"iam_{uname}_mfa.json", use_region=False) or {}
        mfa_devices = mfa_resp.get("MFADevices") or []
        if not mfa_devices:
            cr_row = _cred_report.get(uname, {})
            has_password = cr_row.get("password_enabled", "").lower() == "true"
            has_active_key = cr_row.get("access_key_1_active", "").lower() == "true"
            if has_password:
                log(f"[aws] {uname} — console user without MFA (HIGH)")
                finding(title=f"IAM user without MFA: {uname}",
                         severity="HIGH",
                         description=f"IAM user {uname} has console login enabled but no MFA device configured.",
                         data={"catalogue_id": "FORGE-AWS-020", "affected": uname,
                               "remediation": "Enable virtual or hardware MFA for this user."},
                         output_file=str(out_dir / f"iam_{uname}_mfa.json"))
            elif has_active_key:
                log(f"[aws] {uname} — programmatic-only user without MFA (INFO)")
                finding(title=f"Programmatic IAM user without MFA: {uname}",
                         severity="INFO",
                         description=f"IAM user {uname} has no console password and only programmatic access keys. "
                                     "MFA is not applicable for API-only access but the user should be reviewed.",
                         data={"catalogue_id": "FORGE-AWS-020", "affected": uname,
                               "remediation": "Verify this user is intended for programmatic-only access."},
                         output_file=str(out_dir / f"iam_{uname}_mfa.json"))
            else:
                log(f"[aws] {uname} — no password, no active keys, no MFA (orphaned user)")
                finding(title=f"Orphaned IAM user: {uname}",
                         severity="MEDIUM",
                         description=f"IAM user {uname} has no console password, no active access keys, and no MFA. "
                                     "This appears to be an unused/orphaned account.",
                         data={"catalogue_id": "FORGE-AWS-027", "affected": uname,
                               "remediation": "Delete the unused IAM user or activate credentials if still needed."},
                         output_file=str(out_dir / f"iam_{uname}_mfa.json"))
        else:
            log(f"[aws] {uname} — MFA enabled ({len(mfa_devices)} device(s))")

        # Attached policy checks (AdministratorAccess + other overly-permissive)
        log(f"[aws] {uname} — checking attached policies...")
        policies_resp = _aws_run(["iam", "list-attached-user-policies", "--user-name", uname],
                                   f"iam_{uname}_policies.json", use_region=False) or {}
        attached = policies_resp.get("AttachedPolicies") or []
        log(f"[aws] {uname} — {len(attached)} attached polic(ies)")
        for pol in attached:
            pol_name = pol.get("PolicyArn", "").rsplit("/", 1)[-1]
            if pol_name == "AdministratorAccess":
                log(f"[aws] {uname} — has AdministratorAccess directly attached (CRITICAL)")
                finding(title=f"IAM user has AdministratorAccess: {uname}",
                         severity="CRITICAL",
                         description=f"User {uname} has the AdministratorAccess managed policy directly attached.",
                         data={"catalogue_id": "FORGE-AWS-021", "affected": uname,
                               "remediation": "Remove direct AdministratorAccess; use role assumption with least-privilege."},
                         output_file=str(out_dir / f"iam_{uname}_policies.json"))
            elif pol_name in _OVERPERM_POLICIES:
                log(f"[aws] {uname} — has overly-permissive policy {pol_name} directly attached (HIGH)")
                finding(title=f"IAM user has overly-permissive policy: {uname} ({pol_name})",
                         severity="HIGH",
                         description=f"User {uname} has the {pol_name} managed policy directly attached. "
                                     "Full-access policies violate least-privilege and increase blast radius.",
                         data={"catalogue_id": "FORGE-AWS-028", "affected": uname,
                               "remediation": f"Replace {pol_name} with a scoped policy granting only the permissions this user needs."},
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

            # Check key last-used (still inside the key loop where `key` is the key dict)
            _key_id = key.get("AccessKeyId", "")
            if _key_id and key.get("Status") == "Active":
                _klu_resp = _aws_run(["iam", "get-access-key-last-used", "--access-key-id", _key_id],
                                      f"iam_{uname}_{_key_id}_last_used.json", use_region=False) or {}
                _klu = _klu_resp.get("AccessKeyLastUsed") or {}
                _last_used = _klu.get("LastUsedDate", "")
                if _last_used:
                    try:
                        _lu_dt = datetime.fromisoformat(_last_used.replace("Z", "+00:00"))
                        _unused_days = (datetime.now(timezone.utc) - _lu_dt).days
                        if _unused_days > 45:
                            log(f"[aws] {uname} — access key {_key_id} unused for {_unused_days} days (MEDIUM)")
                            finding(title=f"IAM access key unused for {_unused_days} days: {uname}/{_key_id}",
                                     severity="MEDIUM",
                                     description=f"Access key {_key_id} for user {uname} has not been used for {_unused_days} days.",
                                     data={"catalogue_id": "FORGE-AWS-231", "affected": uname,
                                           "remediation": "Deactivate or delete unused access keys."},
                                     output_file=str(out_dir / f"iam_{uname}_{_key_id}_last_used.json"))
                    except Exception:
                        pass
                elif not _klu.get("ServiceName"):
                    log(f"[aws] {uname} — access key {_key_id} has never been used (MEDIUM)")
                    finding(title=f"IAM access key never used: {uname}/{_key_id}",
                             severity="MEDIUM",
                             description=f"Access key {_key_id} for user {uname} has never been used since creation.",
                             data={"catalogue_id": "FORGE-AWS-231", "affected": uname,
                                   "remediation": "Delete access keys that have never been used."},
                             output_file=str(out_dir / f"iam_{uname}_{_key_id}_last_used.json"))


        # FORGE-AWS-230: Inline policies on user
        log(f"[aws] {uname} — checking inline policies...")
        inline_resp = _aws_run(["iam", "list-user-policies", "--user-name", uname],
                                 f"iam_{uname}_inline_policies.json", use_region=False) or {}
        inline_policies = inline_resp.get("PolicyNames") or []
        if inline_policies or attached:
            _direct_count = len(inline_policies) + len(attached)
            log(f"[aws] {uname} — has {_direct_count} direct policy attachment(s) (MEDIUM)")
            finding(title=f"IAM user has direct policy attachments: {uname}",
                     severity="MEDIUM",
                     description=f"IAM user {uname} has {len(attached)} attached and {len(inline_policies)} inline "
                                 "policies directly assigned. Best practice is to assign policies through groups or roles.",
                     data={"catalogue_id": "FORGE-AWS-230", "affected": uname,
                           "remediation": "Move user policies to IAM groups and add the user to the group instead."},
                     output_file=str(out_dir / f"iam_{uname}_inline_policies.json"))

        # FORGE-AWS-233: User with long-lived credentials accessing non-IAM/STS services
        cr_row = _cred_report.get(uname, {})
        _svc1 = cr_row.get("access_key_1_last_used_service", "")
        _svc2 = cr_row.get("access_key_2_last_used_service", "")
        _non_iam_sts = {s for s in (_svc1, _svc2) if s and s.lower() not in ("iam", "sts", "n/a", "")}
        if _non_iam_sts and cr_row.get("access_key_1_active", "").lower() == "true":
            log(f"[aws] {uname} — uses long-lived credentials for {_non_iam_sts} (HIGH)")
            finding(title=f"IAM user uses long-lived credentials for non-IAM services: {uname}",
                     severity="HIGH",
                     description=f"IAM user {uname} uses long-lived access keys to access services: "
                                 f"{', '.join(sorted(_non_iam_sts))}. Use temporary credentials via IAM roles instead.",
                     data={"catalogue_id": "FORGE-AWS-233", "affected": uname,
                           "remediation": "Replace long-lived access keys with IAM role assumption (STS temporary credentials)."},
                     output_file=str(out_dir / f"iam_{uname}_keys.json"))

    log(f"[aws] IAM user audit complete — checked {len(iam_users)} user(s)")
    _refresh_intel()


    # -- IAM Roles Audit --
    _check_pause()
    log("[aws] Starting IAM roles audit...")
    roles_resp = _aws_run(["iam", "list-roles", "--max-items", "200"], "iam_roles.json", use_region=False) or {}
    iam_roles = roles_resp.get("Roles") or []
    log(f"[aws] Found {len(iam_roles)} IAM role(s) (max 200)")
    _has_security_audit = False
    _has_support_access = False
    _check_pause()
    for role in iam_roles:
        _check_pause()
        rname = role.get("RoleName", "")
        rpath = role.get("Path", "")
        if rpath.startswith("/aws-service-role/") or rpath.startswith("/aws-reserved/"):
            continue
        trust_doc = role.get("AssumeRolePolicyDocument") or {}
        if isinstance(trust_doc, str):
            try:
                trust_doc = json.loads(trust_doc)
            except (json.JSONDecodeError, TypeError):
                trust_doc = {}

        # Check attached policies
        rpol_resp = _aws_run(["iam", "list-attached-role-policies", "--role-name", rname],
                              f"iam_role_{rname}_policies.json", use_region=False) or {}
        rattached = rpol_resp.get("AttachedPolicies") or []
        for rpol in rattached:
            rpol_name = rpol.get("PolicyArn", "").rsplit("/", 1)[-1]
            if rpol_name == "SecurityAudit":
                _has_security_audit = True
            if rpol_name == "AWSSupportAccess":
                _has_support_access = True

            # FORGE-AWS-234: AdministratorAccess on role
            if rpol_name == "AdministratorAccess":
                log(f"[aws] Role {rname} — has AdministratorAccess (HIGH)")
                finding(title=f"IAM role has AdministratorAccess: {rname}",
                         severity="HIGH",
                         description=f"IAM role {rname} has the AdministratorAccess managed policy attached.",
                         data={"catalogue_id": "FORGE-AWS-234", "affected": rname,
                               "remediation": "Replace AdministratorAccess with least-privilege policies."},
                         output_file=str(out_dir / f"iam_role_{rname}_policies.json"))

            # FORGE-AWS-235: Cross-account ReadOnlyAccess
            if rpol_name == "ReadOnlyAccess":
                for stmt in _normalize_stmts(trust_doc):
                    principal = stmt.get("Principal", {})
                    p_aws = principal.get("AWS", []) if isinstance(principal, dict) else []
                    if isinstance(p_aws, str):
                        p_aws = [p_aws]
                    for p in p_aws:
                        if ":" in p and ":root" in p:
                            log(f"[aws] Role {rname} — cross-account ReadOnlyAccess to {p} (HIGH)")
                            finding(title=f"IAM role grants cross-account ReadOnlyAccess: {rname}",
                                     severity="HIGH",
                                     description=f"Role {rname} has ReadOnlyAccess and trusts external account {p}.",
                                     data={"catalogue_id": "FORGE-AWS-235", "affected": rname,
                                           "remediation": "Remove ReadOnlyAccess or restrict the trust policy to internal accounts."},
                                     output_file=str(out_dir / f"iam_role_{rname}_policies.json"))
                            break

        # FORGE-AWS-236: Confused deputy prevention for service roles
        for stmt in _normalize_stmts(trust_doc):
            principal = stmt.get("Principal", {})
            p_svc = principal.get("Service", []) if isinstance(principal, dict) else []
            if isinstance(p_svc, str):
                p_svc = [p_svc]
            if p_svc:
                cond = stmt.get("Condition") or {}
                has_source = any(
                    cond.get(op, {}).get(k) for op in ("StringEquals", "StringLike", "ArnLike", "ArnEquals")
                    for k in ("aws:SourceArn", "aws:SourceAccount"))
                if not has_source:
                    log(f"[aws] Role {rname} — service trust without confused deputy prevention (HIGH)")
                    finding(title=f"IAM role missing confused deputy prevention: {rname}",
                             severity="HIGH",
                             description=f"Role {rname} trusts AWS service(s) {', '.join(p_svc)} but has no "
                                         "aws:SourceArn or aws:SourceAccount condition to prevent confused deputy attacks.",
                             data={"catalogue_id": "FORGE-AWS-236", "affected": rname,
                                   "remediation": "Add Condition with aws:SourceArn or aws:SourceAccount to the trust policy."},
                             output_file=str(out_dir / f"iam_role_{rname}_policies.json"))
                    break

                # FORGE-AWS-506: Service trust restricts source to THIS account
                if p_svc:
                    cond_src = stmt.get("Condition") or {}
                    _has_acct = any(
                        _aws_account_id and _aws_account_id in str(cond_src.get(op, {}).get("aws:SourceAccount", ""))
                        for op in ("StringEquals", "StringLike")) if _aws_account_id else False
                    if not _has_acct:
                        _has_arn_acct = any(
                            _aws_account_id and _aws_account_id in str(cond_src.get(op, {}).get("aws:SourceArn", ""))
                            for op in ("StringEquals", "StringLike", "ArnLike", "ArnEquals")) if _aws_account_id else False
                        if not _has_arn_acct:
                            log(f"[aws] Role {rname} — service trust does not restrict source to account (MEDIUM)")
                            finding(title=f"IAM role service trust not restricted to account: {rname}",
                                     severity="MEDIUM",
                                     description=f"Role {rname} trusts AWS service(s) {', '.join(p_svc)} but does not "
                                                 f"restrict aws:SourceAccount to {_aws_account_id or 'this account'}.",
                                     data={"catalogue_id": "FORGE-AWS-506", "affected": rname,
                                           "remediation": "Add aws:SourceAccount condition matching the account ID to the trust policy."},
                                     output_file=str(out_dir / f"iam_role_{rname}_policies.json"))
                            break

    # FORGE-AWS-238: SecurityAudit role
    if not _has_security_audit:
        log("[aws] No role with SecurityAudit policy found (LOW)")
        finding(title="IAM: No SecurityAudit role configured",
                 severity="LOW",
                 description="No IAM role has the SecurityAudit AWS managed policy attached. "
                             "A dedicated audit role is recommended for security assessments.",
                 data={"catalogue_id": "FORGE-AWS-238",
                       "remediation": "Create an IAM role with the SecurityAudit managed policy."},
                 output_file=str(out_dir / "iam_roles.json"))
    else:
        log("[aws] SecurityAudit role found")

    # FORGE-AWS-239: AWSSupportAccess role
    if not _has_support_access:
        log("[aws] No role with AWSSupportAccess policy found (LOW)")
        finding(title="IAM: No support access role configured",
                 severity="LOW",
                 description="No IAM role has the AWSSupportAccess managed policy. "
                             "A support role is needed to open AWS support cases.",
                 data={"catalogue_id": "FORGE-AWS-239",
                       "remediation": "Create an IAM role with the AWSSupportAccess managed policy."},
                 output_file=str(out_dir / "iam_roles.json"))
    else:
        log("[aws] AWSSupportAccess role found")

    # FORGE-AWS-237: Custom policies with permissive sts:AssumeRole
    _check_pause()
    log("[aws] Checking custom policies for permissive role assumption...")
    custom_pols = _aws_run(["iam", "list-policies", "--scope", "Local", "--max-items", "100"],
                            "iam_custom_policies.json", use_region=False) or {}
    for cpol in (custom_pols.get("Policies") or []):
        cpol_arn = cpol.get("Arn", "")
        cpol_name = cpol_arn.rsplit("/", 1)[-1]
        cpol_ver = cpol.get("DefaultVersionId", "v1")
        ver_resp = _aws_run(["iam", "get-policy-version", "--policy-arn", cpol_arn,
                              "--version-id", cpol_ver],
                             f"iam_policy_{cpol_name}_{cpol_ver}.json", use_region=False) or {}
        pol_doc = (ver_resp.get("PolicyVersion") or {}).get("Document") or {}
        if isinstance(pol_doc, str):
            try:
                pol_doc = json.loads(pol_doc)
            except (json.JSONDecodeError, TypeError):
                pol_doc = {}
        for stmt in _normalize_stmts(pol_doc):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            has_assume = any(a.lower() in ("sts:assumerole", "sts:*", "*") for a in actions)
            has_wildcard_resource = "*" in resources
            if has_assume and has_wildcard_resource:
                log(f"[aws] Custom policy {cpol_name} — allows sts:AssumeRole on * (HIGH)")
                finding(title=f"Custom IAM policy allows permissive role assumption: {cpol_name}",
                         severity="HIGH",
                         description=f"Custom policy {cpol_name} allows sts:AssumeRole (or sts:*) on Resource=*. "
                                     "This enables assumption of any role in the account.",
                         data={"catalogue_id": "FORGE-AWS-237", "affected": cpol_name,
                               "remediation": "Restrict the Resource to specific role ARNs."},
                         output_file=str(out_dir / f"iam_policy_{cpol_name}_{cpol_ver}.json"))
                break

    # FORGE-AWS-500: Hardware MFA for users with console access
    _check_pause()
    log("[aws] Checking for hardware MFA on console users...")
    for user in iam_users:
        uname = user.get("UserName", "")
        cr_row = _cred_report.get(uname, {})
        if cr_row.get("password_enabled", "").lower() != "true":
            continue
        mfa_resp = _aws_run(["iam", "list-mfa-devices", "--user-name", uname],
                              f"iam_{uname}_mfa.json", use_region=False) or {}
        mfa_devices = mfa_resp.get("MFADevices") or []
        has_hw = any("sms-mfa" not in (d.get("SerialNumber", "").lower())
                      and "arn:aws:iam::mfa/totp" not in (d.get("SerialNumber", "").lower())
                      and ":mfa/" in d.get("SerialNumber", "")
                      and "arn:aws:iam::mfa/" not in d.get("SerialNumber", "")
                      for d in mfa_devices)
        has_virtual = any("arn:aws:iam::" in d.get("SerialNumber", "")
                          and ":mfa/" in d.get("SerialNumber", "")
                          for d in mfa_devices)
        if mfa_devices and not has_hw and has_virtual:
            log(f"[aws] {uname} — MFA enabled but no hardware MFA device (HIGH)")
            finding(title=f"IAM user lacks hardware MFA: {uname}",
                     severity="HIGH",
                     description=f"IAM user {uname} has virtual MFA but no hardware MFA device. "
                                 "Hardware MFA provides stronger protection against phishing and SIM-swap attacks.",
                     data={"catalogue_id": "FORGE-AWS-500", "affected": uname,
                           "remediation": "Assign a hardware MFA device (YubiKey, Gemalto) to this user."},
                     output_file=str(out_dir / f"iam_{uname}_mfa.json"))

    # FORGE-AWS-501: Root account hardware MFA
    if root_row:
        if root_row.get("mfa_active", "").lower() == "true":
            root_mfa_resp = _aws_run(["iam", "list-mfa-devices"], "iam_root_mfa.json", use_region=False) or {}
            root_mfa_devices = root_mfa_resp.get("MFADevices") or []
            _root_has_hw = any("arn:aws:iam" in d.get("SerialNumber", "")
                                and ":mfa/" in d.get("SerialNumber", "")
                                and d.get("SerialNumber", "").startswith("arn:aws:iam::") is False
                                for d in root_mfa_devices)
            if not _root_has_hw and root_mfa_devices:
                log("[aws] Root account — virtual MFA only, no hardware MFA (CRITICAL)")
                finding(title="IAM: Root account lacks hardware MFA",
                         severity="CRITICAL",
                         description="Root account has virtual MFA but not hardware MFA. "
                                     "Hardware MFA is strongly recommended for the root account.",
                         data={"catalogue_id": "FORGE-AWS-501", "affected": "root",
                               "remediation": "Replace virtual MFA with a hardware MFA device on the root account."},
                         output_file=str(out_dir / "iam_root_mfa.json"))
            else:
                log("[aws] Root account — hardware MFA status checked")

    # FORGE-AWS-502: AWS-managed policy with *:* administrative privileges
    _check_pause()
    log("[aws] Checking AWS-managed policies for *:* privileges on entities...")
    _aws_managed_resp = _aws_run(["iam", "list-policies", "--scope", "AWS",
                                    "--only-attached", "--max-items", "200"],
                                  "iam_aws_managed_attached.json", use_region=False) or {}
    for mp in (_aws_managed_resp.get("Policies") or []):
        mp_name = mp.get("PolicyName", "")
        if mp_name in ("AdministratorAccess",):
            continue
        mp_arn = mp.get("Arn", "")
        mp_ver = mp.get("DefaultVersionId", "v1")
        ver_r = _aws_run(["iam", "get-policy-version", "--policy-arn", mp_arn,
                            "--version-id", mp_ver],
                           f"iam_awspol_{mp_name}_{mp_ver}.json", use_region=False) or {}
        pd = (ver_r.get("PolicyVersion") or {}).get("Document") or {}
        if isinstance(pd, str):
            try:
                pd = json.loads(pd)
            except (json.JSONDecodeError, TypeError):
                pd = {}
        for stmt in _normalize_stmts(pd):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            if "*" in actions and "*" in resources:
                log(f"[aws] AWS-managed policy {mp_name} — grants *:* (CRITICAL)")
                finding(title=f"AWS-managed policy with administrative privileges attached: {mp_name}",
                         severity="CRITICAL",
                         description=f"AWS-managed policy {mp_name} allows Action=* on Resource=* and is attached to entities. "
                                     "This grants full administrative access.",
                         data={"catalogue_id": "FORGE-AWS-502", "affected": mp_name,
                               "remediation": f"Detach {mp_name} and replace with least-privilege policies."},
                         output_file=str(out_dir / f"iam_awspol_{mp_name}_{mp_ver}.json"))
                break

    # FORGE-AWS-503: Root credentials management (Org feature)
    _check_pause()
    log("[aws] Checking centralized root credentials management...")
    org_resp = _aws_run(["organizations", "describe-organization"],
                         "organizations_describe.json", use_region=False)
    if org_resp:
        org = org_resp.get("Organization") or {}
        features = org.get("AvailablePolicyTypes") or []
        root_mgmt_resp = _aws_run(["iam", "list-account-aliases"], "iam_account_aliases.json", use_region=False) or {}
        org_features = _aws_run(["organizations", "list-roots"], "org_roots.json", use_region=False) or {}
        org_roots = org_features.get("Roots") or []
        has_root_mgmt = False
        for r in org_roots:
            for pt in r.get("PolicyTypes") or []:
                if "ROOT_CREDENTIALS" in pt.get("Type", ""):
                    has_root_mgmt = True
        if not has_root_mgmt:
            log("[aws] Centralized root credentials management not enabled (HIGH)")
            finding(title="AWS Organization lacks centralized root credentials management",
                     severity="HIGH",
                     description="The AWS Organization does not have centralized root credentials management enabled. "
                                 "This feature allows managing root user credentials from the management account.",
                     data={"catalogue_id": "FORGE-AWS-503",
                           "remediation": "Enable centralized root credentials management in AWS Organizations."},
                     output_file=str(out_dir / "org_roots.json"))

    # FORGE-AWS-507/508/509/510: Stale Bedrock and SageMaker access on users and roles
    _check_pause()
    log("[aws] Checking for stale Bedrock/SageMaker access...")
    _bedrock_actions = {"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream",
                        "bedrock:CreateModelCustomizationJob", "bedrock:*"}
    _sm_actions = {"sagemaker:CreateTrainingJob", "sagemaker:CreateEndpoint",
                   "sagemaker:InvokeEndpoint", "sagemaker:*"}
    _service_stale_checks = [
        ("Bedrock", _bedrock_actions, "FORGE-AWS-507", "FORGE-AWS-509"),
        ("SageMaker", _sm_actions, "FORGE-AWS-508", "FORGE-AWS-510"),
    ]
    for _svc_label, _svc_acts, _user_cat, _role_cat in _service_stale_checks:
        for user in iam_users:
            uname = user.get("UserName", "")
            cr_row = _cred_report.get(uname, {})
            _last_used = cr_row.get("access_key_1_last_used_date", "N/A")
            _ak1_active = cr_row.get("access_key_1_active", "").lower() == "true"
            if not _ak1_active:
                continue
            upol_resp = _aws_run(["iam", "list-attached-user-policies", "--user-name", uname],
                                  f"iam_user_{uname}_policies.json", use_region=False) or {}
            _has_svc = False
            for up in (upol_resp.get("AttachedPolicies") or []):
                _parn = up.get("PolicyArn", "")
                if _svc_label.lower() in _parn.lower() or "AdministratorAccess" in _parn:
                    _has_svc = True
                    break
            if _has_svc and _last_used == "N/A":
                log(f"[aws] User {uname} — has {_svc_label} access but key never used (MEDIUM)")
                finding(title=f"IAM user has stale {_svc_label} access: {uname}",
                         severity="MEDIUM",
                         description=f"User {uname} has {_svc_label} permissions but access key has never been used. "
                                     "Unused service access should be revoked.",
                         data={"catalogue_id": _user_cat, "affected": uname,
                               "remediation": f"Remove {_svc_label} permissions from user {uname} or verify active use."},
                         output_file=str(out_dir / f"iam_user_{uname}_policies.json"))
        for role in iam_roles:
            rname = role.get("RoleName", "")
            rpath = role.get("Path", "")
            if rpath.startswith("/aws-service-role/") or rpath.startswith("/aws-reserved/"):
                continue
            _last_used_r = (role.get("RoleLastUsed") or {}).get("LastUsedDate", "")
            rpol_resp2 = _aws_run(["iam", "list-attached-role-policies", "--role-name", rname],
                                    f"iam_role_{rname}_policies.json", use_region=False) or {}
            _has_svc_r = False
            for rp in (rpol_resp2.get("AttachedPolicies") or []):
                _rparn = rp.get("PolicyArn", "")
                if _svc_label.lower() in _rparn.lower() or "AdministratorAccess" in _rparn:
                    _has_svc_r = True
                    break
            if _has_svc_r and not _last_used_r:
                log(f"[aws] Role {rname} — has {_svc_label} access but never used (MEDIUM)")
                finding(title=f"IAM role has stale {_svc_label} access: {rname}",
                         severity="MEDIUM",
                         description=f"Role {rname} has {_svc_label} permissions but has never been used. "
                                     "Unused service access should be revoked.",
                         data={"catalogue_id": _role_cat, "affected": rname,
                               "remediation": f"Remove {_svc_label} permissions from role {rname} or verify active use."},
                         output_file=str(out_dir / f"iam_role_{rname}_policies.json"))

    log("[aws] IAM roles audit complete")

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
    _refresh_intel()

    # ── CloudTrail ────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting CloudTrail audit...")
    status("aws", "CloudTrail audit", "running")
    trails_resp = _aws_run(["cloudtrail", "describe-trails"], "cloudtrail_trails.json") or {}
    trails = trails_resp.get("trailList") or []
    log(f"[aws] Found {len(trails)} CloudTrail trail(s)")
    if not trails:
        if "cloudtrail" in _denied_services:
            log("[aws] CloudTrail — AccessDenied (cannot determine trail status)")
        else:
            log("[aws] No CloudTrail trails configured (HIGH)")
            finding(title="CloudTrail: No CloudTrail trails configured",
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

            # FORGE-AWS-284: CloudTrail Insights
            log(f"[aws] {trail_name} — checking Insights...")
            ins_resp = _aws_run(["cloudtrail", "get-insight-selectors", "--trail-name", trail_name],
                                 f"cloudtrail_{trail_name}_insights.json") or {}
            ins_selectors = ins_resp.get("InsightSelectors") or []
            if not ins_selectors:
                log(f"[aws] {trail_name} — Insights not enabled (LOW)")
                finding(title=f"CloudTrail Insights not enabled: {trail_name}",
                         severity="LOW",
                         description=f"Trail {trail_name} does not have CloudTrail Insights enabled for anomaly detection.",
                         data={"catalogue_id": "FORGE-AWS-284", "affected": trail_name,
                               "remediation": "aws cloudtrail put-insight-selectors --trail-name <trail> --insight-selectors '[{\"InsightType\":\"ApiCallRateInsight\"},{\"InsightType\":\"ApiErrorRateInsight\"}]'"},
                         output_file=str(out_dir / f"cloudtrail_{trail_name}_insights.json"))
            else:
                log(f"[aws] {trail_name} — Insights enabled")

            # FORGE-AWS-285/286: CloudTrail S3 data events
            log(f"[aws] {trail_name} — checking S3 data event logging...")
            _ct_es_resp = _aws_run(["cloudtrail", "get-event-selectors", "--trail-name", trail_name],
                                    f"cloudtrail_{trail_name}_event_selectors.json") or {}
            _has_s3_read = False
            _has_s3_write = False
            for _es in _ct_es_resp.get("EventSelectors") or []:
                for _dr in _es.get("DataResources") or []:
                    if _dr.get("Type") == "AWS::S3::Object":
                        rwt = _es.get("ReadWriteType", "")
                        if rwt in ("ReadOnly", "All"):
                            _has_s3_read = True
                        if rwt in ("WriteOnly", "All"):
                            _has_s3_write = True
            # Also check advanced event selectors
            for _aes in _ct_es_resp.get("AdvancedEventSelectors") or []:
                for _fs in _aes.get("FieldSelectors") or []:
                    if _fs.get("Field") == "resources.type" and "AWS::S3::Object" in (_fs.get("Equals") or []):
                        _has_s3_read = True
                        _has_s3_write = True
            if not _has_s3_read:
                log(f"[aws] {trail_name} — S3 read data events not logged (LOW)")
                finding(title=f"CloudTrail S3 read data events not logged: {trail_name}",
                         severity="LOW",
                         description=f"Trail {trail_name} does not log S3 object-level read events.",
                         data={"catalogue_id": "FORGE-AWS-285", "affected": trail_name,
                               "remediation": "Add S3 data event logging with ReadWriteType=All to the trail."},
                         output_file=str(out_dir / f"cloudtrail_{trail_name}_event_selectors.json"))
            if not _has_s3_write:
                log(f"[aws] {trail_name} — S3 write data events not logged (LOW)")
                finding(title=f"CloudTrail S3 write data events not logged: {trail_name}",
                         severity="LOW",
                         description=f"Trail {trail_name} does not log S3 object-level write events.",
                         data={"catalogue_id": "FORGE-AWS-286", "affected": trail_name,
                               "remediation": "Add S3 data event logging with ReadWriteType=All to the trail."},
                         output_file=str(out_dir / f"cloudtrail_{trail_name}_event_selectors.json"))
            if _has_s3_read and _has_s3_write:
                log(f"[aws] {trail_name} — S3 data events (read+write) logged OK")

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

            # FORGE-AWS-411: Multi-region key check
            if km.get("MultiRegion"):
                log(f"[aws] KMS {key_id[:8]} — multi-region key (MEDIUM)")
                finding(title=f"KMS customer-managed key is multi-region: {key_id[:8]}...",
                         severity="MEDIUM",
                         description="Customer-managed KMS key is configured as multi-region. "
                                     "Multi-region keys have broader blast radius if compromised.",
                         data={"catalogue_id": "FORGE-AWS-411", "affected": key_id,
                               "remediation": "Evaluate whether multi-region is required. Prefer single-region keys for reduced blast radius."},
                         output_file=str(out_dir / f"kms_{key_id[:8]}_detail.json"))

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
                for stmt in _normalize_stmts(pol_doc):
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

        # FORGE-AWS-280: Lambda not in VPC
        _vpc_cfg = fn.get("VpcConfig") or {}
        if not _vpc_cfg.get("VpcId"):
            log(f"[aws] {fn_name} — not deployed inside a VPC (LOW)")
            finding(title=f"Lambda function not in VPC: {fn_name}",
                     severity="LOW",
                     description=f"Lambda function {fn_name} is not deployed inside a VPC. "
                                 "Functions accessing private resources should run within a VPC.",
                     data={"catalogue_id": "FORGE-AWS-280", "affected": fn_name,
                           "remediation": "Configure VPC settings in the function's networking configuration."},
                     output_file=str(out_dir / "lambda_functions.json"))
        else:
            log(f"[aws] {fn_name} — in VPC {_vpc_cfg['VpcId']}")

        # FORGE-AWS-281: Lambda no DLQ
        _dlq = (fn.get("DeadLetterConfig") or {}).get("TargetArn", "")
        if not _dlq:
            log(f"[aws] {fn_name} — no dead letter queue configured (MEDIUM)")
            finding(title=f"Lambda function missing dead letter queue: {fn_name}",
                     severity="MEDIUM",
                     description=f"Lambda function {fn_name} has no Dead Letter Queue (DLQ) configured. "
                                 "Failed invocations will be silently discarded.",
                     data={"catalogue_id": "FORGE-AWS-281", "affected": fn_name,
                           "remediation": "Configure a Dead Letter Queue (SQS or SNS) for the function."},
                     output_file=str(out_dir / "lambda_functions.json"))
        else:
            log(f"[aws] {fn_name} — DLQ configured")

        # FORGE-AWS-282: Lambda env vars not encrypted with CMK
        if env_vars and not fn.get("KMSKeyArn"):
            log(f"[aws] {fn_name} — environment variables not encrypted with CMK (MEDIUM)")
            finding(title=f"Lambda function env vars not encrypted with CMK: {fn_name}",
                     severity="MEDIUM",
                     description=f"Lambda function {fn_name} has environment variables encrypted with the "
                                 "default Lambda service key, not a customer-managed KMS key.",
                     data={"catalogue_id": "FORGE-AWS-282", "affected": fn_name,
                           "remediation": "Configure a customer-managed KMS key for environment variable encryption."},
                     output_file=str(out_dir / "lambda_functions.json"))

    log(f"[aws] Lambda audit complete — checked {len(lambda_fns)} function(s)")
    _refresh_intel()


    # FORGE-AWS-283: Check if CloudTrail logs Lambda invoke operations
    _check_pause()
    log("[aws] Checking CloudTrail Lambda data event logging...")
    _has_lambda_data_events = False
    try:
        for trail in trails:
            trail_name = trail.get("Name", "")
            es_resp = _aws_run(["cloudtrail", "get-event-selectors", "--trail-name", trail_name],
                               f"cloudtrail_{trail_name}_event_selectors.json") or {}
            for es in es_resp.get("EventSelectors") or []:
                for dr in es.get("DataResources") or []:
                    if dr.get("Type") == "AWS::Lambda::Function":
                        _has_lambda_data_events = True
                        break
                if _has_lambda_data_events:
                    break
            # Also check advanced event selectors
            for aes in es_resp.get("AdvancedEventSelectors") or []:
                for fs in aes.get("FieldSelectors") or []:
                    if fs.get("Field") == "resources.type" and "AWS::Lambda::Function" in (fs.get("Equals") or []):
                        _has_lambda_data_events = True
                        break
            if _has_lambda_data_events:
                break
    except Exception:
        pass
    if not _has_lambda_data_events and lambda_fns:
        log("[aws] CloudTrail does not log Lambda invoke operations (LOW)")
        finding(title="CloudTrail: Lambda invoke API operations not logged",
                 severity="LOW",
                 description="No CloudTrail trail is configured to log Lambda Invoke data events. "
                             "Function invocations are not auditable.",
                 data={"catalogue_id": "FORGE-AWS-283",
                       "remediation": "Add Lambda data event logging to a CloudTrail trail."},
                 output_file=str(out_dir / "cloudtrail_trails.json"))
    elif _has_lambda_data_events:
        log("[aws] CloudTrail logs Lambda invoke operations OK")

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
    # FORGE-AWS-1401: VPCs in multiple regions
    _check_pause()
    log("[aws] Checking for VPCs in multiple regions...")
    _vpc_regions_with_vpcs = set()
    _all_regions_resp = _aws_run(["ec2", "describe-regions", "--query", "Regions[].RegionName"],
                                  "ec2_regions.json", use_region=False) or []
    if isinstance(_all_regions_resp, list) and len(_all_regions_resp) > 1:
        for _vr in _all_regions_resp[:20]:
            _vr_vpcs = _aws_run(["ec2", "describe-vpcs", "--region", _vr,
                                  "--query", "Vpcs[?IsDefault==`false`].VpcId"],
                                  f"ec2_vpcs_{_vr}.json", use_region=False) or []
            if isinstance(_vr_vpcs, list) and _vr_vpcs:
                _vpc_regions_with_vpcs.add(_vr)
        if len(_vpc_regions_with_vpcs) <= 1:
            log(f"[aws] VPCs only in {len(_vpc_regions_with_vpcs)} region(s) (MEDIUM)")
            finding(title="VPCs not distributed across multiple regions",
                     severity="MEDIUM",
                     description=f"Non-default VPCs exist in only {len(_vpc_regions_with_vpcs)} region(s). "
                                 "Multi-region VPC deployment improves disaster recovery posture.",
                     data={"catalogue_id": "FORGE-AWS-1401",
                           "affected": ", ".join(_vpc_regions_with_vpcs) if _vpc_regions_with_vpcs else "none",
                           "remediation": "Deploy workloads across multiple AWS regions for resilience."},
                     output_file=str(out_dir / "ec2_regions.json"))
        else:
            log(f"[aws] VPCs present in {len(_vpc_regions_with_vpcs)} regions: {', '.join(sorted(_vpc_regions_with_vpcs))}")

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
            finding(title="IAM: Password policy does not meet complexity requirements",
                     severity="MEDIUM",
                     description=f"Account password policy has weaknesses: {'; '.join(issues)}.",
                     data={"catalogue_id": "FORGE-AWS-024", "affected": "account",
                           "remediation": "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters"},
                     output_file=str(out_dir / "iam_password_policy.json"))
        else:
            log("[aws] Password policy meets complexity requirements")

        # Password expiry (FORGE-AWS-240)
        max_age = pp.get("MaxPasswordAge", 0)
        if not max_age or max_age > 90:
            log(f"[aws] Password policy — no expiry or > 90 days (max_age={max_age}) (MEDIUM)")
            finding(title="IAM: Password policy does not enforce expiration within 90 days",
                     severity="MEDIUM",
                     description=f"Account password policy MaxPasswordAge is {max_age or 'not set'}. "
                                 "Passwords should expire within 90 days.",
                     data={"catalogue_id": "FORGE-AWS-240", "affected": "account",
                           "remediation": "aws iam update-account-password-policy --max-password-age 90"},
                     output_file=str(out_dir / "iam_password_policy.json"))
        else:
            log(f"[aws] Password policy — expires in {max_age} days OK")

        # Password reuse prevention (FORGE-AWS-241)
        reuse_prev = pp.get("PasswordReusePrevention", 0)
        if not reuse_prev or reuse_prev < 24:
            log(f"[aws] Password policy — reuse prevention {reuse_prev} (should be >=24) (MEDIUM)")
            finding(title="IAM: Password policy does not prevent reuse of 24 passwords",
                     severity="MEDIUM",
                     description=f"Account password policy PasswordReusePrevention is {reuse_prev or 'not set'}. "
                                 "Should prevent reuse of the last 24 passwords.",
                     data={"catalogue_id": "FORGE-AWS-241", "affected": "account",
                           "remediation": "aws iam update-account-password-policy --password-reuse-prevention 24"},
                     output_file=str(out_dir / "iam_password_policy.json"))
        else:
            log(f"[aws] Password policy — reuse prevention {reuse_prev} OK")

    else:
        if "iam" in _denied_services:
            log("[aws] Password policy — AccessDenied (cannot determine status)")
        else:
            log("[aws] No account password policy configured (MEDIUM)")
            finding(title="IAM: Account password policy not configured",
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
    _refresh_intel()

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
                for stmt in _normalize_stmts(pol_doc):
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
                for stmt in _normalize_stmts(pol_doc):
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
                for stmt in _normalize_stmts(pol_doc):
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
        if "guardduty" in _denied_services:
            log("[aws] GuardDuty — AccessDenied (cannot determine status)")
        else:
            log("[aws] GuardDuty not enabled — no detectors found (MEDIUM)")
            finding(title="GuardDuty: Not enabled",
                     severity="MEDIUM",
                     description="Amazon GuardDuty is not enabled in this region — threat detection for the account is absent.",
                     data={"catalogue_id": "FORGE-AWS-100",
                           "remediation": "aws guardduty create-detector --enable"},
                     output_file=str(out_dir / "guardduty_detectors.json"))
    else:
        log(f"[aws] GuardDuty enabled — {len(gd_detectors)} detector(s)")

        _check_pause()
        for _det_id in gd_detectors:
            log(f"[aws] Checking GuardDuty detector {_det_id} features...")
            _det_resp = _aws_run(["guardduty", "get-detector", "--detector-id", _det_id],
                                  f"guardduty_{_det_id}_detail.json") or {}
            _features = _det_resp.get("Features") or []
            _feature_map = {f.get("Name", ""): f.get("Status", "") for f in _features}

            # FORGE-AWS-293: Runtime Monitoring
            if _feature_map.get("RUNTIME_MONITORING") != "ENABLED":
                log(f"[aws] GuardDuty {_det_id} — Runtime Monitoring not enabled (HIGH)")
                finding(title=f"GuardDuty Runtime Monitoring not enabled",
                         severity="HIGH",
                         description="GuardDuty Runtime Monitoring is not enabled — runtime threat detection for EC2/ECS/EKS is absent.",
                         data={"catalogue_id": "FORGE-AWS-293", "affected": _det_id,
                               "remediation": "Enable Runtime Monitoring in GuardDuty detector settings."},
                         output_file=str(out_dir / f"guardduty_{_det_id}_detail.json"))
            else:
                log(f"[aws] GuardDuty {_det_id} — Runtime Monitoring enabled")

            # FORGE-AWS-294: Lambda Protection
            if _feature_map.get("LAMBDA_NETWORK_LOGS") != "ENABLED":
                log(f"[aws] GuardDuty {_det_id} — Lambda Protection not enabled (HIGH)")
                finding(title=f"GuardDuty Lambda Protection not enabled",
                         severity="HIGH",
                         description="GuardDuty Lambda Protection is not enabled — Lambda network activity is not monitored for threats.",
                         data={"catalogue_id": "FORGE-AWS-294", "affected": _det_id,
                               "remediation": "Enable Lambda Protection in GuardDuty detector settings."},
                         output_file=str(out_dir / f"guardduty_{_det_id}_detail.json"))
            else:
                log(f"[aws] GuardDuty {_det_id} — Lambda Protection enabled")

            # FORGE-AWS-296: EKS Runtime Monitoring
            if _feature_map.get("EKS_RUNTIME_MONITORING") != "ENABLED":
                log(f"[aws] GuardDuty {_det_id} — EKS Runtime Monitoring not enabled (MEDIUM)")
                finding(title=f"GuardDuty EKS Runtime Monitoring not enabled",
                         severity="MEDIUM",
                         description="GuardDuty EKS Runtime Monitoring is not enabled.",
                         data={"catalogue_id": "FORGE-AWS-296", "affected": _det_id,
                               "remediation": "Enable EKS Runtime Monitoring in GuardDuty settings."},
                         output_file=str(out_dir / f"guardduty_{_det_id}_detail.json"))

            # FORGE-AWS-1001: AI Protection
            if _feature_map.get("AI_PROTECTION") != "ENABLED":
                log(f"[aws] GuardDuty {_det_id} — AI Protection not enabled (HIGH)")
                finding(title=f"GuardDuty AI Protection not enabled",
                         severity="HIGH",
                         description="GuardDuty AI Protection is not enabled — AI-related threats and model abuse are not monitored.",
                         data={"catalogue_id": "FORGE-AWS-1001", "affected": _det_id,
                               "remediation": "Enable AI Protection in GuardDuty detector settings."},
                         output_file=str(out_dir / f"guardduty_{_det_id}_detail.json"))
            else:
                log(f"[aws] GuardDuty {_det_id} — AI Protection enabled")

            # FORGE-AWS-297: Centrally managed
            _admin_resp = _aws_run(["guardduty", "get-administrator-account", "--detector-id", _det_id],
                                    f"guardduty_{_det_id}_admin.json") or {}
            _admin = _admin_resp.get("Administrator") or {}
            if not _admin.get("AccountId"):
                _members_resp = _aws_run(["guardduty", "list-members", "--detector-id", _det_id, "--max-results", "1"],
                                          f"guardduty_{_det_id}_members.json") or {}
                _members = _members_resp.get("Members") or []
                if not _members:
                    log(f"[aws] GuardDuty {_det_id} — not centrally managed (MEDIUM)")
                    finding(title="GuardDuty not centrally managed",
                             severity="MEDIUM",
                             description="GuardDuty detector is not managed by an administrator account and has no member accounts.",
                             data={"catalogue_id": "FORGE-AWS-297", "affected": _det_id,
                                   "remediation": "Configure GuardDuty with a delegated administrator for centralized management."},
                             output_file=str(out_dir / f"guardduty_{_det_id}_admin.json"))

    log("[aws] GuardDuty audit complete")

    # ── Security Hub ──────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting Security Hub audit...")
    status("aws", "Security Hub audit", "running")
    sh_resp = _aws_run(["securityhub", "describe-hub"], "securityhub_hub.json")
    if not sh_resp or not sh_resp.get("HubArn"):
        if "securityhub" in _denied_services:
            log("[aws] Security Hub — AccessDenied (cannot determine status)")
        else:
            log("[aws] Security Hub not enabled (MEDIUM)")
            finding(title="Security Hub: Not enabled",
                     severity="MEDIUM",
                     description="AWS Security Hub is not enabled in this region — centralized security posture management is absent.",
                     data={"catalogue_id": "FORGE-AWS-101",
                           "remediation": "aws securityhub enable-security-hub"},
                     output_file=str(out_dir / "securityhub_hub.json"))
    else:
        log(f"[aws] Security Hub enabled — {sh_resp.get('HubArn', '')}")

    # FORGE-AWS-102: SecurityHub delegated admin
    _sh_admin = _aws_run(["securityhub", "list-organization-admin-accounts"],
                          "securityhub_admin_accounts.json") or {}
    if not (_sh_admin.get("AdminAccounts") or []):
        if "securityhub" not in _denied_services:
            log("[aws] Security Hub — no delegated administrator configured (HIGH)")
            finding(title="Security Hub: No delegated administrator",
                     severity="HIGH",
                     description="Security Hub does not have a delegated administrator account configured "
                                 "for centralized security management across the organization.",
                     data={"catalogue_id": "FORGE-AWS-102",
                           "remediation": "Designate a Security Hub delegated administrator via AWS Organizations."},
                     output_file=str(out_dir / "securityhub_admin_accounts.json"))
    else:
        log(f"[aws] Security Hub delegated admin configured")
    log("[aws] Security Hub audit complete")
    _refresh_intel()

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

    # -- CloudWatch CIS Metric Filter Checks --
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting CloudWatch CIS metric filter/alarm audit...")
    status("aws", "CloudWatch CIS audit", "running")

    # Collect all CloudWatch alarms
    _cw_alarms_resp = _aws_run(["cloudwatch", "describe-alarms", "--max-records", "200"],
                                "cloudwatch_alarms.json") or {}
    _cw_alarms = _cw_alarms_resp.get("MetricAlarms") or []
    log(f"[aws] Found {len(_cw_alarms)} CloudWatch alarm(s)")

    # FORGE-AWS-270: Alarms with actions disabled
    _disabled_alarms = [a for a in _cw_alarms if not a.get("ActionsEnabled", True)]
    if _disabled_alarms:
        log(f"[aws] {len(_disabled_alarms)} alarm(s) have actions disabled (HIGH)")
        finding(title=f"CloudWatch alarms with actions disabled ({len(_disabled_alarms)} alarm(s))",
                 severity="HIGH",
                 description=f"{len(_disabled_alarms)} CloudWatch alarms have ActionsEnabled=false — "
                             "they will not trigger notifications or actions when breached.",
                 data={"catalogue_id": "FORGE-AWS-270",
                       "affected": f"{len(_disabled_alarms)} alarm(s)",
                       "remediation": "Enable actions on all CloudWatch alarms."},
                 output_file=str(out_dir / "cloudwatch_alarms.json"))

    # FORGE-AWS-271: Alarms without ALARM state actions
    _no_action_alarms = [a for a in _cw_alarms if not (a.get("AlarmActions") or [])]
    if _no_action_alarms:
        log(f"[aws] {len(_no_action_alarms)} alarm(s) have no ALARM actions configured (HIGH)")
        finding(title=f"CloudWatch alarms without ALARM actions ({len(_no_action_alarms)} alarm(s))",
                 severity="HIGH",
                 description=f"{len(_no_action_alarms)} CloudWatch alarms have no actions configured for the ALARM state.",
                 data={"catalogue_id": "FORGE-AWS-271",
                       "affected": f"{len(_no_action_alarms)} alarm(s)",
                       "remediation": "Configure AlarmActions (e.g., SNS topic) on all CloudWatch alarms."},
                 output_file=str(out_dir / "cloudwatch_alarms.json"))

    # CIS metric filter checks — table-driven
    # Build a map of all metric names that have alarms
    _alarmed_metrics = set()
    for a in _cw_alarms:
        mn = a.get("MetricName", "")
        ns = a.get("Namespace", "")
        if mn:
            _alarmed_metrics.add((ns, mn))

    # Get the CloudTrail log group name (if trail delivers to CW Logs)
    _ct_log_group = ""
    try:
        for trail in trails:
            _lg_arn = trail.get("CloudWatchLogsLogGroupArn", "")
            if _lg_arn:
                # ARN format: arn:aws:logs:region:account:log-group:NAME:*
                parts = _lg_arn.split(":")
                if len(parts) >= 7:
                    _ct_log_group = parts[6]
                    break
    except Exception:
        pass

    _cis_metric_filters = []
    if _ct_log_group:
        log(f"[aws] CloudTrail log group: {_ct_log_group}")
        mf_resp = _aws_run(["logs", "describe-metric-filters", "--log-group-name", _ct_log_group,
                             "--limit", "50"],
                            "cloudwatch_metric_filters.json") or {}
        _cis_metric_filters = mf_resp.get("metricFilters") or []
        log(f"[aws] Found {len(_cis_metric_filters)} metric filter(s) on trail log group")
    else:
        log("[aws] No CloudTrail→CloudWatch Logs integration — cannot check CIS metric filters")

    # Build set of filter patterns that exist + have alarms
    _active_filter_metrics = set()
    for mf in _cis_metric_filters:
        for mt in mf.get("metricTransformations") or []:
            mn = mt.get("metricName", "")
            ns = mt.get("metricNamespace", "")
            if (ns, mn) in _alarmed_metrics:
                _active_filter_metrics.add(mf.get("filterName", "").lower())
                _active_filter_metrics.add(mn.lower())
                _pat = (mf.get("filterPattern") or "").lower()
                _active_filter_metrics.add(_pat[:60])

    _CIS_CHECKS = [
        ("FORGE-AWS-250", "Unauthorized API calls",
         ["unauthorizedaccess", "accessdenied", "errorcode"]),
        ("FORGE-AWS-251", "Console sign-in without MFA",
         ["consolelogin", "mfaused"]),
        ("FORGE-AWS-252", "Root account usage",
         ["root", "useridentity"]),
        ("FORGE-AWS-253", "IAM policy changes",
         ["createpolicy", "deletepolicy", "attachpolicy", "detachpolicy", "putrolepolicy"]),
        ("FORGE-AWS-254", "CloudTrail configuration changes",
         ["createtrail", "updatetrail", "deletetrail", "startlogging", "stoplogging"]),
        ("FORGE-AWS-255", "Console authentication failures",
         ["consolelogin", "failed"]),
        ("FORGE-AWS-256", "KMS CMK disable or scheduled deletion",
         ["disablekey", "schedulekeydeletion"]),
        ("FORGE-AWS-257", "S3 bucket policy changes",
         ["putbucketpolicy", "deletebucketpolicy", "putbucketacl"]),
        ("FORGE-AWS-258", "AWS Config configuration changes",
         ["stoprecorder", "deletedelivery", "putdelivery", "putconfiguration"]),
        ("FORGE-AWS-259", "Security group changes",
         ["authorizesecuritygroup", "revokesecuritygroup", "createsecuritygroup", "deletesecuritygroup"]),
        ("FORGE-AWS-260", "Network ACL changes",
         ["createnetworkacl", "deletenetworkacl", "replacenetworkacl"]),
        ("FORGE-AWS-261", "Network gateway changes",
         ["createcustomergateway", "deletecustomergateway", "attachinternetgateway", "detachinternetgateway"]),
        ("FORGE-AWS-262", "Route table changes",
         ["createroutetable", "deleteroutetable", "replaceroute", "createroute", "deleteroute"]),
        ("FORGE-AWS-263", "VPC changes",
         ["createvpc", "deletevpc", "modifyvpc", "createvpcpeering", "deletevpcpeering"]),
        ("FORGE-AWS-264", "AWS Organizations changes",
         ["organizations", "inviteaccount", "leaveorganization"]),
    ]

    if _ct_log_group:
        for cat_id, label, keywords in _CIS_CHECKS:
            _found = False
            for token in _active_filter_metrics:
                if any(kw in token for kw in keywords):
                    _found = True
                    break
            if not _found:
                log(f"[aws] CIS check missing: {label} ({cat_id}) (MEDIUM)")
                finding(title=f"CloudWatch: No metric filter/alarm for {label}",
                         severity="MEDIUM",
                         description=f"CIS Benchmark requires a CloudWatch Logs metric filter and alarm for "
                                     f"{label}. No matching filter+alarm was found on log group {_ct_log_group}.",
                         data={"catalogue_id": cat_id, "affected": _ct_log_group,
                               "remediation": f"Create a metric filter on {_ct_log_group} matching {label} events, then create a CloudWatch alarm on that metric."},
                         output_file=str(out_dir / "cloudwatch_metric_filters.json"))
            else:
                log(f"[aws] CIS check OK: {label}")
    else:
        # No CloudTrail->CW integration — emit a single finding covering all CIS checks
        log("[aws] CloudTrail not integrated with CloudWatch — all CIS metric filter checks are gaps")
        finding(title="CloudWatch: No CloudTrail log group for CIS metric filter checks",
                 severity="MEDIUM",
                 description="CloudTrail does not deliver events to a CloudWatch Logs log group. "
                             "CIS Benchmark requires 15+ metric filters and alarms on CloudTrail events "
                             "which cannot be assessed without this integration.",
                 data={"catalogue_id": "FORGE-AWS-250", "affected": "account",
                       "remediation": "Configure CloudTrail to deliver events to a CloudWatch Logs log group, then create the CIS-required metric filters and alarms."},
                 output_file=str(out_dir / "cloudwatch_metric_filters.json"))
    log("[aws] CloudWatch CIS audit complete")


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

        # FORGE-AWS-301: Restrictive resource policy
        log(f"[aws] Secret {s_name} — checking resource policy...")
        _srp_resp = _aws_run(["secretsmanager", "get-resource-policy", "--secret-id", s_name],
                              f"secretsmanager_{s_name}_policy.json") or {}
        _srp = _srp_resp.get("ResourcePolicy", "")
        if _srp:
            try:
                _srp_doc = json.loads(_srp)
                for _stmt in _normalize_stmts(_srp_doc):
                    _p = _stmt.get("Principal", "")
                    _p_val = _p.get("AWS", "") if isinstance(_p, dict) else _p
                    if _p_val == "*" and not (_stmt.get("Condition") or {}):
                        log(f"[aws] Secret {s_name} — resource policy allows Principal=* (HIGH)")
                        finding(title=f"Secrets Manager secret publicly accessible: {s_name}",
                                 severity="HIGH",
                                 description=f"Secret {s_name} has a resource policy granting Principal=* without conditions.",
                                 data={"catalogue_id": "FORGE-AWS-301", "affected": s_name,
                                       "remediation": "Restrict the resource policy to specific accounts/principals."},
                                 output_file=str(out_dir / f"secretsmanager_{s_name}_policy.json"))
                        break
            except (json.JSONDecodeError, TypeError):
                pass
        else:
            log(f"[aws] Secret {s_name} — no resource policy (default account access)")

        # FORGE-AWS-302: Secret rotated periodically
        _last_rotated = secret.get("LastRotatedDate", "")
        if _last_rotated:
            try:
                _lr_str = _last_rotated if isinstance(_last_rotated, str) else str(_last_rotated)
                _lr_dt = datetime.fromisoformat(_lr_str.replace("Z", "+00:00"))
                _rot_days = (datetime.now(timezone.utc) - _lr_dt).days
                if _rot_days > 90:
                    log(f"[aws] Secret {s_name} — last rotated {_rot_days} days ago (MEDIUM)")
                    finding(title=f"Secrets Manager secret not rotated recently: {s_name}",
                             severity="MEDIUM",
                             description=f"Secret {s_name} was last rotated {_rot_days} days ago (threshold: 90 days).",
                             data={"catalogue_id": "FORGE-AWS-302", "affected": s_name,
                                   "remediation": "Configure automatic rotation or manually rotate the secret."},
                             output_file=str(out_dir / "secretsmanager_secrets.json"))
            except Exception:
                pass

        # FORGE-AWS-303: Secret unused
        _last_accessed = secret.get("LastAccessedDate", "")
        if _last_accessed:
            try:
                _la_str = _last_accessed if isinstance(_last_accessed, str) else str(_last_accessed)
                _la_dt = datetime.fromisoformat(_la_str.replace("Z", "+00:00"))
                _unused_d = (datetime.now(timezone.utc) - _la_dt).days
                if _unused_d > 90:
                    log(f"[aws] Secret {s_name} — not accessed for {_unused_d} days (MEDIUM)")
                    finding(title=f"Secrets Manager secret unused for {_unused_d} days: {s_name}",
                             severity="MEDIUM",
                             description=f"Secret {s_name} has not been accessed in {_unused_d} days.",
                             data={"catalogue_id": "FORGE-AWS-303", "affected": s_name,
                                   "remediation": "Review whether this secret is still needed and delete if unused."},
                             output_file=str(out_dir / "secretsmanager_secrets.json"))
            except Exception:
                pass

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

        # FORGE-AWS-287: Default root object
        if not dist.get("DefaultRootObject"):
            log(f"[aws] CloudFront {dist_label} — no default root object (HIGH)")
            finding(title=f"CloudFront distribution missing default root object: {dist_label}",
                     severity="HIGH",
                     description=f"CloudFront distribution {dist_id} has no default root object. "
                                 "Requests to the root URL may expose the S3 bucket contents.",
                     data={"catalogue_id": "FORGE-AWS-287", "affected": dist_label,
                           "remediation": "Set a default root object (e.g., index.html) in the distribution settings."},
                     output_file=str(out_dir / "cloudfront_distributions.json"))
        else:
            log(f"[aws] CloudFront {dist_label} — default root object: {dist.get('DefaultRootObject')}")

        # FORGE-AWS-288: Geo restrictions
        _geo = (dist.get("Restrictions") or {}).get("GeoRestriction") or {}
        if _geo.get("RestrictionType") == "none":
            log(f"[aws] CloudFront {dist_label} — no geo restrictions (LOW)")
            finding(title=f"CloudFront distribution without geo restrictions: {dist_label}",
                     severity="LOW",
                     description=f"CloudFront distribution {dist_id} has no geographic restrictions configured.",
                     data={"catalogue_id": "FORGE-AWS-288", "affected": dist_label,
                           "remediation": "Configure geo restrictions to limit access by country."},
                     output_file=str(out_dir / "cloudfront_distributions.json"))
        else:
            log(f"[aws] CloudFront {dist_label} — geo restrictions: {_geo.get('RestrictionType')}")

        # FORGE-AWS-289: Origin traffic encryption
        _origins = (dist.get("Origins") or {}).get("Items") or []
        for _origin in _origins:
            _coc = _origin.get("CustomOriginConfig") or {}
            if _coc and _coc.get("OriginProtocolPolicy") == "http-only":
                _oid = _origin.get("Id", "")
                log(f"[aws] CloudFront {dist_label} — origin {_oid} uses HTTP only (MEDIUM)")
                finding(title=f"CloudFront origin traffic not encrypted: {dist_label}/{_oid}",
                         severity="MEDIUM",
                         description=f"CloudFront distribution {dist_id} origin {_oid} uses OriginProtocolPolicy=http-only. "
                                     "Traffic between CloudFront and the origin is unencrypted.",
                         data={"catalogue_id": "FORGE-AWS-289", "affected": f"{dist_label}/{_oid}",
                               "remediation": "Change OriginProtocolPolicy to https-only or match-viewer."},
                         output_file=str(out_dir / "cloudfront_distributions.json"))

        # FORGE-AWS-290: S3 Origin Access Control
        for _origin in _origins:
            _s3_domain = _origin.get("DomainName", "")
            if ".s3." in _s3_domain or _s3_domain.endswith(".s3.amazonaws.com"):
                _has_oac = bool(_origin.get("OriginAccessControlId"))
                _has_oai = bool((_origin.get("S3OriginConfig") or {}).get("OriginAccessIdentity"))
                if not _has_oac and not _has_oai:
                    _oid = _origin.get("Id", "")
                    log(f"[aws] CloudFront {dist_label} — S3 origin {_oid} missing OAC/OAI (MEDIUM)")
                    finding(title=f"CloudFront S3 origin without access control: {dist_label}/{_oid}",
                             severity="MEDIUM",
                             description=f"CloudFront distribution {dist_id} S3 origin {_oid} has neither "
                                         "Origin Access Control (OAC) nor Origin Access Identity (OAI). "
                                         "The S3 bucket may need to be public for CloudFront to access it.",
                             data={"catalogue_id": "FORGE-AWS-290", "affected": f"{dist_label}/{_oid}",
                                   "remediation": "Configure Origin Access Control (OAC) for the S3 origin."},
                             output_file=str(out_dir / "cloudfront_distributions.json"))

    # FORGE-AWS-1101: CloudFront Field Level Encryption
    _check_pause()
    log("[aws] Checking CloudFront field-level encryption configs...")
    _fle_resp = _aws_run(["cloudfront", "list-field-level-encryption-configs"],
                          "cloudfront_fle_configs.json", use_region=False) or {}
    _fle_items = (_fle_resp.get("FieldLevelEncryptionList") or {}).get("Items") or []
    if dist_list and not _fle_items:
        log("[aws] No CloudFront field-level encryption configs found (LOW)")
        finding(title="CloudFront: No field-level encryption configured",
                 severity="LOW",
                 description="No CloudFront field-level encryption configurations exist. "
                             "Sensitive data in POST requests is not encrypted at the edge.",
                 data={"catalogue_id": "FORGE-AWS-1101",
                       "remediation": "Create a field-level encryption configuration for distributions handling sensitive form data."},
                 output_file=str(out_dir / "cloudfront_fle_configs.json"))
    elif _fle_items:
        log(f"[aws] Found {len(_fle_items)} field-level encryption config(s)")

    # FORGE-AWS-1102: CloudFront PQC TLS
    for dist in dist_list:
        dist_id = dist.get("Id", "")
        aliases = (dist.get("Aliases") or {}).get("Items") or []
        dist_label = aliases[0] if aliases else dist_id
        _vc = dist.get("ViewerCertificate") or {}
        _min_proto = _vc.get("MinimumProtocolVersion", "")
        if _min_proto and "PQCTLSv1" not in _min_proto:
            log(f"[aws] CloudFront {dist_label} — not using PQC TLS (LOW)")
            finding(title=f"CloudFront distribution not using post-quantum TLS: {dist_label}",
                     severity="LOW",
                     description=f"CloudFront distribution {dist_id} uses TLS security policy '{_min_proto}' "
                                 "which does not enforce post-quantum key exchange.",
                     data={"catalogue_id": "FORGE-AWS-1102", "affected": dist_label,
                           "remediation": "Update the security policy to one with PQC TLS 1.3 support."},
                     output_file=str(out_dir / "cloudfront_distributions.json"))

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

        # FORGE-AWS-298: DynamoDB deletion protection
        if not tbl.get("DeletionProtectionEnabled"):
            log(f"[aws] DynamoDB {tbl_name} — deletion protection disabled (MEDIUM)")
            finding(title=f"DynamoDB table deletion protection disabled: {tbl_name}",
                     severity="MEDIUM",
                     description=f"DynamoDB table {tbl_name} does not have deletion protection enabled.",
                     data={"catalogue_id": "FORGE-AWS-298", "affected": tbl_name,
                           "remediation": "aws dynamodb update-table --table-name <table> --deletion-protection-enabled"},
                     output_file=str(out_dir / f"dynamodb_{tbl_name}_detail.json"))
        else:
            log(f"[aws] DynamoDB {tbl_name} — deletion protection enabled")

        # FORGE-AWS-299: DynamoDB PITR
        _pitr_resp = _aws_run(["dynamodb", "describe-continuous-backups", "--table-name", tbl_name],
                               f"dynamodb_{tbl_name}_backups.json") or {}
        _pitr_desc = (_pitr_resp.get("ContinuousBackupsDescription") or {}).get("PointInTimeRecoveryDescription") or {}
        if _pitr_desc.get("PointInTimeRecoveryStatus") != "ENABLED":
            log(f"[aws] DynamoDB {tbl_name} — PITR not enabled (MEDIUM)")
            finding(title=f"DynamoDB table PITR not enabled: {tbl_name}",
                     severity="MEDIUM",
                     description=f"DynamoDB table {tbl_name} does not have point-in-time recovery (PITR) enabled.",
                     data={"catalogue_id": "FORGE-AWS-299", "affected": tbl_name,
                           "remediation": "aws dynamodb update-continuous-backups --table-name <table> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"},
                     output_file=str(out_dir / f"dynamodb_{tbl_name}_backups.json"))
        else:
            log(f"[aws] DynamoDB {tbl_name} — PITR enabled")

    # FORGE-AWS-1201: DynamoDB tables protected by backup plan
    _check_pause()
    log("[aws] Checking DynamoDB tables against AWS Backup plans...")
    _ddb_backup_selections = set()
    try:
        _bp_resp = _aws_run(["backup", "list-backup-plans"], "backup_plans_ddb.json") or {}
        for _bp in (_bp_resp.get("BackupPlansList") or []):
            _bp_id = _bp.get("BackupPlanId", "")
            _sel_resp = _aws_run(["backup", "list-backup-selections", "--backup-plan-id", _bp_id],
                                  f"backup_{_bp_id}_selections.json") or {}
            for _sel in (_sel_resp.get("BackupSelectionsList") or []):
                _sel_id = _sel.get("SelectionId", "")
                _sel_detail = _aws_run(["backup", "get-backup-selection",
                                        "--backup-plan-id", _bp_id, "--selection-id", _sel_id],
                                        f"backup_{_bp_id}_{_sel_id}.json") or {}
                _sel_data = _sel_detail.get("BackupSelection") or {}
                for _r in _sel_data.get("Resources") or []:
                    if ":dynamodb:" in _r or _r == "*":
                        _ddb_backup_selections.add("*")
                    if ":table/" in _r:
                        _ddb_backup_selections.add(_r.rsplit("/", 1)[-1])
    except Exception:
        pass
    if "*" not in _ddb_backup_selections:
        for tbl_name in ddb_tables:
            if tbl_name not in _ddb_backup_selections:
                log(f"[aws] DynamoDB {tbl_name} — not protected by a backup plan (MEDIUM)")
                finding(title=f"DynamoDB table not protected by backup plan: {tbl_name}",
                         severity="MEDIUM",
                         description=f"DynamoDB table {tbl_name} is not covered by any AWS Backup plan.",
                         data={"catalogue_id": "FORGE-AWS-1201", "affected": tbl_name,
                               "remediation": "Add the DynamoDB table to an AWS Backup plan."},
                         output_file=str(out_dir / "backup_plans_ddb.json"))

    log(f"[aws] DynamoDB audit complete — checked {len(ddb_tables)} table(s)")
    _refresh_intel()

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

            # FORGE-AWS-306: Check logging configuration mode
            _log_cfg = cdef.get("logConfiguration") or {}
            _log_opts = _log_cfg.get("options") or {}
            if _log_opts.get("mode") == "blocking":
                log(f"[aws] ECS {td_name}/{c_name} — logging in blocking mode (LOW)")
                finding(title=f"ECS task definition uses blocking log mode: {td_name}/{c_name}",
                         severity="LOW",
                         description=f"Container {c_name} in task definition {td_name} uses blocking log mode. "
                                     "If the logging driver is unavailable, the container will block.",
                         data={"catalogue_id": "FORGE-AWS-306", "affected": f"{td_name}/{c_name}",
                               "remediation": "Set logging options mode to 'non-blocking' with max-buffer-size."},
                         output_file=str(out_dir / f"ecs_{td_name}_detail.json"))

    log(f"[aws] ECS audit complete — checked {len(ecs_arns)} task definition(s)")

    # FORGE-AWS-304: ECS cluster Container Insights
    _check_pause()
    log("[aws] Checking ECS cluster Container Insights...")
    ecs_clusters_resp = _aws_run(["ecs", "list-clusters"], "ecs_clusters.json") or {}
    ecs_cluster_arns = ecs_clusters_resp.get("clusterArns") or []
    if ecs_cluster_arns:
        _check_pause()
        ecs_desc_resp = _aws_run(["ecs", "describe-clusters", "--clusters"] + ecs_cluster_arns[:10] +
                                  ["--include", "SETTINGS"],
                                  "ecs_clusters_detail.json") or {}
        for _cl in ecs_desc_resp.get("clusters") or []:
            _cl_name = _cl.get("clusterName", "")
            _cl_settings = _cl.get("settings") or []
            _ci_enabled = any(s.get("name") == "containerInsights" and s.get("value") == "enabled"
                              for s in _cl_settings)
            if not _ci_enabled:
                log(f"[aws] ECS cluster {_cl_name} — Container Insights not enabled (MEDIUM)")
                finding(title=f"ECS cluster Container Insights disabled: {_cl_name}",
                         severity="MEDIUM",
                         description=f"ECS cluster {_cl_name} does not have Container Insights enabled for monitoring.",
                         data={"catalogue_id": "FORGE-AWS-304", "affected": _cl_name,
                               "remediation": "aws ecs update-cluster-settings --cluster <name> --settings name=containerInsights,value=enabled"},
                         output_file=str(out_dir / "ecs_clusters_detail.json"))
            else:
                log(f"[aws] ECS cluster {_cl_name} — Container Insights enabled")

        # FORGE-AWS-305: ECS service public IP assignment
        for _cl_arn in ecs_cluster_arns[:10]:
            _cl_short = _cl_arn.rsplit("/", 1)[-1] if "/" in _cl_arn else _cl_arn
            _svcs_resp = _aws_run(["ecs", "list-services", "--cluster", _cl_arn, "--max-results", "20"],
                                   f"ecs_{_cl_short}_services.json") or {}
            _svc_arns = _svcs_resp.get("serviceArns") or []
            if _svc_arns:
                _check_pause()
                _svc_desc = _aws_run(["ecs", "describe-services", "--cluster", _cl_arn,
                                       "--services"] + _svc_arns[:10],
                                      f"ecs_{_cl_short}_services_detail.json") or {}
                for _svc in _svc_desc.get("services") or []:
                    _svc_name = _svc.get("serviceName", "")
                    _net_cfg = (_svc.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
                    if _net_cfg.get("assignPublicIp") == "ENABLED":
                        log(f"[aws] ECS service {_svc_name} — assigns public IP (HIGH)")
                        finding(title=f"ECS service assigns public IP: {_svc_name}",
                                 severity="HIGH",
                                 description=f"ECS service {_svc_name} in cluster {_cl_short} assigns public IP addresses to tasks.",
                                 data={"catalogue_id": "FORGE-AWS-305", "affected": f"{_cl_short}/{_svc_name}",
                                       "remediation": "Set assignPublicIp to DISABLED and use a load balancer for public access."},
                                 output_file=str(out_dir / f"ecs_{_cl_short}_services_detail.json"))

    # ── ELBv2 ─────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting ELBv2 audit...")
    status("aws", "ELBv2 audit", "running")
    _elb_resp = _aws_run(["elbv2", "describe-load-balancers"], "elbv2_load_balancers.json") or {}
    _elbs = _elb_resp.get("LoadBalancers") or []
    log(f"[aws] Found {len(_elbs)} ELBv2 load balancer(s)")
    _check_pause()
    for _lb in _elbs:
        _lb_arn = _lb.get("LoadBalancerArn", "")
        _lb_name = _lb.get("LoadBalancerName", "")
        _lb_type = _lb.get("Type", "")
        log(f"[aws] Checking ELBv2 {_lb_name} ({_lb_type})...")

        # FORGE-AWS-310: Deletion protection
        _lb_attrs_resp = _aws_run(["elbv2", "describe-load-balancer-attributes",
                                    "--load-balancer-arn", _lb_arn],
                                   f"elbv2_{_lb_name}_attrs.json") or {}
        _lb_attrs = {a.get("Key"): a.get("Value") for a in (_lb_attrs_resp.get("Attributes") or [])}
        if _lb_attrs.get("deletion_protection.enabled") != "true":
            log(f"[aws] ELBv2 {_lb_name} — deletion protection disabled (MEDIUM)")
            finding(title=f"ELBv2 deletion protection disabled: {_lb_name}",
                     severity="MEDIUM",
                     description=f"Load balancer {_lb_name} does not have deletion protection enabled.",
                     data={"catalogue_id": "FORGE-AWS-310", "affected": _lb_name,
                           "remediation": "aws elbv2 modify-load-balancer-attributes --load-balancer-arn <arn> --attributes Key=deletion_protection.enabled,Value=true"},
                     output_file=str(out_dir / f"elbv2_{_lb_name}_attrs.json"))
        else:
            log(f"[aws] ELBv2 {_lb_name} — deletion protection enabled")

        # FORGE-AWS-311: Drop invalid header fields (ALB only)
        if _lb_type == "application":
            if _lb_attrs.get("routing.http.drop_invalid_header_fields.enabled") != "true":
                log(f"[aws] ELBv2 {_lb_name} — does not drop invalid header fields (MEDIUM)")
                finding(title=f"ALB does not drop invalid header fields: {_lb_name}",
                         severity="MEDIUM",
                         description=f"Application Load Balancer {_lb_name} does not drop invalid HTTP header fields. "
                                     "This could allow HTTP request smuggling attacks.",
                         data={"catalogue_id": "FORGE-AWS-311", "affected": _lb_name,
                               "remediation": "Enable routing.http.drop_invalid_header_fields.enabled attribute."},
                         output_file=str(out_dir / f"elbv2_{_lb_name}_attrs.json"))

        # FORGE-AWS-312/313: Listener TLS policies
        log(f"[aws] ELBv2 {_lb_name} — checking listeners...")
        _listeners_resp = _aws_run(["elbv2", "describe-listeners", "--load-balancer-arn", _lb_arn],
                                    f"elbv2_{_lb_name}_listeners.json") or {}
        for _listener in _listeners_resp.get("Listeners") or []:
            _proto = _listener.get("Protocol", "")
            if _proto in ("HTTPS", "TLS"):
                _ssl_pol = _listener.get("SslPolicy", "")
                _port = _listener.get("Port", "")
                if _ssl_pol and "FIPS" not in _ssl_pol:
                    log(f"[aws] ELBv2 {_lb_name}:{_port} — non-FIPS TLS policy {_ssl_pol} (LOW)")
                    finding(title=f"ELBv2 listener without FIPS TLS policy: {_lb_name}:{_port}",
                             severity="LOW",
                             description=f"Listener on {_lb_name} port {_port} uses TLS policy {_ssl_pol} which is not FIPS-compliant.",
                             data={"catalogue_id": "FORGE-AWS-312", "affected": f"{_lb_name}:{_port}",
                                   "remediation": "Update the listener SSL policy to a FIPS-compliant policy."},
                             output_file=str(out_dir / f"elbv2_{_lb_name}_listeners.json"))
                # FORGE-AWS-505: PQC TLS for ELBv2
                if _ssl_pol and "PQ" not in _ssl_pol.upper() and "PostQuantum" not in _ssl_pol:
                    log(f"[aws] ELBv2 {_lb_name}:{_port} — no post-quantum TLS policy (LOW)")
                    finding(title=f"ELBv2 listener without post-quantum TLS policy: {_lb_name}:{_port}",
                             severity="LOW",
                             description=f"Listener on {_lb_name} port {_port} uses TLS policy {_ssl_pol} "
                                         "which does not support post-quantum key exchange.",
                             data={"catalogue_id": "FORGE-AWS-505", "affected": f"{_lb_name}:{_port}",
                                   "remediation": "Update the listener SSL policy to a PQ-TLS-supporting policy."},
                             output_file=str(out_dir / f"elbv2_{_lb_name}_listeners.json"))
    log(f"[aws] ELBv2 audit complete — checked {len(_elbs)} load balancer(s)")

    # ── IAM Access Analyzer ───────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting IAM Access Analyzer audit...")
    status("aws", "Access Analyzer audit", "running")
    _aa_resp = _aws_run(["accessanalyzer", "list-analyzers"], "accessanalyzer_analyzers.json") or {}
    _analyzers = _aa_resp.get("analyzers") or []
    if not _analyzers:
        if "accessanalyzer" not in _denied_services:
            log("[aws] IAM Access Analyzer not enabled (LOW)")
            finding(title="IAM Access Analyzer not enabled",
                     severity="LOW",
                     description="No IAM Access Analyzer is configured in this region. "
                                 "Access Analyzer identifies resources shared with external entities.",
                     data={"catalogue_id": "FORGE-AWS-320",
                           "remediation": "aws accessanalyzer create-analyzer --analyzer-name default --type ACCOUNT"},
                     output_file=str(out_dir / "accessanalyzer_analyzers.json"))
    else:
        log(f"[aws] IAM Access Analyzer enabled — {len(_analyzers)} analyzer(s)")
    log("[aws] IAM Access Analyzer audit complete")

    # ── AWS Config ────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting AWS Config audit...")
    status("aws", "AWS Config audit", "running")
    _cfg_recorders = _aws_run(["configservice", "describe-configuration-recorders"],
                               "config_recorders.json") or {}
    _recorders = _cfg_recorders.get("ConfigurationRecorders") or []
    _cfg_status = _aws_run(["configservice", "describe-configuration-recorder-status"],
                            "config_recorder_status.json") or {}
    _rec_statuses = _cfg_status.get("ConfigurationRecordersStatus") or []
    _rec_recording = any(s.get("recording") for s in _rec_statuses)
    if not _recorders or not _rec_recording:
        if "configservice" not in _denied_services:
            log("[aws] AWS Config recorder not enabled or not recording (MEDIUM)")
            finding(title="AWS Config recorder not enabled",
                     severity="MEDIUM",
                     description="AWS Config is not recording resource configurations in this region.",
                     data={"catalogue_id": "FORGE-AWS-330",
                           "remediation": "Enable AWS Config recording for all resource types."},
                     output_file=str(out_dir / "config_recorders.json"))
    else:
        log(f"[aws] AWS Config recorder active — {len(_recorders)} recorder(s)")

    _cfg_agg = _aws_run(["configservice", "describe-configuration-aggregators"],
                          "config_aggregators.json") or {}
    if not (_cfg_agg.get("ConfigurationAggregators") or []):
        if "configservice" not in _denied_services:
            log("[aws] No AWS Config aggregator configured (HIGH)")
            finding(title="AWS Config: No configuration aggregator",
                     severity="HIGH",
                     description="No AWS Config aggregator is configured — cross-account/cross-region configuration visibility is absent.",
                     data={"catalogue_id": "FORGE-AWS-331",
                           "remediation": "Create an organization or account aggregator in AWS Config."},
                     output_file=str(out_dir / "config_aggregators.json"))
    else:
        log("[aws] AWS Config aggregator configured")
    log("[aws] AWS Config audit complete")

    # ── Inspector ─────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting Inspector audit...")
    status("aws", "Inspector audit", "running")
    _insp_resp = _aws_run(["inspector2", "batch-get-account-status"],
                           "inspector2_account_status.json") or {}
    _insp_accounts = _insp_resp.get("accounts") or []
    _insp_enabled = False
    for _ia in _insp_accounts:
        if (_ia.get("state") or {}).get("status") == "ENABLED":
            _insp_enabled = True
            break
    if not _insp_enabled:
        if "inspector2" not in _denied_services:
            log("[aws] Inspector not enabled (MEDIUM)")
            finding(title="Inspector not enabled",
                     severity="MEDIUM",
                     description="Amazon Inspector is not enabled — automated vulnerability scanning for EC2, ECR, and Lambda is absent.",
                     data={"catalogue_id": "FORGE-AWS-340",
                           "remediation": "aws inspector2 enable --resource-types EC2 ECR LAMBDA LAMBDA_CODE"},
                     output_file=str(out_dir / "inspector2_account_status.json"))
    else:
        log("[aws] Inspector enabled")
        # FORGE-AWS-341: Inspector2 active findings
        _insp_findings = _aws_run(["inspector2", "list-findings",
                                    "--filter-criteria", '{"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}',
                                    "--max-results", "10"],
                                   "inspector2_active_findings.json") or {}
        _active_f = _insp_findings.get("findings") or []
        if _active_f:
            log(f"[aws] Inspector — {len(_active_f)}+ active finding(s) (HIGH)")
            finding(title=f"Inspector2 has active findings ({len(_active_f)}+)",
                     severity="HIGH",
                     description=f"Amazon Inspector has {len(_active_f)}+ active vulnerability findings that require remediation.",
                     data={"catalogue_id": "FORGE-AWS-341",
                           "affected": f"{len(_active_f)}+ finding(s)",
                           "remediation": "Review and remediate active Inspector findings."},
                     output_file=str(out_dir / "inspector2_active_findings.json"))
        else:
            log("[aws] Inspector — no active findings")

        # FORGE-AWS-511: Inspector2 active findings age check
        if _active_f:
            from datetime import datetime as _dt, timezone as _tz
            _now = _dt.now(_tz.utc)
            _max_age_days = 90
            for _af in _active_f:
                _created = _af.get("firstObservedAt", "") or _af.get("createdAt", "")
                if _created:
                    try:
                        _created_dt = _dt.fromisoformat(_created.replace("Z", "+00:00"))
                        _age = (_now - _created_dt).days
                        if _age > _max_age_days:
                            _ftitle = _af.get("title", "Unknown")[:80]
                            log(f"[aws] Inspector finding older than {_max_age_days} days: {_ftitle} ({_age}d) (MEDIUM)")
                            finding(title=f"Inspector2 finding older than {_max_age_days} days",
                                     severity="MEDIUM",
                                     description=f"Active Inspector finding \"{_ftitle}\" is {_age} days old (max: {_max_age_days}). "
                                                 "Aging findings indicate unresolved vulnerabilities.",
                                     data={"catalogue_id": "FORGE-AWS-511",
                                           "affected": _ftitle,
                                           "remediation": "Remediate or suppress aged Inspector findings."},
                                     output_file=str(out_dir / "inspector2_active_findings.json"))
                            break
                    except (ValueError, TypeError):
                        pass

        # FORGE-AWS-342: Inspector2 coverage
        _insp_cov = _aws_run(["inspector2", "list-coverage", "--max-results", "50"],
                              "inspector2_coverage.json") or {}
        _cov_resources = _insp_cov.get("coveredResources") or []
        _inactive_cov = [r for r in _cov_resources
                         if r.get("scanStatus", {}).get("statusCode") != "ACTIVE"]
        if _inactive_cov:
            log(f"[aws] Inspector — {len(_inactive_cov)} resource(s) not actively scanned (MEDIUM)")
            finding(title=f"Inspector2 resources not actively scanned ({len(_inactive_cov)})",
                     severity="MEDIUM",
                     description=f"{len(_inactive_cov)} resources covered by Inspector are not in ACTIVE scan status.",
                     data={"catalogue_id": "FORGE-AWS-342",
                           "affected": f"{len(_inactive_cov)} resource(s)",
                           "remediation": "Investigate why covered resources are not being actively scanned."},
                     output_file=str(out_dir / "inspector2_coverage.json"))
        # FORGE-AWS-343: Resources not recently scanned
        from datetime import datetime as _dt2, timezone as _tz2
        _stale_scan_days = 30
        _stale_count = 0
        for _cr in _cov_resources:
            _ls = _cr.get("lastScannedAt", "")
            if _ls:
                try:
                    _ls_dt = _dt2.fromisoformat(str(_ls).replace("Z", "+00:00"))
                    if (_dt2.now(_tz2.utc) - _ls_dt).days > _stale_scan_days:
                        _stale_count += 1
                except (ValueError, TypeError):
                    pass
        if _stale_count:
            log(f"[aws] Inspector — {_stale_count} resource(s) not scanned in {_stale_scan_days}+ days (MEDIUM)")
            finding(title=f"Inspector2 resources not recently scanned ({_stale_count})",
                     severity="MEDIUM",
                     description=f"{_stale_count} Inspector-covered resource(s) were not scanned in the last {_stale_scan_days} days.",
                     data={"catalogue_id": "FORGE-AWS-343",
                           "affected": f"{_stale_count} resource(s)",
                           "remediation": "Ensure Inspector SSM agent is running and resources are reachable."},
                     output_file=str(out_dir / "inspector2_coverage.json"))
    log("[aws] Inspector audit complete")

    # ── EKS ───────────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting EKS audit...")
    status("aws", "EKS audit", "running")
    _eks_resp = _aws_run(["eks", "list-clusters"], "eks_clusters.json") or {}
    _eks_clusters = _eks_resp.get("clusters") or []
    log(f"[aws] Found {len(_eks_clusters)} EKS cluster(s)")
    _check_pause()
    for _eks_name in _eks_clusters:
        _check_pause()
        log(f"[aws] Checking EKS cluster {_eks_name}...")
        _eks_detail = _aws_run(["eks", "describe-cluster", "--name", _eks_name],
                                f"eks_{_eks_name}_detail.json") or {}
        _cl = _eks_detail.get("cluster") or {}

        # FORGE-AWS-350: Control plane logging
        _logging = _cl.get("logging") or {}
        _log_types_enabled = set()
        for _lc in (_logging.get("clusterLogging") or []):
            if _lc.get("enabled"):
                _log_types_enabled.update(_lc.get("types") or [])
        _required_types = {"api", "audit", "authenticator", "controllerManager", "scheduler"}
        _missing_types = _required_types - _log_types_enabled
        if _missing_types:
            log(f"[aws] EKS {_eks_name} — missing log types: {sorted(_missing_types)} (MEDIUM)")
            finding(title=f"EKS cluster control plane logging incomplete: {_eks_name}",
                     severity="MEDIUM",
                     description=f"EKS cluster {_eks_name} is missing control plane log types: {', '.join(sorted(_missing_types))}.",
                     data={"catalogue_id": "FORGE-AWS-350", "affected": _eks_name,
                           "remediation": "aws eks update-cluster-config --name <cluster> --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'"},
                     output_file=str(out_dir / f"eks_{_eks_name}_detail.json"))
        else:
            log(f"[aws] EKS {_eks_name} — all control plane log types enabled")

        # FORGE-AWS-351: Deletion protection
        if not _cl.get("deletionProtection"):
            log(f"[aws] EKS {_eks_name} — deletion protection not enabled (HIGH)")
            finding(title=f"EKS cluster deletion protection not enabled: {_eks_name}",
                     severity="HIGH",
                     description=f"EKS cluster {_eks_name} does not have deletion protection enabled.",
                     data={"catalogue_id": "FORGE-AWS-351", "affected": _eks_name,
                           "remediation": "aws eks update-cluster-config --name <cluster> --deletion-protection true"},
                     output_file=str(out_dir / f"eks_{_eks_name}_detail.json"))
    log(f"[aws] EKS audit complete — checked {len(_eks_clusters)} cluster(s)")

    # ── Cognito ───────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting Cognito audit...")
    status("aws", "Cognito audit", "running")
    _cog_resp = _aws_run(["cognito-idp", "list-user-pools", "--max-results", "60"],
                          "cognito_user_pools.json") or {}
    _cog_pools = _cog_resp.get("UserPools") or []
    log(f"[aws] Found {len(_cog_pools)} Cognito user pool(s)")
    _check_pause()
    for _pool in _cog_pools:
        _pool_id = _pool.get("Id", "")
        _pool_name = _pool.get("Name", _pool_id)
        log(f"[aws] Checking Cognito user pool {_pool_name}...")
        _pool_detail = _aws_run(["cognito-idp", "describe-user-pool", "--user-pool-id", _pool_id],
                                 f"cognito_{_pool_id}_detail.json") or {}
        _up = _pool_detail.get("UserPool") or {}

        # FORGE-AWS-360: MFA
        _mfa_cfg = _up.get("MfaConfiguration", "OFF")
        if _mfa_cfg == "OFF":
            log(f"[aws] Cognito {_pool_name} — MFA disabled (MEDIUM)")
            finding(title=f"Cognito user pool MFA disabled: {_pool_name}",
                     severity="MEDIUM",
                     description=f"Cognito user pool {_pool_name} has MFA set to OFF.",
                     data={"catalogue_id": "FORGE-AWS-360", "affected": _pool_name,
                           "remediation": "Enable MFA (OPTIONAL or ON) for the user pool."},
                     output_file=str(out_dir / f"cognito_{_pool_id}_detail.json"))
        else:
            log(f"[aws] Cognito {_pool_name} — MFA: {_mfa_cfg}")

        # FORGE-AWS-361: Deletion protection
        if _up.get("DeletionProtection") != "ACTIVE":
            log(f"[aws] Cognito {_pool_name} — deletion protection not active (MEDIUM)")
            finding(title=f"Cognito user pool deletion protection disabled: {_pool_name}",
                     severity="MEDIUM",
                     description=f"Cognito user pool {_pool_name} does not have deletion protection enabled.",
                     data={"catalogue_id": "FORGE-AWS-361", "affected": _pool_name,
                           "remediation": "Enable deletion protection for the user pool."},
                     output_file=str(out_dir / f"cognito_{_pool_id}_detail.json"))

        # FORGE-AWS-362: Password policy minimum length
        _pp = (_up.get("Policies") or {}).get("PasswordPolicy") or {}
        _min_len = _pp.get("MinimumLength", 0)
        if _min_len < 14:
            log(f"[aws] Cognito {_pool_name} — password min length {_min_len} (< 14) (MEDIUM)")
            finding(title=f"Cognito user pool weak password policy: {_pool_name}",
                     severity="MEDIUM",
                     description=f"Cognito user pool {_pool_name} requires minimum password length of {_min_len} "
                                 "(should be at least 14).",
                     data={"catalogue_id": "FORGE-AWS-362", "affected": _pool_name,
                           "remediation": "Update the password policy to require minimum 14 characters."},
                     output_file=str(out_dir / f"cognito_{_pool_id}_detail.json"))

        # FORGE-AWS-363: User pool client prevent user existence errors
        _clients_resp = _aws_run(["cognito-idp", "list-user-pool-clients",
                                   "--user-pool-id", _pool_id, "--max-results", "20"],
                                  f"cognito_{_pool_id}_clients.json") or {}
        for _client in (_clients_resp.get("UserPoolClients") or []):
            _cid = _client.get("ClientId", "")
            _cname = _client.get("ClientName", _cid)
            _cd = _aws_run(["cognito-idp", "describe-user-pool-client",
                             "--user-pool-id", _pool_id, "--client-id", _cid],
                            f"cognito_{_pool_id}_{_cid}_detail.json") or {}
            _upc = _cd.get("UserPoolClient") or {}
            if _upc.get("PreventUserExistenceErrors") != "ENABLED":
                log(f"[aws] Cognito client {_cname} — does not prevent user existence errors (MEDIUM)")
                finding(title=f"Cognito client does not prevent user existence errors: {_cname}",
                         severity="MEDIUM",
                         description=f"Cognito user pool client {_cname} (pool {_pool_name}) does not prevent "
                                     "user existence errors. Attackers can enumerate valid usernames.",
                         data={"catalogue_id": "FORGE-AWS-363", "affected": f"{_pool_name}/{_cname}",
                               "remediation": "Enable PreventUserExistenceErrors on the user pool client."},
                         output_file=str(out_dir / f"cognito_{_pool_id}_{_cid}_detail.json"))
    log(f"[aws] Cognito audit complete — checked {len(_cog_pools)} user pool(s)")

    # ── SSM Patch Compliance ──────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting SSM patch compliance audit...")
    status("aws", "SSM audit", "running")
    _ssm_resp = _aws_run(["ssm", "describe-instance-information", "--max-results", "50"],
                          "ssm_managed_instances.json") or {}
    _ssm_instances = _ssm_resp.get("InstanceInformationList") or []
    log(f"[aws] Found {len(_ssm_instances)} SSM managed instance(s)")
    _check_pause()
    _noncompliant_count = 0
    for _mi in _ssm_instances:
        _mi_id = _mi.get("InstanceId", "")
        _comp_resp = _aws_run(["ssm", "list-compliance-items",
                                "--resource-ids", _mi_id,
                                "--resource-types", "ManagedInstance",
                                "--filters", "Key=ComplianceType,Values=Patch,Type=EQUAL",
                                "--max-results", "50"],
                               f"ssm_{_mi_id}_compliance.json") or {}
        _comp_items = _comp_resp.get("ComplianceItems") or []
        _nc = [c for c in _comp_items if c.get("Status") == "NON_COMPLIANT"]
        if _nc:
            _noncompliant_count += 1
            log(f"[aws] SSM {_mi_id} — {len(_nc)} non-compliant patch(es) (HIGH)")
            finding(title=f"SSM managed instance non-compliant with patching: {_mi_id}",
                     severity="HIGH",
                     description=f"Managed instance {_mi_id} has {len(_nc)} non-compliant patches.",
                     data={"catalogue_id": "FORGE-AWS-370", "affected": _mi_id,
                           "remediation": "Apply missing patches via Systems Manager Patch Manager."},
                     output_file=str(out_dir / f"ssm_{_mi_id}_compliance.json"))
    if _noncompliant_count == 0 and _ssm_instances:
        log("[aws] All SSM managed instances are patch-compliant")
    log("[aws] SSM audit complete")

    # ── AWS Backup ────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting AWS Backup audit...")
    status("aws", "Backup audit", "running")
    _bkp_rp = _aws_run(["backup", "list-report-plans"], "backup_report_plans.json") or {}
    if not (_bkp_rp.get("ReportPlans") or []):
        if "backup" not in _denied_services:
            log("[aws] No AWS Backup report plans configured (LOW)")
            finding(title="AWS Backup: No report plans configured",
                     severity="LOW",
                     description="No AWS Backup report plans are configured for compliance auditing.",
                     data={"catalogue_id": "FORGE-AWS-380",
                           "remediation": "Create an AWS Backup report plan for backup compliance monitoring."},
                     output_file=str(out_dir / "backup_report_plans.json"))
    else:
        log(f"[aws] AWS Backup report plans: {len(_bkp_rp.get('ReportPlans', []))}")
    log("[aws] AWS Backup audit complete")

    # ── CloudFormation ────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting CloudFormation audit...")
    status("aws", "CloudFormation audit", "running")
    _cfn_resp = _aws_run(["cloudformation", "list-stacks",
                           "--stack-status-filter", "CREATE_COMPLETE", "UPDATE_COMPLETE",
                           "UPDATE_ROLLBACK_COMPLETE"],
                          "cloudformation_stacks.json") or {}
    _cfn_stacks = _cfn_resp.get("StackSummaries") or []
    log(f"[aws] Found {len(_cfn_stacks)} CloudFormation stack(s)")
    _check_pause()
    _no_term_count = 0
    for _stk in _cfn_stacks:
        _stk_name = _stk.get("StackName", "")
        _stk_detail = _aws_run(["cloudformation", "describe-stacks", "--stack-name", _stk_name],
                                f"cfn_{_stk_name}_detail.json") or {}
        _stk_info = (_stk_detail.get("Stacks") or [{}])[0]
        if not _stk_info.get("EnableTerminationProtection"):
            _no_term_count += 1
    if _no_term_count > 0:
        log(f"[aws] {_no_term_count} CloudFormation stack(s) without termination protection (MEDIUM)")
        finding(title=f"CloudFormation stacks without termination protection ({_no_term_count} stack(s))",
                 severity="MEDIUM",
                 description=f"{_no_term_count} of {len(_cfn_stacks)} CloudFormation stacks do not have termination protection enabled.",
                 data={"catalogue_id": "FORGE-AWS-390",
                       "affected": f"{_no_term_count} stack(s)",
                       "remediation": "aws cloudformation update-termination-protection --enable-termination-protection --stack-name <name>"},
                 output_file=str(out_dir / "cloudformation_stacks.json"))
    else:
        log("[aws] All CloudFormation stacks have termination protection")
    log("[aws] CloudFormation audit complete")

    # ── Bedrock ───────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting Bedrock audit...")
    status("aws", "Bedrock audit", "running")
    _br_log = _aws_run(["bedrock", "get-model-invocation-logging-configuration"],
                        "bedrock_logging.json") or {}
    _br_log_cfg = _br_log.get("loggingConfig") or {}
    if not _br_log_cfg:
        if "bedrock" not in _denied_services:
            log("[aws] Bedrock model invocation logging not configured (MEDIUM)")
            finding(title="Bedrock model invocation logging not enabled",
                     severity="MEDIUM",
                     description="Amazon Bedrock does not have model invocation logging configured.",
                     data={"catalogue_id": "FORGE-AWS-400",
                           "remediation": "Configure model invocation logging in Amazon Bedrock settings."},
                     output_file=str(out_dir / "bedrock_logging.json"))
    else:
        log("[aws] Bedrock model invocation logging configured")

    _br_gr = _aws_run(["bedrock", "list-guardrails"], "bedrock_guardrails.json") or {}
    if not (_br_gr.get("guardrails") or []):
        if "bedrock" not in _denied_services:
            log("[aws] No Bedrock guardrails configured (MEDIUM)")
            finding(title="Bedrock: No guardrails configured",
                     severity="MEDIUM",
                     description="No Amazon Bedrock guardrails are configured to enforce content filtering and safety controls.",
                     data={"catalogue_id": "FORGE-AWS-401",
                           "remediation": "Create at least one Bedrock guardrail for content filtering."},
                     output_file=str(out_dir / "bedrock_guardrails.json"))
    else:
        log(f"[aws] Bedrock guardrails: {len(_br_gr.get('guardrails', []))}")

    # FORGE-AWS-402: Bedrock prompt management exists
    _br_prompts = _aws_run(["bedrock-agent", "list-prompts"], "bedrock_prompts.json") or {}
    if not (_br_prompts.get("promptSummaries") or []):
        if "bedrock" not in _denied_services and "bedrock-agent" not in _denied_services:
            log("[aws] No Bedrock prompt management prompts (LOW)")
            finding(title="Bedrock: No prompt management prompts exist",
                     severity="LOW",
                     description="No Amazon Bedrock Prompt Management prompts are configured. Prompt Management "
                                 "enables centralized creation, versioning, and management of prompts for generative AI applications.",
                     data={"catalogue_id": "FORGE-AWS-402",
                           "remediation": "Create prompts in Amazon Bedrock Prompt Management to standardize and version AI interactions."},
                     output_file=str(out_dir / "bedrock_prompts.json"))
    else:
        log(f"[aws] Bedrock prompt management prompts: {len(_br_prompts.get('promptSummaries', []))}")
    log("[aws] Bedrock audit complete")

    # ── SageMaker ─────────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting SageMaker audit...")
    status("aws", "SageMaker audit", "running")

    # FORGE-AWS-440: SageMaker Clarify processing jobs exist
    _sm_clarify = _aws_run(["sagemaker", "list-processing-jobs",
                             "--name-contains", "clarify"], "sagemaker_clarify_jobs.json") or {}
    _sm_clarify_jobs = _sm_clarify.get("ProcessingJobSummaries") or []
    if not _sm_clarify_jobs:
        if "sagemaker" not in _denied_services:
            log("[aws] No SageMaker Clarify processing jobs (LOW)")
            finding(title="SageMaker: No Clarify processing jobs exist",
                     severity="LOW",
                     description="No Amazon SageMaker Clarify processing jobs exist. SageMaker Clarify helps "
                                 "detect bias in ML models and explain model predictions for responsible AI.",
                     data={"catalogue_id": "FORGE-AWS-440",
                           "remediation": "Create SageMaker Clarify processing jobs to evaluate ML models for bias and explainability."},
                     output_file=str(out_dir / "sagemaker_clarify_jobs.json"))
    else:
        log(f"[aws] SageMaker Clarify jobs: {len(_sm_clarify_jobs)}")

    # FORGE-AWS-441: SageMaker monitoring schedule exists
    _sm_monitors = _aws_run(["sagemaker", "list-monitoring-schedules"], "sagemaker_monitoring_schedules.json") or {}
    _sm_sched_list = _sm_monitors.get("MonitoringScheduleSummaries") or []
    if not _sm_sched_list:
        if "sagemaker" not in _denied_services:
            log("[aws] No SageMaker monitoring schedules (LOW)")
            finding(title="SageMaker: No monitoring schedules configured",
                     severity="LOW",
                     description="No Amazon SageMaker monitoring schedules are configured. Model monitoring detects "
                                 "data drift, model drift, and quality degradation in deployed ML models.",
                     data={"catalogue_id": "FORGE-AWS-441",
                           "remediation": "Create a SageMaker Model Monitor monitoring schedule for deployed endpoints."},
                     output_file=str(out_dir / "sagemaker_monitoring_schedules.json"))
    else:
        log(f"[aws] SageMaker monitoring schedules: {len(_sm_sched_list)}")

    # FORGE-AWS-442: SageMaker Model Registry in use (at least one approved model package)
    _sm_mpg = _aws_run(["sagemaker", "list-model-package-groups"], "sagemaker_model_registry.json") or {}
    _sm_groups = _sm_mpg.get("ModelPackageGroupSummaryList") or []
    _has_approved = False
    for _mpg in _sm_groups:
        _mpg_name = _mpg.get("ModelPackageGroupName", "")
        _mp_resp = _aws_run(["sagemaker", "list-model-packages",
                              "--model-package-group-name", _mpg_name,
                              "--model-approval-status", "Approved",
                              "--max-results", "1"],
                             f"sagemaker_mpg_{_mpg_name}_approved.json") or {}
        if _mp_resp.get("ModelPackageSummaryList"):
            _has_approved = True
            break
    if not _has_approved:
        if "sagemaker" not in _denied_services:
            log("[aws] SageMaker Model Registry has no approved model packages (LOW)")
            finding(title="SageMaker: Model Registry has no approved model packages",
                     severity="LOW",
                     description="Amazon SageMaker Model Registry contains no approved model packages. "
                                 "The registry provides a central hub for versioning, approving, and deploying ML models.",
                     data={"catalogue_id": "FORGE-AWS-442",
                           "remediation": "Register and approve model packages in SageMaker Model Registry for governed ML deployment."},
                     output_file=str(out_dir / "sagemaker_model_registry.json"))
    else:
        log(f"[aws] SageMaker Model Registry has approved packages")
    log(f"[aws] SageMaker audit complete")

    # ── DLM ───────────────────────────────────────────────────────────────────
    _check_pause()
    log("[aws] Checking DLM lifecycle policies...")
    _dlm_resp = _aws_run(["dlm", "get-lifecycle-policies"], "dlm_policies.json") or {}
    _dlm_policies = _dlm_resp.get("Policies") or []
    if not _dlm_policies:
        if "dlm" not in _denied_services:
            log("[aws] No DLM EBS snapshot lifecycle policies (MEDIUM)")
            finding(title="DLM: No EBS snapshot lifecycle policies",
                     severity="MEDIUM",
                     description="No Data Lifecycle Manager policies exist for automated EBS snapshot management.",
                     data={"catalogue_id": "FORGE-AWS-410",
                           "remediation": "Create a DLM lifecycle policy for EBS snapshot automation."},
                     output_file=str(out_dir / "dlm_policies.json"))
    else:
        log(f"[aws] DLM lifecycle policies: {len(_dlm_policies)}")

    # ── Auto Scaling ──────────────────────────────────────────────────────────
    _check_pause()
    _save_checkpoint()
    log("[aws] Starting Auto Scaling audit...")
    status("aws", "Auto Scaling audit", "running")
    _asg_resp = _aws_run(["autoscaling", "describe-auto-scaling-groups"], "autoscaling_groups.json") or {}
    _asgs = _asg_resp.get("AutoScalingGroups") or []
    log(f"[aws] Found {len(_asgs)} Auto Scaling group(s)")
    for _asg in _asgs:
        _asg_name = _asg.get("AutoScalingGroupName", "")
        _azs = _asg.get("AvailabilityZones") or []
        if len(_azs) < 2:
            log(f"[aws] ASG {_asg_name} — single AZ ({_azs}) (MEDIUM)")
            finding(title=f"Auto Scaling group in single AZ: {_asg_name}",
                     severity="MEDIUM",
                     description=f"Auto Scaling group {_asg_name} uses only {len(_azs)} Availability Zone(s). "
                                 "Multi-AZ deployment provides high availability.",
                     data={"catalogue_id": "FORGE-AWS-420", "affected": _asg_name,
                           "remediation": "Add additional Availability Zones to the Auto Scaling group."},
                     output_file=str(out_dir / "autoscaling_groups.json"))
        _mip = _asg.get("MixedInstancesPolicy")
        if not _mip:
            log(f"[aws] ASG {_asg_name} — single instance type (MEDIUM)")
            finding(title=f"Auto Scaling group uses single instance type: {_asg_name}",
                     severity="MEDIUM",
                     description=f"Auto Scaling group {_asg_name} does not use a mixed instances policy. "
                                 "Multiple instance types improve availability and cost optimization.",
                     data={"catalogue_id": "FORGE-AWS-421", "affected": _asg_name,
                           "remediation": "Configure a mixed instances policy with multiple instance types."},
                     output_file=str(out_dir / "autoscaling_groups.json"))
    log(f"[aws] Auto Scaling audit complete — checked {len(_asgs)} group(s)")

    # ── Network Firewall ──────────────────────────────────────────────────────
    _check_pause()
    log("[aws] Checking Network Firewall...")
    _nfw_resp = _aws_run(["network-firewall", "list-firewalls"], "networkfirewall_firewalls.json") or {}
    _nfw_firewalls = _nfw_resp.get("Firewalls") or []
    if not _nfw_firewalls:
        if "network-firewall" not in _denied_services:
            log("[aws] No Network Firewalls deployed (MEDIUM)")
            finding(title="Network Firewall: No firewalls deployed",
                     severity="MEDIUM",
                     description="No AWS Network Firewalls are deployed. Network traffic inspection and filtering is absent.",
                     data={"catalogue_id": "FORGE-AWS-430",
                           "remediation": "Deploy AWS Network Firewall for VPC traffic inspection."},
                     output_file=str(out_dir / "networkfirewall_firewalls.json"))
    else:
        log(f"[aws] Network Firewalls: {len(_nfw_firewalls)}")


    # ── Final intelligence refresh ──────────────────────────────────────────
    _check_pause()
    log("[aws] Final intelligence refresh...")
    status("aws", "Intelligence generation", "running")
    _refresh_intel()

    # ── AccessDenied summary ────────────────────────────────────────────────
    if _denied_services:
        svc_list = ", ".join(sorted(_denied_services))
        log(f"[aws] AccessDenied for {len(_denied_services)} service(s): {svc_list}")
        finding(title=f"Scope Limitations: Insufficient permissions for {len(_denied_services)} AWS service(s)",
                 severity="INFO",
                 description=f"The audit credentials lack permissions for the following AWS "
                             f"service(s), so their configuration could not be fully assessed: "
                             f"{svc_list}. Findings for these services may be incomplete.",
                 data={"catalogue_id": "FORGE-AWS-900",
                       "affected": svc_list,
                       "remediation": "Grant the audit IAM user/role read-only access to these services."})

    log(f"[aws] AWS audit complete — profile={profile or 'default'}, region={region}")
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
