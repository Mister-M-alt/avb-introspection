#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Kebag-Logic
# SPDX-License-Identifier: MIT
"""Browser end-to-end tests (TV-4): drives the real UI with Playwright.

Starts its own backend on a random port with a scratch data directory,
then walks the full user journey in a headless browser (Firefox by
default — the FE-1 reference target):

  register -> login -> upload pcap -> analysis -> events table ->
  packet inspector -> state view -> investigation notes (edit, save,
  persist across reload) -> logout -> login again

Usage:
  python3 scripts/e2e_playwright.py [--browser firefox|chromium] [--headed]

Requires: pip install playwright && playwright install firefox
On non-Ubuntu hosts set PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
(this script sets it itself).
"""
import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS", "true")

from playwright.sync_api import expect, sync_playwright  # noqa: E402

USER = "e2e-user"
PASSWORD = "correct-horse-9"
NOTE_TEXT = "# E2E notes\n\nEdited **by** the browser test.\n"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"backend did not listen on :{port}")


def run_tests(page, url):
    console_errors = []
    page.on("console",
            lambda m: console_errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: console_errors.append(str(e)))

    # ---- register + auto-login -------------------------------------------
    page.goto(url)
    expect(page.locator("#f-pass")).to_be_visible()
    page.get_by_text("No account? Register").click()
    page.locator("#f-user").fill(USER)
    page.locator("#f-pass").fill(PASSWORD)
    page.locator("button[type=submit]").click()

    # Home view after auto-login.
    expect(page.locator("#userbox")).to_be_visible()
    expect(page.locator("#user-name")).to_have_text(USER)

    # ---- upload a golden capture -----------------------------------------
    pcap = os.path.join(ROOT, "testdata", "milan_scenario.pcap")
    page.locator("input[type=file]").set_input_files(pcap)

    # Upload triggers session creation and navigation to the session view.
    page.wait_for_url("**/#/session/*", timeout=15000)

    # ---- analysis completes, events arrive -------------------------------
    expect(page.locator(".toolbar .sbadge")).to_have_text("done",
                                                          timeout=30000)
    rows = page.locator(".erow")
    expect(rows.first).to_be_visible(timeout=15000)
    count = rows.count()  # table is virtualized: visible window only
    assert count > 10, f"expected >10 rendered event rows, got {count}"

    # Timeline canvas rendered; GPTP is a first-class protocol chip.
    canvas = page.locator(".session-view canvas").first
    expect(canvas).to_be_visible()
    assert page.locator(".chip", has_text="GPTP").count() >= 1, \
        "GPTP filter chip missing"

    # Click-to-focus: zoom into the start of the capture, then select a late
    # table row — the timeline viewport (exposed via data-t0/t1) must pan.
    expect(canvas).to_have_attribute("data-t1", re.compile(r".+"),
                                     timeout=10000)
    canvas.hover(position={"x": 300, "y": 30})
    page.mouse.wheel(0, -800)  # zoom in around the hovered time
    page.wait_for_timeout(150)
    t1_zoomed = float(canvas.get_attribute("data-t1"))
    page.locator(".etable-body").evaluate("el => { el.scrollTop = el.scrollHeight; }")
    page.wait_for_timeout(150)
    page.locator(".erow").last.click()  # a late event, outside the zoom window
    page.wait_for_timeout(150)
    t1_after = float(canvas.get_attribute("data-t1"))
    assert t1_after > t1_zoomed, \
        f"timeline did not pan to the selected event " \
        f"(t1 stayed at {t1_after} <= {t1_zoomed})"

    # ---- packet inspector -------------------------------------------------
    rows.first.click()
    expect(page.get_by_text("ethernet_mac_frame").first).to_be_visible(
        timeout=10000)

    # ---- state view --------------------------------------------------------
    page.get_by_role("button", name="State", exact=True).click()
    expect(page.get_by_text("Stage Box FOH").first).to_be_visible(timeout=10000)
    expect(page.get_by_text("Monitor Desk").first).to_be_visible()
    expect(page.get_by_text("DISCONNECTED").first).to_be_visible()
    # Milan v1.2 sections render (the scenario contains a BIND flow).
    expect(page.get_by_text("Milan listener sinks", exact=False).first
           ).to_be_visible()
    expect(page.get_by_text("Milan talker sources", exact=False).first
           ).to_be_visible()

    # ---- time display mode (rel seconds <-> local time-of-day + ns) --------
    ts_cell = page.locator(".erow .c-ts").first
    expect(ts_cell).to_be_visible()
    assert ts_cell.inner_text().endswith("s"), "rel mode should show seconds"
    page.locator('#time-mode button[data-mode="tod"]').click()
    expect(ts_cell).to_have_text(
        re.compile(r"^([01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{9}$"), timeout=5000)
    page.locator('#time-mode button[data-mode="rel"]').click()

    # ---- info tab: file/capture metadata + device rename --------------------
    page.locator("#tab-info").click()
    expect(page.get_by_text("Devices", exact=False).first).to_be_visible(
        timeout=10000)
    name_input = page.locator('input.dev-name[data-mac="00:1b:92:00:00:01"]')
    expect(name_input).to_be_visible()
    name_input.fill("FOH Rack")
    name_input.press("Enter")
    page.wait_for_timeout(300)
    # The user-set name propagates into the events table SRC column.
    expect(page.locator(".erow .c-src", has_text="FOH Rack").first
           ).to_be_visible(timeout=5000)

    # ---- investigation notes (FE-9/BE-9) -----------------------------------
    page.locator("#tab-notes").click()
    notes = page.locator("#notes-editor")
    expect(notes).to_be_visible(timeout=10000)
    expect(notes).to_be_enabled(timeout=10000)
    assert notes.input_value().startswith("# Investigation:"), \
        "notes not seeded with template"
    notes.fill(NOTE_TEXT)
    expect(page.locator("#notes-status")).to_have_attribute("data-state",
                                                            "dirty")
    page.locator("#notes-save").click()
    expect(page.locator("#notes-status")).to_have_attribute(
        "data-state", "saved", timeout=10000)

    # Markdown preview renders (escaped, no live HTML).
    page.locator("#notes-preview-toggle").click()
    expect(page.locator("#notes-preview h1")).to_have_text("E2E notes")
    expect(page.locator("#notes-preview strong")).to_have_text("by")
    page.locator("#notes-preview-toggle").click()

    # Persisted: reload the app, notes still there.
    page.reload()
    page.locator("#tab-notes").click()
    notes = page.locator("#notes-editor")
    expect(notes).to_be_enabled(timeout=10000)
    assert notes.input_value() == NOTE_TEXT, "notes lost after reload"

    # ---- presence: the header shows who is where ----------------------------
    expect(page.locator("#presence")).to_be_visible()
    expect(page.locator("#presence-count")).to_have_text(
        re.compile(r"[1-9]"), timeout=15000)
    page.locator("#presence").hover()
    expect(page.locator(
        f'#presence-list .presence-entry[data-user="{USER}"]').first
           ).to_be_visible(timeout=10000)
    page.mouse.move(400, 400)  # leave the popover area

    # ---- notes conflict: stale rev -> banner -> take theirs ----------------
    page.locator("#tab-notes").click()
    notes = page.locator("#notes-editor")
    expect(notes).to_be_enabled(timeout=10000)
    # Sabotage from "another user": rewrite the notes behind the UI's back.
    page.evaluate(
        """async ([sid, tok]) => {
             await fetch(`api/sessions/${sid}/notes`, {
               method: 'PUT',
               headers: {'Authorization': 'Bearer ' + tok,
                         'Content-Type': 'application/json'},
               body: JSON.stringify({markdown: '# Someone else was here\\n'}),
             });
           }""",
        [page.url.split("session/")[1],
         page.evaluate("localStorage.getItem('avb.token')")])
    notes.fill("# My conflicting edit\n")
    page.locator("#notes-save").click()
    expect(page.locator("#notes-conflict")).to_be_visible(timeout=10000)
    page.locator("#notes-take-theirs").click()
    expect(page.locator("#notes-conflict")).to_be_hidden()
    assert notes.input_value().startswith("# Someone else was here"), \
        "take-theirs did not adopt the other content"

    # ---- logout / login round trip -----------------------------------------
    page.locator("#logout-btn").click()
    expect(page.locator("#f-pass")).to_be_visible()
    page.locator("#f-user").fill(USER)
    page.locator("#f-pass").fill(PASSWORD)
    page.locator("button[type=submit]").click()
    expect(page.get_by_text("milan_scenario.pcap").first).to_be_visible(
        timeout=10000)
    # Regular users see no admin entry.
    expect(page.locator("#admin-link")).to_be_hidden()

    # ---- admin panel ---------------------------------------------------------
    page.locator("#logout-btn").click()
    expect(page.locator("#f-pass")).to_be_visible()
    page.locator("#f-user").fill("admin")
    page.locator("#f-pass").fill("admin-pass-123")
    page.locator("button[type=submit]").click()
    expect(page.locator("#admin-link")).to_be_visible(timeout=10000)
    page.locator("#admin-link").click()
    expect(page.locator(f'.aurow[data-user="{USER}"]')).to_be_visible(
        timeout=10000)
    # Create and delete a user through the panel.
    page.locator("#admin-new-user").fill("panel-user")
    page.locator("#admin-new-pass").fill("panel-pass-123")
    page.locator("#admin-create").click()
    expect(page.locator('.aurow[data-user="panel-user"]')).to_be_visible(
        timeout=10000)
    page.on("dialog", lambda d: d.accept())
    page.locator('button.admin-del[data-user="panel-user"]').click()
    expect(page.locator('.aurow[data-user="panel-user"]')).to_be_hidden(
        timeout=10000)

    # ---- no console errors --------------------------------------------------
    benign = [e for e in console_errors if "favicon" in e.lower()]
    real = [e for e in console_errors if e not in benign]
    assert not real, f"console errors: {real}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", default="firefox",
                    choices=["firefox", "chromium"])
    ap.add_argument("--headed", action="store_true")
    args = ap.parse_args()

    binary = os.path.join(ROOT, "build", "avb-introspectd")
    if not os.path.exists(binary):
        subprocess.check_call(["make", "-j", "build/avb-introspectd"], cwd=ROOT)
    pcap = os.path.join(ROOT, "testdata", "milan_scenario.pcap")
    if not os.path.exists(pcap):
        subprocess.check_call([sys.executable, "tools/gen_pcaps.py"], cwd=ROOT)

    port = free_port()
    data_dir = tempfile.mkdtemp(prefix="avb-e2e.")
    server = subprocess.Popen(
        [binary, "--port", str(port), "--data", data_dir,
         "--frontend", os.path.join(ROOT, "frontend")],
        env={**os.environ, "AVB_ADMIN_USER": "admin",
             "AVB_ADMIN_PASSWORD": "admin-pass-123"},
        stdout=subprocess.DEVNULL)
    try:
        wait_port(port)
        with sync_playwright() as p:
            browser = getattr(p, args.browser).launch(headless=not args.headed)
            page = browser.new_context(
                viewport={"width": 1400, "height": 900}).new_page()
            try:
                run_tests(page, f"http://127.0.0.1:{port}/")
                print("E2E OK")
            except Exception:
                shot = os.path.join(ROOT, "build", "e2e-failure.png")
                try:
                    page.screenshot(path=shot, full_page=True)
                    print(f"screenshot: {shot}", file=sys.stderr)
                except Exception:
                    pass
                raise
            finally:
                browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
        shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
