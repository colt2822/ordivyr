#!/usr/bin/env python3
"""Drive the real dashboard in headless Chrome against a real `ordivyr-board` and a scripted local model (no GPU, no spend).

    python scripts/dashboard_smoke.py        # uses whichever ordivyr this Python imports; needs `pip install websocket-client` and Chrome/Chromium

Checks: every tab renders, typed input survives the 5 s refresh, a job launched from the form writes into its workspace folder, no script exceptions.
Exit 0 = pass, 1 = fail, 2 = skipped (missing Chrome or websocket-client).
"""
import json, os, shutil, subprocess, sys, tempfile, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try: import websocket
except ImportError: print("skip: pip install websocket-client"); sys.exit(2)
CHROME = next((p for p in map(shutil.which, ("google-chrome", "chromium", "chromium-browser")) if p and not p.startswith("/snap/")), None)      # snap cannot write a profile under /tmp
if not CHROME: print("skip: no Chrome/Chromium found"); sys.exit(2)


class Model(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a): pass

    def do_POST(self):
        r = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if any(m["role"] == "tool" for m in r["messages"]): msg = {"role": "assistant", "content": "wrote it"}
        else: msg = {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "write_file", "arguments": json.dumps({"path": "hello.txt", "content": "hi\n"})}}]}
        b = json.dumps({"id": "x", "model": r.get("model"), "choices": [{"index": 0, "message": msg, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)


def wait(fn, what, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        r = fn()
        if r: return r
        time.sleep(0.1)
    raise AssertionError("timed out waiting for " + what)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="board-smoke-")); home = tmp / "home"; procs = []
    model = ThreadingHTTPServer(("127.0.0.1", 0), Model); threading.Thread(target=model.serve_forever, daemon=True).start()
    env = {k: v for k, v in os.environ.items() if not k.startswith("BOARD_")}
    board = [sys.executable, "-m", "ordivyr.board"]
    try:
        subprocess.run([*board, "init", "--home", str(home), "--model", "stub", "--base-url", f"http://127.0.0.1:{model.server_address[1]}/v1"], check=True, capture_output=True, env=env)
        up = subprocess.Popen([*board, "up", "--home", str(home), "--port", "0", "--lease-port", "0", "--access-log", str(tmp / "access.log")], stdout=subprocess.PIPE, text=True, env=env); procs.append(up)
        url = json.loads(up.stdout.readline())["api"]
        procs.append(subprocess.Popen([CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--remote-debugging-port=0", "--remote-allow-origins=*", f"--user-data-dir={tmp / 'chrome'}", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        portfile = tmp / "chrome" / "DevToolsActivePort"
        port = wait(lambda: portfile.is_file() and portfile.read_text().split()[0], "Chrome")
        page = wait(lambda: next((t for t in json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json")) if t["type"] == "page"), None), "a tab")
        ws = websocket.create_connection(page["webSocketDebuggerUrl"], timeout=20); n = 0; errors = []

        def cmd(method, **params):
            nonlocal n
            n += 1; ws.send(json.dumps({"id": n, "method": method, "params": params}))
            while True:
                r = json.loads(ws.recv())
                if r.get("method") == "Runtime.exceptionThrown": errors.append(json.dumps(r["params"])[:400])
                if r.get("id") == n: return r.get("result", r)

        def js(expr):
            r = cmd("Runtime.evaluate", expression=expr, returnByValue=True)
            assert "exceptionDetails" not in r, (expr, r["exceptionDetails"])
            return r["result"].get("value")

        def tab(name): js(f"[...document.querySelectorAll('#tabs button')].find(b => b.textContent === {json.dumps(name)}).click()")

        cmd("Runtime.enable"); cmd("Page.navigate", url=url + "/")
        button = "[...document.querySelectorAll('#view button')].find(b => b.textContent === 'Use API key')"
        wait(lambda: js("!!" + button), "the sign-in form")
        key = (home / "admin.token").read_text().strip()
        js(f"(() => {{ const f = {button}.form; f.querySelector('input').value = {json.dumps(key)}; f.requestSubmit(); }})()")
        names = wait(lambda: js("[...document.querySelectorAll('#tabs button')].map(b => b.textContent)"), "tabs")
        for name in names:
            tab(name); time.sleep(0.6)
            heads = js("[...document.querySelectorAll('#view h2')].map(h => h.textContent)")
            assert heads and "Houston, we have a problem" not in heads, (name, js("document.querySelector('#view').innerText.slice(0, 300)"))
            print("ok tab", name)
        tab("Jobs"); wait(lambda: js("!!document.querySelector('#view textarea')"), "the launch form")
        workspace = "[...document.querySelectorAll('#view input')].find(i => i.placeholder === 'my-app')"
        js(f"(() => {{ for (const [e, t] of [[document.querySelector('#view textarea'), 'write hello'], [{workspace}, 'my-app']]) {{ e.value = t; e.dispatchEvent(new Event('input', {{bubbles: true}})); e.blur(); }} }})()")
        time.sleep(6)
        assert js("document.querySelector('#view textarea').value") == "write hello" and js(workspace + ".value") == "my-app", "typed input was lost on refresh"
        print("ok draft survives refresh")
        js("document.querySelector('#view textarea').form.requestSubmit()")
        wait(lambda: (home / "ws/board/local/main/my-app/hello.txt").is_file(), "the workspace file")
        wait(lambda: js("document.querySelector('#view textarea') && document.querySelector('#view textarea').value === ''"), "the form to clear")
        print("ok job launched from the form wrote into its workspace")
        assert not errors, errors
        print("PASS"); return 0
    finally:
        for p in reversed(procs):
            p.terminate()
            try: p.wait(20)
            except subprocess.TimeoutExpired: p.kill()
        model.shutdown(); shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__": sys.exit(main())
