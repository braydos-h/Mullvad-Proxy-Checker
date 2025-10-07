import re
import sys
import csv
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_TITLE = "SOCKS5 Proxy Checker (curl)"
CURL_TIMEOUT = 12  # seconds per request
MAX_WORKERS = 32   # parallel checks
DEFAULT_PORT = 1080

MULLVAD_PATTERN = re.compile(r"You are connected to Mullvad \(server ([^)]+)\)\. Your IP address is ([0-9.]+)")
IPV4_PATTERN = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
INTERNAL_PATTERN = re.compile(r"\b(10\.124\.\d+\.\d+)\b")

# --------------------------
# Core checking logic
# --------------------------

def run_curl(args):
    """Run curl with given args list. Returns (returncode, stdout str)."""
    try:
        proc = subprocess.run(
            ["curl", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CURL_TIMEOUT,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        raise RuntimeError("'curl' not found. On Windows 10+, curl.exe is built-in. Ensure it's in PATH.")
    except subprocess.TimeoutExpired:
        return 124, "", "Timeout"


def check_proxy(ip: str, stop_event: threading.Event):
    """Check a single SOCKS5 proxy at ip:DEFAULT_PORT. Returns result dict."""
    if stop_event.is_set():
        return {"ip": ip, "works": False, "mullvad": None, "public_ip": None, "server": None, "note": "cancelled"}

    proxy = f"{ip}:{DEFAULT_PORT}"

    # 1) Quick reachability test via ipify (HTTPS)
    rc, out, err = run_curl(["--socks5", proxy, "-sS", "--max-time", str(CURL_TIMEOUT), "https://api.ipify.org"])
    if stop_event.is_set():
        return {"ip": ip, "works": False, "mullvad": None, "public_ip": None, "server": None, "note": "cancelled"}

    if rc == 0 and IPV4_PATTERN.match(out or ""):
        public_ip = out.strip()
        works = True
    else:
        # Not reachable as SOCKS5 (or failed TLS). Try plain HTTP fallback to reduce false negatives.
        rc2, out2, err2 = run_curl(["--socks5", proxy, "-sS", "--max-time", str(CURL_TIMEOUT), "http://ifconfig.me"])
        if rc2 == 0 and IPV4_PATTERN.match(out2 or ""):
            public_ip = out2.strip()
            works = True
        else:
            note = err or err2 or "unreachable"
            return {"ip": ip, "works": False, "mullvad": None, "public_ip": None, "server": None, "note": note[:200]}

    # 2) If it works, check Mullvad endpoint
    rc3, out3, err3 = run_curl(["--socks5", proxy, "-sS", "--max-time", str(CURL_TIMEOUT), "https://am.i.mullvad.net/connected"])
    mullvad = None
    server = None
    mullvad_ip = None

    if rc3 == 0 and out3:
        m = MULLVAD_PATTERN.search(out3)
        if m:
            server = m.group(1)
            mullvad_ip = m.group(2)
            mullvad = True
        elif "not connected" in out3.lower():
            mullvad = False
        else:
            # Content returned but unrecognized — still counts as reachable
            mullvad = False
    else:
        # Mullvad endpoint failed but proxy worked for ipify.
        mullvad = False

    return {
        "ip": ip,
        "works": works,
        "mullvad": mullvad,
        "public_ip": mullvad_ip or public_ip,
        "server": server,
        "note": ""
    }


# --------------------------
# GUI
# --------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1050x650")
        self.minsize(950, 580)
        try:
            self.iconbitmap(False, "")  # ignore if default icon is fine
        except Exception:
            pass

        self.stop_event = threading.Event()
        self.executor = None
        self.total = 0
        self.completed = 0

        self._build_ui()

    def _build_ui(self):
        # Top controls
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=10, pady=8)

        ttk.Label(top, text="Paste your proxy list below (any text). We'll extract all 10.124.*.* addresses.").pack(side=tk.LEFT)

        btn_frame = ttk.Frame(top)
        btn_frame.pack(side=tk.RIGHT)
        self.start_btn = ttk.Button(btn_frame, text="Start", command=self.start_checks)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_checks, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        self.export_btn = ttk.Button(btn_frame, text="Export CSV", command=self.export_csv, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = ttk.Button(btn_frame, text="Clear", command=self.clear_all)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        self.load_btn = ttk.Button(btn_frame, text="Load File…", command=self.load_file)
        self.load_btn.pack(side=tk.LEFT, padx=5)

        # Text input
        self.text = tk.Text(self, height=10, wrap=tk.NONE)
        self.text.pack(fill=tk.X, padx=10)

        # Results tree
        cols = ("ip", "works", "mullvad", "server", "public_ip", "note")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=16)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self.tree.heading("ip", text="Proxy (10.124.x.x:1080)")
        self.tree.heading("works", text="Works")
        self.tree.heading("mullvad", text="Mullvad")
        self.tree.heading("server", text="Server")
        self.tree.heading("public_ip", text="Public IP")
        self.tree.heading("note", text="Notes")

        self.tree.column("ip", width=200)
        self.tree.column("works", width=80, anchor=tk.CENTER)
        self.tree.column("mullvad", width=80, anchor=tk.CENTER)
        self.tree.column("server", width=200)
        self.tree.column("public_ip", width=140)
        self.tree.column("note", width=250)

        # Color tags
        try:
            self.tree.tag_configure("ok", background="#d1fadf", foreground="#0f5132")     # greenish
            self.tree.tag_configure("warn", background="#fff3cd", foreground="#664d03")   # yellowish
            self.tree.tag_configure("fail", background="#f8d7da", foreground="#842029")   # reddish
        except Exception:
            pass

        # Status bar
        status = ttk.Frame(self)
        status.pack(fill=tk.X, padx=10, pady=(0,10))
        self.progress = ttk.Progressbar(status, mode="determinate")
        self.progress.pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.status_label = ttk.Label(status, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=10)

    def parse_ips(self):
        raw = self.text.get("1.0", tk.END)
        ips = set(INTERNAL_PATTERN.findall(raw))
        # Sort numerically
        def keyf(ip):
            return tuple(map(int, ip.split('.')))
        return sorted(ips, key=keyf)

    def start_checks(self):
        ips = self.parse_ips()
        if not ips:
            messagebox.showwarning(APP_TITLE, "No 10.124.*.* addresses found. Paste your list first.")
            return

        # Prepare UI
        self.tree.delete(*self.tree.get_children())
        self.stop_event.clear()
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.export_btn.configure(state=tk.DISABLED)

        self.total = len(ips)
        self.completed = 0
        self.progress.configure(maximum=self.total, value=0)
        self.status_label.configure(text=f"Checking {self.total} proxies…")

        # Kick off background thread to manage the pool
        threading.Thread(target=self._run_checks, args=(ips,), daemon=True).start()

    def _run_checks(self, ips):
        results = []
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
                futures = {ex.submit(check_proxy, ip, self.stop_event): ip for ip in ips}
                for fut in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    try:
                        res = fut.result()
                    except Exception as e:
                        ip = futures[fut]
                        res = {"ip": ip, "works": False, "mullvad": None, "public_ip": None, "server": None, "note": str(e)[:200]}
                    results.append(res)
                    self.completed += 1
                    self._add_result_row(res)
                    self._update_progress()
        finally:
            self._checks_done()
            self.results = results

    def _add_result_row(self, res):
        ip = res["ip"]
        works = "Yes" if res["works"] else "No"
        mullvad = "Yes" if res["mullvad"] else ("No" if res["mullvad"] is False else "?")
        server = res["server"] or ""
        public_ip = res["public_ip"] or ""
        note = res["note"] or ""

        # Tag logic
        if res["works"] and res["mullvad"]:
            tag = "ok"
        elif res["works"] and (res["mullvad"] is False):
            tag = "warn"
        else:
            tag = "fail"

        self.tree.insert("", tk.END, values=(f"{ip}:{DEFAULT_PORT}", works, mullvad, server, public_ip, note), tags=(tag,))

    def _update_progress(self):
        self.progress.configure(value=self.completed)
        self.status_label.configure(text=f"Checked {self.completed}/{self.total}")

    def _checks_done(self):
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.export_btn.configure(state=tk.NORMAL)
        self.status_label.configure(text=f"Done at {datetime.now().strftime('%H:%M:%S')}")

    def stop_checks(self):
        self.stop_event.set()
        self.status_label.configure(text="Stopping… (finishing in-flight checks)")

    def export_csv(self):
        if not hasattr(self, "results") or not self.results:
            messagebox.showinfo(APP_TITLE, "No results to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", ".csv"), ("All files", ".*")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["proxy", "works", "mullvad", "server", "public_ip", "note"]) 
            for r in self.results:
                w.writerow([f"{r['ip']}:{DEFAULT_PORT}", r["works"], r["mullvad"], r.get("server") or "", r.get("public_ip") or "", r.get("note") or ""]) 
        messagebox.showinfo(APP_TITLE, f"Saved {len(self.results)} rows to {path}")

    def clear_all(self):
        self.text.delete("1.0", tk.END)
        self.tree.delete(*self.tree.get_children())
        self.progress.configure(value=0)
        self.status_label.configure(text="Ready")
        self.export_btn.configure(state=tk.DISABLED)

    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", ".txt .log .cfg .csv"), ("All files", ".*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read()
            self.text.delete("1.0", tk.END)
            self.text.insert("1.0", data)
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Couldn't load file: {e}")


def main():
    # Quick preflight: check for curl availability
    try:
        subprocess.run(["curl", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except FileNotFoundError:
        messagebox.showerror(APP_TITLE, "'curl' not found. On Windows 10+, curl.exe is built-in; otherwise install curl and ensure it's on PATH.")
        sys.exit(1)

    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
