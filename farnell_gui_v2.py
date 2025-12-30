import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import csv
import time
import threading
import requests
import os
import json
from datetime import datetime
from cryptography.fernet import Fernet

# ================== CONFIG ==================
BASE_URL = "https://api.element14.com/catalog/products"
STORE_ID = "uk.farnell.com"

REQUEST_TIMEOUT = 30
RATE_LIMIT_DELAY = 0.6  # 2 calls/sec safe
DAILY_QUOTA = 1000

APP_DIR = os.path.join(os.path.expanduser("~"), ".farnell_gui")
KEY_FILE = os.path.join(APP_DIR, "key.key")
CONFIG_FILE = os.path.join(APP_DIR, "config.enc")
# ============================================


# ---------- Encryption ----------
def load_cipher():
    os.makedirs(APP_DIR, exist_ok=True)
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)


# ---------- Farnell API ----------
def lookup_farnell(part_number: str, api_key: str):
    pn = part_number.strip()
    is_keyword = pn.isdigit()

    term = f"any:{pn}" if is_keyword else f"manuPartNum:{pn}"

    params = {
        "term": term,
        "storeInfo.id": STORE_ID,
        "resultsSettings.responseGroup": "small",
        "callInfo.apiKey": api_key,
        "callInfo.responseDataFormat": "JSON"
    }

    if is_keyword:
        params["resultsSettings.offset"] = 0
        params["resultsSettings.numberOfResults"] = 1

    r = requests.get(
        BASE_URL,
        params=params,
        headers={
            "Accept": "application/json",
            "User-Agent": "FarnellLookupGUI/1.0"
        },
        timeout=REQUEST_TIMEOUT
    )

    if r.status_code != 200:
        return "", "", f"API_ERROR_{r.status_code}"

    data = r.json()

    if is_keyword:
        products = data.get("keywordSearchReturn", {}).get("products", [])
    else:
        products = data.get("manufacturerPartNumberSearchReturn", {}).get("products", [])

    if not products:
        return "", "", "NO_RESULTS"

    p = products[0]
    return (
        p.get("brandName", ""),
        p.get("translatedManufacturerPartNumber", ""),
        "OK"
    )


# ---------- GUI ----------
class FarnellGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Farnell API Lookup Tool")
        self.root.geometry("780x600")
        self.root.resizable(False, False)

        self.api_key = tk.StringVar()
        self.remember = tk.BooleanVar()
        self.input_csv = tk.StringVar()

        self.stop_requested = False
        self.calls_made = 0

        self.cipher = load_cipher()
        self.load_config()
        self.build_ui()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="Farnell API Lookup Tool", font=("Segoe UI", 14, "bold")).pack(anchor="w")

        creds = ttk.LabelFrame(main, text="API Key", padding=10)
        creds.pack(fill="x", pady=10)

        ttk.Label(creds, text="Farnell API Key").grid(row=0, column=0, sticky="w")
        ttk.Entry(creds, textvariable=self.api_key, width=60, show="*").grid(row=0, column=1)

        ttk.Checkbutton(
            creds,
            text="Remember API key (encrypted)",
            variable=self.remember
        ).grid(row=1, column=1, sticky="w", pady=(6, 0))

        files = ttk.LabelFrame(main, text="Input", padding=10)
        files.pack(fill="x")

        ttk.Button(files, text="Browse CSV", command=self.pick_input).grid(row=0, column=0)
        ttk.Entry(files, textvariable=self.input_csv, width=60).grid(row=0, column=1, padx=6)

        btns = ttk.Frame(main)
        btns.pack(pady=8)

        self.run_btn = ttk.Button(btns, text="Run Lookup", command=self.run)
        self.run_btn.grid(row=0, column=0, padx=6)

        self.cancel_btn = ttk.Button(btns, text="Cancel", command=self.cancel, state="disabled")
        self.cancel_btn.grid(row=0, column=1, padx=6)

        self.quota_label = ttk.Label(main, text="Calls used: 0 / 1000")
        self.quota_label.pack(anchor="w", pady=(4, 0))

        self.progress = ttk.Progressbar(main, length=740, mode="determinate")
        self.progress.pack(pady=4)

        self.log = scrolledtext.ScrolledText(main, height=16, font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)

    def log_msg(self, msg):
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)

    def pick_input(self):
        path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if path:
            self.input_csv.set(path)

    def save_config(self):
        if not self.remember.get():
            return
        data = json.dumps({"api_key": self.api_key.get()}).encode()
        enc = self.cipher.encrypt(data)
        with open(CONFIG_FILE, "wb") as f:
            f.write(enc)

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "rb") as f:
                data = self.cipher.decrypt(f.read())
                cfg = json.loads(data.decode())
                self.api_key.set(cfg.get("api_key", ""))
                self.remember.set(True)

    # ---------- Controls ----------
    def cancel(self):
        self.stop_requested = True
        self.log_msg("Cancel requested…")

    def run(self):
        if not self.api_key.get() or not self.input_csv.get():
            messagebox.showerror("Missing data", "API key and input CSV are required.")
            return

        self.stop_requested = False
        self.calls_made = 0

        self.run_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.progress["value"] = 0
        self.log.delete("1.0", tk.END)

        threading.Thread(target=self.run_worker, daemon=True).start()

    def run_worker(self):
        try:
            self.save_config()

            input_path = self.input_csv.get()
            output_path = os.path.join(
                os.path.dirname(input_path),
                f"farnell_output_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
            )

            with open(input_path, newline="", encoding="utf-8-sig") as f:
                rows = list(csv.DictReader(f))

            total = len(rows)
            self.root.after(0, lambda: self.progress.config(maximum=total))

            with open(output_path, "w", newline="", encoding="utf-8") as f_out:
                writer = csv.DictWriter(
                    f_out,
                    fieldnames=["Input_PN", "Manufacturer", "MPN", "Status"]
                )
                writer.writeheader()

                for i, row in enumerate(rows, 1):
                    if self.stop_requested:
                        break

                    pn = row.get("Input_PN", "").strip()

                    try:
                        mfr, mpn, status = lookup_farnell(pn, self.api_key.get())
                    except Exception:
                        mfr = mpn = ""
                        status = "EXCEPTION"

                    self.calls_made += 1

                    self.root.after(0, lambda i=i, pn=pn, mfr=mfr, mpn=mpn, st=status:
                        self.log_msg(f"[{i}/{total}] {pn} → {st} | {mfr} | {mpn}")
                    )

                    writer.writerow({
                        "Input_PN": pn,
                        "Manufacturer": mfr,
                        "MPN": mpn,
                        "Status": status
                    })

                    self.root.after(0, lambda i=i:
                        self.progress.config(value=i)
                    )

                    self.root.after(0, lambda:
                        self.quota_label.config(
                            text=f"Calls used: {self.calls_made} / {DAILY_QUOTA}"
                        )
                    )

                    time.sleep(RATE_LIMIT_DELAY)

            self.root.after(0, lambda: self.finish(output_path))

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, lambda: self.reset_buttons())

    def finish(self, output_path):
        self.reset_buttons()
        self.log_msg(f"\nDone! Output saved to:\n{output_path}")
        messagebox.showinfo("Completed", f"Output file created:\n{output_path}")

    def reset_buttons(self):
        self.run_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")


# ---------- Launch ----------
if __name__ == "__main__":
    root = tk.Tk()
    FarnellGUI(root)
    root.mainloop()
