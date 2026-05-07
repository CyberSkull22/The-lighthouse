import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess
import sys
import os

def run_scan():
    target = target_entry.get()
    ports = ports_entry.get()
    concurrency = concurrency_entry.get()
    timeout = timeout_entry.get()
    output = output_entry.get()

    if not target:
        messagebox.showerror("Error", "Please enter a target.")
        return

    cmd = [sys.executable, "main.py", target]
    if ports:
        cmd.extend(["-p", ports])
    if concurrency:
        cmd.extend(["-c", concurrency])
    if timeout:
        cmd.extend(["-t", timeout])
    if output:
        cmd.extend(["--output", output])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(__file__))
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, result.stdout)
        if result.stderr:
            output_text.insert(tk.END, "\nErrors:\n" + result.stderr)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def select_output_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")])
    if file_path:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, file_path)

root = tk.Tk()
root.title("The Lighthouse GUI")

tk.Label(root, text="Target IP/Hostname:").grid(row=0, column=0, sticky="w")
target_entry = tk.Entry(root, width=30)
target_entry.grid(row=0, column=1)

tk.Label(root, text="Ports (e.g., 1-100 or 22,80):").grid(row=1, column=0, sticky="w")
ports_entry = tk.Entry(root, width=30)
ports_entry.grid(row=1, column=1)

tk.Label(root, text="Concurrency:").grid(row=2, column=0, sticky="w")
concurrency_entry = tk.Entry(root, width=30)
concurrency_entry.insert(0, "200")
concurrency_entry.grid(row=2, column=1)

tk.Label(root, text="Timeout:").grid(row=3, column=0, sticky="w")
timeout_entry = tk.Entry(root, width=30)
timeout_entry.insert(0, "1.0")
timeout_entry.grid(row=3, column=1)

tk.Label(root, text="Output File:").grid(row=4, column=0, sticky="w")
output_entry = tk.Entry(root, width=30)
output_entry.grid(row=4, column=1)
tk.Button(root, text="Browse", command=select_output_file).grid(row=4, column=2)

tk.Button(root, text="Scan", command=run_scan).grid(row=5, column=0, columnspan=3)

output_text = tk.Text(root, height=20, width=80)
output_text.grid(row=6, column=0, columnspan=3)

root.mainloop()