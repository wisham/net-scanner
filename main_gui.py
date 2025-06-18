# main_gui.py

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from scanners import (
    dns_lookup, port_scanner, whois_lookup, banner_grabber,
    traceroute, ping_sweep, http_headers, subdomain_finder,
    cms_detector, robots_checker
)

# Function mapping
scan_functions = {
    "WHOIS Lookup": whois_lookup.run,
    "DNS Lookup": dns_lookup.run,
    "Subdomain Finder": subdomain_finder.run,
    "Port Scanner": port_scanner.run,
    "Banner Grabber": banner_grabber.run,
    "Robots.txt Scanner": robots_checker.run,
    "HTTP Headers": http_headers.run,
    "Traceroute": traceroute.run,
    "Ping Sweep": ping_sweep.run,
    "CMS Detector": cms_detector.run
}

# Colors
BG_COLOR = "#1e1e2f"
FG_COLOR = "#f1f1f1"
BTN_COLOR = "#3e8e41"
ENTRY_BG = "#2e2e3e"

def run_scan(scan_type, target, output_box):
    output_box.delete('1.0', tk.END)
    try:
        def custom_print(*args, **kwargs):
            output_box.insert(tk.END, " ".join(map(str, args)) + "\n")
            output_box.see(tk.END)

        original_print = __builtins__.print
        __builtins__.print = custom_print

        scan_func = scan_functions.get(scan_type)
        if scan_func:
            scan_func(target)
        else:
            print("[!] Invalid scan type selected")

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        __builtins__.print = original_print

def create_gui():
    root = tk.Tk()
    root.title("Network Scanner & Web Footprinter")
    root.geometry("900x600")
    root.configure(bg=BG_COLOR)

    # Title
    title_label = tk.Label(root, text="Network Scanner & Web Footprinter",
                           bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 20, "bold"))
    title_label.pack(pady=10)

    # Frame for input
    input_frame = tk.Frame(root, bg=BG_COLOR)
    input_frame.pack(pady=10)

    tk.Label(input_frame, text="Enter IP / Domain:", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 12)).grid(row=0, column=0, padx=10)
    target_entry = tk.Entry(input_frame, width=40, font=("Segoe UI", 12), bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR)
    target_entry.grid(row=0, column=1, padx=10)

    tk.Label(input_frame, text="Select Scan Type:", bg=BG_COLOR, fg=FG_COLOR, font=("Segoe UI", 12)).grid(row=1, column=0, padx=10, pady=10)
    scan_type = ttk.Combobox(input_frame, values=list(scan_functions.keys()), font=("Segoe UI", 12), width=37)
    scan_type.grid(row=1, column=1, padx=10, pady=10)
    scan_type.set("WHOIS Lookup")

    # Run Button
    run_button = tk.Button(root, text="Run Scan", bg=BTN_COLOR, fg="white", font=("Segoe UI", 12, "bold"),
                           command=lambda: run_scan(scan_type.get(), target_entry.get(), output_box))
    run_button.pack(pady=5)

    # Output box
    output_box = scrolledtext.ScrolledText(root, height=20, font=("Consolas", 10), bg="#121218", fg=FG_COLOR, insertbackground=FG_COLOR)
    output_box.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    # Footer
    footer = tk.Label(root, text="Developed by Ethical Hacker | Tkinter UI", bg=BG_COLOR, fg="#888888", font=("Segoe UI", 10))
    footer.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
