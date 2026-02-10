#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, PhotoImage
import threading
import sys
from io import StringIO
import os

# Ensure the repository root is in sys.path.
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from bugbounty_tool.cli import scan

class BugBountyToolGUI:
    """Simplified GUI for the Bug Bounty Automation Tool with real-time log output."""

    def __init__(self, root):
        self.root = root
        self.root.title("Bug Bounty Tool - GUI Mode")
        self.root.geometry("900x700")
        self.root.configure(bg="black")

        # Set icon if available.
        icon_path = "icon.ico"
        if os.path.exists(icon_path):
            try:
                self.root.iconbitmap(icon_path)
            except Exception as e:
                print("Failed to load icon.ico:", e)
        else:
            alt_icon = "icon.png"
            if os.path.exists(alt_icon):
                try:
                    icon = PhotoImage(file=alt_icon)
                    self.root.iconphoto(True, icon)
                except Exception as e:
                    print("Failed to load icon.png:", e)
            else:
                print("Icon not loaded: no icon.ico or icon.png found.")

        # Menubar with Help options.
        self.menubar = tk.Menu(self.root, bg="black", fg="green")
        self.root.config(menu=self.menubar)
        file_menu = tk.Menu(self.menubar, tearoff=0, bg="black", fg="green")
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menubar.add_cascade(label="File", menu=file_menu)
        help_menu = tk.Menu(self.menubar, tearoff=0, bg="black", fg="green")
        help_menu.add_command(label="Instructions", command=self.show_instructions)
        help_menu.add_command(label="About", command=self.show_about)
        self.menubar.add_cascade(label="Help", menu=help_menu)

        # Input Frame: Target field.
        self.input_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        self.input_frame.pack(pady=10, padx=10, fill=tk.X)
        self.target_label = ttk.Label(self.input_frame, text="Target (URL, IP, Domain, or ASN):",
                                      font=("Courier New", 14), foreground="green", background="black")
        self.target_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.target_entry = ttk.Entry(self.input_frame, width=50, font=("Courier New", 14))
        self.target_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        self.target_entry.bind("<Return>", lambda event: self.start_scan())

        self.start_button = ttk.Button(self.input_frame, text="Start Scan", command=self.start_scan,
                                       style="Hacker.TButton")
        self.start_button.grid(row=0, column=2, padx=10, pady=5, sticky=tk.W)

        # Log Output Area.
        self.log_text = tk.Text(self.root, height=25, width=80, bg="black", fg="green",
                                font=("Courier New", 12))
        self.log_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    def show_instructions(self):
        instructions = (
            "Instructions for using the Bug Bounty Tool (GUI Mode):\n\n"
            "1. Enter a valid target (URL, IP, Domain, or ASN) in the target field.\n"
            "   Press Enter or click 'Start Scan' to begin.\n\n"
            "2. The scan output will be displayed in the log area and saved in the 'results' directory.\n\n"
            "3. For advanced features (e.g., multiple scan options, interactive graphs, network mapping), "
            "please use the Advanced Launcher (launcher.py).\n\n"
            "Happy scanning!"
        )
        messagebox.showinfo("Instructions", instructions)

    def show_about(self):
        about_text = (
            "Bug Bounty Tool (GUI Mode)\n"
            "Author: Shadow@Bhanu\n"
            "Version: 0.1.0\n\n"
            "This tool automates vulnerability scanning and displays the output in a terminal-like interface.\n"
            "Output files are saved in the 'results' directory."
        )
        messagebox.showinfo("About", about_text)

    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a valid target.")
            return
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, f"Starting scan for target: {target}\n")
        threading.Thread(target=self.run_scan, args=(target,), daemon=True).start()

    def run_scan(self, target):
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        try:
            scan(target=target, full=True)
        except Exception as e:
            print("Error during scan:", e)
        output = mystdout.getvalue()
        sys.stdout = old_stdout
        self.root.after(0, self.update_log, output)

    def update_log(self, text):
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()

    # Apply hacker theme styles.
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Hacker.TFrame", background="black")
    style.configure("Hacker.TLabel", background="black", foreground="green")
    style.configure("Hacker.TEntry", fieldbackground="black", foreground="green")
    style.configure("Hacker.TButton", background="black", foreground="green")
    style.configure("Hacker.TCombobox", fieldbackground="black", foreground="green")

    app = BugBountyToolGUI(root)
    root.mainloop()
