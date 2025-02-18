#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, PhotoImage, filedialog
import threading
import sys
from io import StringIO
import os
import time
import subprocess
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import yaml  # Used for reading the YAML config file

# Ensure repository root is in sys.path.
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from bugbounty_tool.core.tool_runner import ToolRunner
from bugbounty_tool.core.target_processor import TargetProcessor
from bugbounty_tool.core.report_generator import ReportGenerator
from bugbounty_tool.core.ai_analyzer import AIAnalyzer
from bugbounty_tool.core.utils import setup_logging, validate_target
from bugbounty_tool.core.plugin_manager import load_plugins  # For dynamic plugin loading

class BugBountyToolGUI:
    """Enhanced GUI Launcher for the Bug Bounty Automation Tool that streams scan output
    live in the main terminal. All scanning tools’ output appears in real time, along with
    features like scheduling, configuration viewing, plugin loading, and report generation.
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Bug Bounty Automation Tool - Enhanced Launcher")
        self.root.geometry("1300x900")
        self.root.configure(bg="black")

        # Determine best available font and store as a tuple.
        available_fonts = list(tk.font.families())
        if "JetBrains Mono" in available_fonts:
            self.custom_font = ("JetBrains Mono", 12)
        elif "Fira Code" in available_fonts:
            self.custom_font = ("Fira Code", 12)
        else:
            self.custom_font = ("Courier New", 12)

        # Set application icon using icon.png from repository root.
        icon_path = os.path.join(repo_root, "icon.png")
        if os.path.exists(icon_path):
            try:
                icon = PhotoImage(file=icon_path)
                self.root.iconphoto(True, icon)
            except Exception as e:
                print("Failed to load icon.png:", e)
        else:
            print("Icon not loaded: icon.png not found in repository root.")

        # Configure overall ttk styles.
        self.setup_styles()

        # Create menu bar.
        self.create_menu()

        # === Top Frame: Theme & Scheduling ===
        theme_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        theme_frame.pack(pady=5, padx=10, fill=tk.X)
        ttk.Label(theme_frame, text="Select Theme:", style="Hacker.TLabel").pack(side=tk.LEFT, padx=5)
        theme_options = ["Green Neon", "Blue Neon", "Red Neon"]
        self.theme_var = tk.StringVar(value="Green Neon")
        self.theme_menu = ttk.OptionMenu(theme_frame, self.theme_var, theme_options[0],
                                         *theme_options, command=self.apply_theme)
        self.theme_menu.pack(side=tk.LEFT)

        # Scheduler: Option to schedule scans (in minutes).
        schedule_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        schedule_frame.pack(pady=5, padx=10, fill=tk.X)
        ttk.Label(schedule_frame, text="Schedule Scan (minutes, optional):", style="Hacker.TLabel").pack(side=tk.LEFT, padx=5)
        self.schedule_var = tk.StringVar(value="")
        self.schedule_entry = ttk.Entry(schedule_frame, textvariable=self.schedule_var, width=5, style="Hacker.TEntry")
        self.schedule_entry.pack(side=tk.LEFT)

        # === Custom Command Frame ===
        custom_cmd_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        custom_cmd_frame.pack(pady=5, padx=10, fill=tk.X)
        ttk.Label(custom_cmd_frame, text="Custom Command:", style="Hacker.TLabel").pack(side=tk.LEFT, padx=5)
        self.custom_cmd_entry = ttk.Entry(custom_cmd_frame, width=50, style="Hacker.TEntry")
        self.custom_cmd_entry.pack(side=tk.LEFT, padx=5)
        self.run_cmd_button = ttk.Button(custom_cmd_frame, text="Run Command",
                                         command=self.run_custom_command, style="Hacker.TButton")
        self.run_cmd_button.pack(side=tk.LEFT, padx=5)
        self.custom_cmd_entry.bind("<Return>", lambda event: self.run_custom_command())

        # === Input Frame: Target and Wordlist ===
        self.input_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        self.input_frame.pack(pady=10, padx=10, fill=tk.X)
        self.target_label = ttk.Label(self.input_frame, text="Target (URL, IP, Domain, or ASN):", style="Hacker.TLabel")
        self.target_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.target_entry = ttk.Entry(self.input_frame, width=50, style="Hacker.TEntry")
        self.target_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
        self.target_entry.bind("<Return>", lambda event: self.start_scan())

        self.wordlist_label = ttk.Label(self.input_frame, text="Wordlist:", style="Hacker.TLabel")
        self.wordlist_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        # Dynamically load wordlists from the wordlists directory.
        wordlists_dir = os.path.join(repo_root, "wordlists")
        wordlist_files = [f for f in os.listdir(wordlists_dir)
                          if os.path.isfile(os.path.join(wordlists_dir, f))]
        self.wordlist_combobox = ttk.Combobox(self.input_frame, values=wordlist_files, style="Hacker.TCombobox")
        self.wordlist_combobox.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)
        if wordlist_files:
            self.wordlist_combobox.current(0)

        # === Scan Options Frame ===
        self.scan_frame = ttk.LabelFrame(self.root, text="Scan Options", style="Hacker.TLabelframe")
        self.scan_frame.pack(pady=10, padx=10, fill=tk.X)
        self.scan_options = {
            "Nmap": tk.BooleanVar(),
            "Dirsearch": tk.BooleanVar(),
            "SQLMap": tk.BooleanVar(),
            "Nikto": tk.BooleanVar(),
            "Gobuster": tk.BooleanVar(),
            "Wfuzz": tk.BooleanVar(),
            "Wpscan": tk.BooleanVar(),
        }
        col = 0
        row = 0
        for tool, var in self.scan_options.items():
            chk = ttk.Checkbutton(self.scan_frame, text=tool, variable=var, style="Hacker.TCheckbutton")
            chk.grid(row=row, column=col, padx=10, pady=5, sticky=tk.W)
            col += 1
            if col >= 4:
                col = 0
                row += 1

        # === Buttons Frame: Main Actions and Advanced Options ===
        self.button_frame = ttk.Frame(self.root, style="Hacker.TFrame")
        self.button_frame.pack(pady=10, padx=10, fill=tk.X)
        # Only one Scan button is used; its output is streamed live.
        self.start_button = ttk.Button(self.button_frame, text="Start Scan", command=self.start_scan, style="Hacker.TButton")
        self.start_button.grid(row=0, column=0, padx=10, pady=5)
        self.report_button = ttk.Button(self.button_frame, text="Generate Report", command=self.generate_report, style="Hacker.TButton")
        self.report_button.grid(row=0, column=1, padx=10, pady=5)
        self.graph_button = ttk.Button(self.button_frame, text="Show Graph", command=self.show_graph, style="Hacker.TButton")
        self.graph_button.grid(row=0, column=2, padx=10, pady=5)
        self.map_button = ttk.Button(self.button_frame, text="Live Network Map", command=self.show_network_map, style="Hacker.TButton")
        self.map_button.grid(row=0, column=3, padx=10, pady=5)
        self.exploit_button = ttk.Button(self.button_frame, text="Suggest Exploits", command=self.suggest_exploits, style="Hacker.TButton")
        self.exploit_button.grid(row=0, column=4, padx=10, pady=5)
        self.pdf_button = ttk.Button(self.button_frame, text="Generate PDF Report", command=self.generate_pdf_report, style="Hacker.TButton")
        self.pdf_button.grid(row=0, column=5, padx=10, pady=5)
        self.plugins_button = ttk.Button(self.button_frame, text="Load Plugins", command=self.load_plugins, style="Hacker.TButton")
        self.plugins_button.grid(row=0, column=6, padx=10, pady=5)
        self.config_button = ttk.Button(self.button_frame, text="View Config", command=self.view_config, style="Hacker.TButton")
        self.config_button.grid(row=0, column=7, padx=10, pady=5)
        # (No extra "Real-Time Scan" button: output always streams in the main terminal)

        # === Progress Bar (indeterminate mode during scans) ===
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        # === Log Output Area (Terminal-like) ===
        self.log_text = scrolledtext.ScrolledText(self.root, height=20, width=120,
                                                    bg="black", fg="green",
                                                    font=self.custom_font,
                                                    wrap=tk.WORD, insertbackground="green")
        self.log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # === Status Bar ===
        self.status_var = tk.StringVar()
        self.status_var.set("Ready. Output will be saved to the 'results' directory.")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, style="Hacker.TLabel")
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # === Initialize scanning modules ===
        self.logger = setup_logging(verbose=2)
        wordlist_path = os.path.join(repo_root, "wordlists", self.wordlist_combobox.get()) if wordlist_files else ""
        if wordlist_path and not os.path.exists(wordlist_path):
            self.logger.error(f"Wordlist file '{self.wordlist_combobox.get()}' not found in 'wordlists'.")
        self.tool_runner = ToolRunner(self.logger, os.path.join(repo_root, "results"), wordlist_path)
        self.processor = TargetProcessor(self.logger, os.path.join(repo_root, "results"))
        self.reporter = ReportGenerator(self.logger, os.path.join(repo_root, "results"))
        self.ai_analyzer = AIAnalyzer(self.logger, self.tool_runner.config)

    def setup_styles(self):
        """Configure ttk styles for the hacker theme with improved fonts."""
        style = ttk.Style()
        style.theme_use("clam")
        # Set fonts and colors through styles.
        style.configure("Hacker.TFrame", background="black")
        style.configure("Hacker.TLabel", background="black", foreground="green", font=self.custom_font)
        style.configure("Hacker.TEntry", fieldbackground="black", foreground="green", font=self.custom_font)
        style.configure("Hacker.TButton", background="black", foreground="green", font=self.custom_font)
        style.configure("Hacker.TCheckbutton", background="black", foreground="green", font=self.custom_font)
        style.configure("Hacker.TCombobox", fieldbackground="black", foreground="green", font=self.custom_font)
        style.configure("Hacker.TLabelframe", background="black", foreground="green", font=self.custom_font)
        style.configure("Hacker.TLabelframe.Label", background="black", foreground="green", font=self.custom_font)

    def create_menu(self):
        """Create the menu bar with File, Plugins, and Help menus."""
        menubar = tk.Menu(self.root, background="black", foreground="green",
                          activebackground="green", activeforeground="black")
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0, background="black", foreground="green", font=self.custom_font)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        # Plugins Menu
        plugins_menu = tk.Menu(menubar, tearoff=0, background="black", foreground="green", font=self.custom_font)
        plugins_menu.add_command(label="Load Plugins", command=self.load_plugins)
        menubar.add_cascade(label="Plugins", menu=plugins_menu)
        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0, background="black", foreground="green", font=self.custom_font)
        help_menu.add_command(label="View Config", command=self.view_config)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def apply_theme(self, theme):
        """Apply neon theme based on selection."""
        themes = {
            "Green Neon": {"fg": "green", "bg": "black"},
            "Blue Neon": {"fg": "cyan", "bg": "black"},
            "Red Neon": {"fg": "red", "bg": "black"}
        }
        t = themes.get(theme, themes["Green Neon"])
        style = ttk.Style()
        style.configure("Hacker.TLabel", background=t["bg"], foreground=t["fg"], font=self.custom_font)
        style.configure("Hacker.TFrame", background=t["bg"])
        style.configure("Hacker.TEntry", fieldbackground=t["bg"], foreground=t["fg"], font=self.custom_font)
        style.configure("Hacker.TButton", background=t["bg"], foreground=t["fg"], font=self.custom_font)
        style.configure("Hacker.TCheckbutton", background=t["bg"], foreground=t["fg"], font=self.custom_font)
        style.configure("Hacker.TCombobox", fieldbackground=t["bg"], foreground=t["fg"], font=self.custom_font)
        style.configure("Hacker.TLabelframe", background=t["bg"], foreground=t["fg"], font=self.custom_font)
        style.configure("Hacker.TLabelframe.Label", background=t["bg"], foreground=t["fg"], font=self.custom_font)
        self.status_var.set(f"Theme changed to {theme}")

    def show_about(self):
        """Display the About information."""
        about_text = (
            "Bug Bounty Automation Tool\n"
            "Enhanced Launcher v1.0\n"
            "Developed by Your Name\n\n"
            "This tool integrates multiple scanning modules, dynamic plugin loading, "
            "and report generation in HTML, Markdown, JSON, and PDF formats."
        )
        messagebox.showinfo("About", about_text)

    def show_graph(self):
        """Display an interactive graph using matplotlib."""
        fig, ax = plt.subplots(figsize=(5, 4))
        data = [5, 7, 3, 8, 2]
        ax.bar(range(len(data)), data, color="green")
        ax.set_title("Scan Results Overview")
        ax.set_xlabel("Tools")
        ax.set_ylabel("Findings Count")
        canvas = FigureCanvasTkAgg(fig, master=self.root)
        canvas.draw()
        win = tk.Toplevel(self.root)
        win.title("Interactive Graph")
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def show_network_map(self):
        """Display a demo live network map using networkx."""
        try:
            import networkx as nx
        except ImportError:
            messagebox.showerror("Error", "NetworkX is required for live network mapping. Please install it.")
            return
        G = nx.Graph()
        nodes = ["A", "B", "C", "D", "E"]
        G.add_nodes_from(nodes)
        edges = [("A", "B"), ("B", "C"), ("C", "D"), ("D", "E"), ("E", "A")]
        G.add_edges_from(edges)
        pos = nx.spring_layout(G)
        fig, ax = plt.subplots(figsize=(5, 4))
        nx.draw(G, pos, with_labels=True, node_color="cyan", edge_color="green", ax=ax)
        ax.set_title("Live Network Map (Demo)")
        canvas = FigureCanvasTkAgg(fig, master=self.root)
        canvas.draw()
        win = tk.Toplevel(self.root)
        win.title("Live Network Map")
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def suggest_exploits(self):
        """Show exploit suggestions based on scan results."""
        suggestions = (
            "Based on scan results:\n\n"
            "- SQL Injection detected: Consider SQLMap or manual testing.\n"
            "- Outdated software: Check Exploit-DB for known vulnerabilities.\n"
            "- Further manual testing is recommended for borderline findings.\n\n"
            "Auto-exploit suggestions are under development."
        )
        messagebox.showinfo("Exploit Suggestions", suggestions)

    def generate_pdf_report(self):
        """Generate a dummy PDF report using FPDF."""
        self.status_var.set("Generating PDF report...")
        threading.Thread(target=self.run_pdf_report, daemon=True).start()

    def run_pdf_report(self):
        try:
            from fpdf import FPDF
            # Import enums to use updated parameters (avoid deprecation warnings)
            from fpdf.enums import XPos, YPos
        except ImportError:
            self.update_log("FPDF is required for PDF report generation. Please install it.\n")
            return
        pdf = FPDF()
        pdf.add_page()
        # Use updated parameters: 'text' instead of 'txt' and new_x/new_y to move to a new line.
        pdf.cell(200, 10, text="Bug Bounty Automation Tool Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
        pdf.ln(10)
        pdf.multi_cell(0, 10, text="This is a dummy PDF report.\nCVSS scores and vulnerability details would be included here.")
        output_pdf = os.path.join(repo_root, "results", "report.pdf")
        pdf.output(output_pdf)
        self.root.after(0, self.update_log, f"PDF report generated and saved to {output_pdf}\n")
        self.root.after(0, self.status_var.set, "PDF report generated.")

    def run_custom_command(self):
        """Execute a custom terminal command and display the output."""
        cmd = self.custom_cmd_entry.get().strip()
        if not cmd:
            messagebox.showerror("Error", "Please enter a custom command.")
            return
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
            self.update_log(f"\nCustom Command Output:\n{output}\n")
        except subprocess.CalledProcessError as e:
            self.update_log(f"\nCustom Command Error:\n{e.output}\n")

    def start_scan(self):
        """
        Initiate the scan. This method validates the target and then, in a separate thread,
        runs a real-time scan for each selected tool. All output is streamed live to the main terminal.
        If a schedule interval is provided, scanning is repeated at that interval.
        """
        target = self.target_entry.get().strip()
        if not validate_target(target):
            messagebox.showerror("Error", "Invalid target. Please provide a valid URL, IP, domain, or ASN.")
            return

        schedule_minutes = self.schedule_var.get().strip()
        self.log_text.delete(1.0, tk.END)
        self.progress.start(10)
        if schedule_minutes:
            try:
                interval = float(schedule_minutes) * 60
            except ValueError:
                messagebox.showerror("Error", "Invalid schedule interval. Please enter a number (minutes).")
                self.progress.stop()
                return

            def scheduled_scan():
                while True:
                    self.run_real_time_scan(target)
                    time.sleep(interval)
            threading.Thread(target=scheduled_scan, daemon=True).start()
        else:
            threading.Thread(target=self.run_real_time_scan, args=(target,), daemon=True).start()

    def run_real_time_scan(self, target):
        """
        For each selected tool, build the command and run it using subprocess.Popen.
        Read the output line-by-line and update the main terminal (the log widget) in real time.
        """
        command_mapping = {
            "nmap": "nmap",
            "dirsearch": "dirsearch",
            "sqlmap": "sqlmap",
            "nikto": "nikto",
            "gobuster": "gobuster",
            "wfuzz": "wfuzz",
            "wpscan": "wpscan"
        }
        for tool, var in self.scan_options.items():
            if var.get():
                lower_tool = tool.lower()
                self.root.after(0, self.update_log, f"\nStarting {tool} scan for target: {target}\n")
                args = []
                if lower_tool == "nmap":
                    args = ["-sV", "-A", "-T4", "-Pn", target]
                elif lower_tool == "dirsearch":
                    args = ["-u", target, "-e", "*"]
                elif lower_tool == "sqlmap":
                    args = ["-u", target, "--batch"]
                elif lower_tool == "nikto":
                    args = ["-h", target]
                elif lower_tool == "gobuster":
                    wordlist = os.path.join(repo_root, "wordlists", self.wordlist_combobox.get())
                    args = ["dir", "-u", target, "-w", wordlist]
                elif lower_tool == "wfuzz":
                    wordlist = os.path.join(repo_root, "wordlists", self.wordlist_combobox.get())
                    args = ["-c", "-z", f"file,{wordlist}", target]
                elif lower_tool == "wpscan":
                    args = ["--url", target, "--enumerate", "vp"]

                base_cmd = command_mapping.get(lower_tool, lower_tool)
                cmd = [base_cmd] + args
                try:
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                except Exception as e:
                    self.root.after(0, self.update_log, f"Error running {tool}: {e}\n")
                    continue
                # Stream output line-by-line.
                for line in iter(process.stdout.readline, ""):
                    if line:
                        self.root.after(0, self.update_log, line)
                process.stdout.close()
                process.wait()
                self.root.after(0, self.update_log, f"{tool} scan completed.\n\n")
        self.root.after(0, self.progress.stop)
        self.root.after(0, self.status_var.set, "Scan completed. Results updated in terminal.")

    def update_log(self, text):
        """Append text to the log widget and scroll to the end."""
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)

    def generate_report(self):
        """Generate reports in multiple formats."""
        self.status_var.set("Generating reports...")
        self.progress.start(10)
        threading.Thread(target=self.run_report, daemon=True).start()

    def run_report(self):
        # To avoid UnicodeDecodeError, ensure files are opened with errors='replace'
        results = self.reporter.parse_tool_outputs()
        self.reporter.generate_html_report(results)
        self.reporter.generate_markdown_report(results)
        self.reporter.generate_json_report(results)
        self.root.after(0, self.status_var.set, "Reports generated. Check the 'results' directory.")
        self.root.after(0, self.progress.stop)

    def load_plugins(self):
        """Load scanning tool plugins using the plugin manager."""
        try:
            plugins = load_plugins()
            plugin_names = [plugin.__name__ for plugin in plugins]
            self.update_log("Loaded plugins:\n" + "\n".join(plugin_names) + "\n")
            self.status_var.set("Plugins loaded successfully.")
        except Exception as e:
            self.update_log(f"Error loading plugins: {e}\n")
            self.status_var.set("Failed to load plugins.")

    def view_config(self):
        """Display the configuration file content in a new window."""
        config_path = os.path.join(repo_root, "config", "config.yaml")
        if not os.path.exists(config_path):
            messagebox.showerror("Error", f"Configuration file not found at {config_path}")
            return
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
            config_str = yaml.dump(config_data, default_flow_style=False)
        except Exception as e:
            config_str = f"Error reading configuration: {e}"
        win = tk.Toplevel(self.root)
        win.title("Configuration")
        text_area = scrolledtext.ScrolledText(win, width=100, height=30, font=self.custom_font,
                                               bg="black", fg="green", insertbackground="green")
        text_area.pack(fill=tk.BOTH, expand=True)
        text_area.insert(tk.END, config_str)
        text_area.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = BugBountyToolGUI(root)
    # Bind Ctrl+Q to exit.
    root.bind("<Control-q>", lambda event: root.quit())
    root.mainloop()

