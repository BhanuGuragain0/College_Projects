#!/usr/bin/env python3
"""
Enhanced GUI for the C2 Server Admin Tool - Advanced Version

Features:
  - Animated vertical gradient background.
  - Tabbed interface with Bots, Tasks, and Logs tabs.
  - Top control panel with:
      • A search field (with clear button) to filter Bots.
      • Export buttons for Bots and Tasks data (CSV).
      • A toggle button to pause/resume auto-refresh.
      • A Settings button to adjust refresh interval and theme.
  - Bots and Tasks tables with sortable columns.
  - Right-click context menu on the Bots table for detailed info.
  - Integrated real-time log viewer in the Logs tab.
  - Status bar showing last refresh time and progress messages.
  - Auto-refresh every 30 seconds.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import sqlite3
import csv
import logging
from datetime import datetime
from server.config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

class TextHandler(logging.Handler):
    """Logging handler that outputs messages to a Tkinter ScrolledText widget."""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state="normal")
            self.text_widget.insert(tk.END, msg + "\n")
            self.text_widget.configure(state="disabled")
            self.text_widget.yview(tk.END)
        self.text_widget.after(0, append)

class C2GUI:
    AUTO_REFRESH_INTERVAL = 30000  # 30 seconds

    def __init__(self, root):
        self.root = root
        self.auto_refresh_paused = False
        self.sort_column = None
        self.sort_reverse = False
        self.theme = "Hacker"  # Default theme
        self.root.title("C2 Server By Shadow@Bhanu")
        self.create_background()
        self.create_menu()
        self.create_widgets()
        self.setup_log_viewer()
        self.refresh_data()  # Initial data load
        self.schedule_auto_refresh()

    def create_background(self):
        """Create an animated vertical gradient background using a Canvas."""
        self.bg_canvas = tk.Canvas(self.root, highlightthickness=0)
        self.bg_canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.draw_gradient()
        # Some Tcl/Tk versions may require an argument to lower():
        self.bg_canvas.lower("all")

    def draw_gradient(self):
        """Draw a vertical gradient from black to dark green."""
        width = self.root.winfo_screenwidth()
        height = self.root.winfo_screenheight()
        limit = height
        r1, g1, b1 = 0, 0, 0      # Black
        r2, g2, b2 = 0, 64, 0     # Dark green
        r_ratio = (r2 - r1) / limit
        g_ratio = (g2 - g1) / limit
        b_ratio = (b2 - b1) / limit
        for i in range(limit):
            nr = int(r1 + (r_ratio * i))
            ng = int(g1 + (g_ratio * i))
            nb = int(b1 + (b_ratio * i))
            color = f"#{nr:02x}{ng:02x}{nb:02x}"
            self.bg_canvas.create_line(0, i, width, i, fill=color)

    def create_menu(self):
        """Create a menu bar with File, View, and Settings menus."""
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Refresh Data", command=self.refresh_data)
        menubar.add_cascade(label="View", menu=view_menu)
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Settings", command=self.open_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        self.root.config(menu=menubar)

    def create_widgets(self):
        """Create main widgets including the control panel, tabs, and status bar."""
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(control_frame, text="Search Bots:").pack(side="left", padx=(0, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(control_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side="left")
        search_entry.bind("<KeyRelease>", lambda e: self.refresh_data())
        clear_btn = ttk.Button(control_frame, text="Clear", command=self.clear_search)
        clear_btn.pack(side="left", padx=5)

        export_bots_btn = ttk.Button(control_frame, text="Export Bots", command=self.export_bots)
        export_bots_btn.pack(side="left", padx=5)
        export_tasks_btn = ttk.Button(control_frame, text="Export Tasks", command=self.export_tasks)
        export_tasks_btn.pack(side="left", padx=5)

        self.pause_btn_text = tk.StringVar(value="Pause Auto-Refresh")
        pause_btn = ttk.Button(control_frame, textvariable=self.pause_btn_text, command=self.toggle_auto_refresh)
        pause_btn.pack(side="right", padx=5)

        settings_btn = ttk.Button(control_frame, text="Settings", command=self.open_settings)
        settings_btn.pack(side="right", padx=5)

        self.refresh_label = ttk.Label(self.root, text="")
        self.refresh_label.pack(pady=2)

        self.tabControl = ttk.Notebook(self.root)
        self.bot_tab = ttk.Frame(self.tabControl)
        self.task_tab = ttk.Frame(self.tabControl)
        self.log_tab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.bot_tab, text="Bots")
        self.tabControl.add(self.task_tab, text="Tasks")
        self.tabControl.add(self.log_tab, text="Logs")
        self.tabControl.pack(expand=True, fill="both", padx=5, pady=5)

        self.bot_tree = ttk.Treeview(self.bot_tab, columns=("ID", "IP", "OS", "Last Seen", "Group"), show="headings")
        for col in ("ID", "IP", "OS", "Last Seen", "Group"):
            self.bot_tree.heading(col, text=col, command=lambda _col=col: self.sort_treeview(self.bot_tree, _col))
            self.bot_tree.column(col, anchor="center")
        self.bot_tree.pack(expand=True, fill="both", padx=5, pady=5)
        self.bot_tree.bind("<Button-3>", self.show_bot_context_menu)

        self.task_tree = ttk.Treeview(self.task_tab, columns=("ID", "Bot ID", "Command", "Status"), show="headings")
        for col in ("ID", "Bot ID", "Command", "Status"):
            self.task_tree.heading(col, text=col, command=lambda _col=col: self.sort_treeview(self.task_tree, _col))
            self.task_tree.column(col, anchor="center")
        self.task_tree.pack(expand=True, fill="both", padx=5, pady=5)

        refresh_button = ttk.Button(self.root, text="Refresh Data", command=self.refresh_data)
        refresh_button.pack(pady=5)

        self.status_var = tk.StringVar()
        self.status_var.set("Last refreshed: Never")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        self.status_bar.pack(fill="x", side="bottom")

    def setup_log_viewer(self):
        """Set up a real-time log viewer in the Logs tab."""
        self.log_text = scrolledtext.ScrolledText(self.log_tab, state="disabled", height=10,
                                                   bg="#111", fg="#0f0", font=("Courier New", 10))
        self.log_text.pack(expand=True, fill="both", padx=5, pady=5)
        text_handler = TextHandler(self.log_text)
        text_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.getLogger().addHandler(text_handler)

    def open_settings(self):
        """Open a settings dialog to adjust auto-refresh interval and theme."""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Settings")
        settings_win.grab_set()
        ttk.Label(settings_win, text="Auto Refresh Interval (sec):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        refresh_var = tk.StringVar(value=str(self.AUTO_REFRESH_INTERVAL // 1000))
        refresh_entry = ttk.Entry(settings_win, textvariable=refresh_var)
        refresh_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(settings_win, text="Theme:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        theme_var = tk.StringVar(value=self.theme)
        theme_options = ["Hacker", "Default"]
        theme_menu = ttk.OptionMenu(settings_win, theme_var, theme_var.get(), *theme_options)
        theme_menu.grid(row=1, column=1, padx=5, pady=5)
        def save_settings():
            try:
                new_interval = int(refresh_var.get()) * 1000
                self.AUTO_REFRESH_INTERVAL = new_interval
                self.status_var.set(f"Auto-refresh interval set to {refresh_var.get()} sec.")
                logging.info(f"Auto-refresh interval updated to {new_interval} ms.")
            except ValueError:
                messagebox.showerror("Invalid Value", "Please enter a valid integer.")
                return
            self.theme = theme_var.get()
            self.update_theme(self.theme)
            settings_win.destroy()
        save_btn = ttk.Button(settings_win, text="Save", command=save_settings)
        save_btn.grid(row=2, column=0, columnspan=2, padx=5, pady=10)

    def update_theme(self, theme):
        """Update GUI colors based on the selected theme."""
        if theme == "Hacker":
            bg_color = "#000"
            fg_color = "#0f0"
        else:
            bg_color = "#f0f0f0"
            fg_color = "#000"
        self.status_bar.configure(background=bg_color, foreground=fg_color)
        self.refresh_label.configure(background=bg_color, foreground=fg_color)
        self.log_text.configure(bg=bg_color, fg=fg_color)
        logging.info(f"Theme updated to {theme}.")

    def clear_search(self):
        self.search_var.set("")
        self.refresh_data()

    def sort_treeview(self, tree, col):
        try:
            data_list = [(tree.set(child, col), child) for child in tree.get_children('')]
            try:
                data_list.sort(key=lambda t: float(t[0]) if t[0].replace('.', '', 1).isdigit() else t[0].lower(), reverse=self.sort_reverse)
            except Exception:
                data_list.sort(key=lambda t: t[0].lower(), reverse=self.sort_reverse)
            for index, (val, child) in enumerate(data_list):
                tree.move(child, '', index)
            self.sort_reverse = not self.sort_reverse
            logging.info(f"Sorted tree by column {col} ({'desc' if self.sort_reverse else 'asc'})")
        except Exception as e:
            logging.error(f"Sorting error: {e}")

    def show_bot_context_menu(self, event):
        try:
            item = self.bot_tree.identify_row(event.y)
            if item:
                menu = tk.Menu(self.root, tearoff=0)
                menu.add_command(label="View Details", command=lambda: self.view_bot_details(item))
                menu.post(event.x_root, event.y_root)
        except Exception as e:
            logging.error(f"Context menu error: {e}")

    def view_bot_details(self, item):
        try:
            bot_info = self.bot_tree.item(item, "values")
            detail_win = tk.Toplevel(self.root)
            detail_win.title("Bot Details")
            details = "\n".join(f"{col}: {bot_info[i]}" for i, col in enumerate(["ID", "IP", "OS", "Last Seen", "Group"]))
            tk.Label(detail_win, text=details, justify="left", font=("Courier New", 12),
                     bg="#000", fg="#0f0", padx=10, pady=10).pack()
        except Exception as e:
            logging.error(f"Error showing bot details: {e}")

    def refresh_data(self):
        self.refresh_label.config(text="Refreshing data...")
        self.root.update_idletasks()
        try:
            conn = sqlite3.connect(Config.DB_NAME)
            c = conn.cursor()
            c.execute("SELECT id, ip, os, last_seen, group_name FROM bots")
            bots = c.fetchall()
            c.execute("SELECT id, bot_id, command, status FROM tasks")
            tasks = c.fetchall()
            conn.close()

            search_text = self.search_var.get().lower()
            filtered_bots = [bot for bot in bots if any(search_text in str(field).lower() for field in bot)]

            for i in self.bot_tree.get_children():
                self.bot_tree.delete(i)
            for bot in filtered_bots:
                self.bot_tree.insert("", "end", values=bot)

            for i in self.task_tree.get_children():
                self.task_tree.delete(i)
            for task in tasks:
                self.task_tree.insert("", "end", values=task)

            refresh_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.status_var.set(f"Last refreshed: {refresh_time}")
            logging.info("Data refreshed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh data: {e}")
            logging.error(f"Error refreshing data: {e}")
            self.status_var.set("Error refreshing data.")
        finally:
            self.refresh_label.config(text="")

    def schedule_auto_refresh(self):
        if not self.auto_refresh_paused:
            self.root.after(self.AUTO_REFRESH_INTERVAL, self.auto_refresh)

    def auto_refresh(self):
        self.refresh_data()
        self.schedule_auto_refresh()

    def toggle_auto_refresh(self):
        self.auto_refresh_paused = not self.auto_refresh_paused
        if self.auto_refresh_paused:
            self.pause_btn_text.set("Resume Auto-Refresh")
            self.status_var.set("Auto-refresh paused.")
            logging.info("Auto-refresh paused.")
        else:
            self.pause_btn_text.set("Pause Auto-Refresh")
            self.status_var.set("Auto-refresh resumed.")
            logging.info("Auto-refresh resumed.")
            self.schedule_auto_refresh()

    def export_bots(self):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV Files", "*.csv")],
                title="Save Bots Data As"
            )
            if file_path:
                conn = sqlite3.connect(Config.DB_NAME)
                c = conn.cursor()
                c.execute("SELECT id, ip, os, last_seen, group_name FROM bots")
                bots = c.fetchall()
                conn.close()
                with open(file_path, mode="w", newline="") as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["ID", "IP", "OS", "Last Seen", "Group"])
                    writer.writerows(bots)
                messagebox.showinfo("Export Successful", f"Bots data exported to {file_path}")
                logging.info(f"Bots data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export bots data: {e}")
            logging.error(f"Failed to export bots data: {e}")

    def export_tasks(self):
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV Files", "*.csv")],
                title="Save Tasks Data As"
            )
            if file_path:
                conn = sqlite3.connect(Config.DB_NAME)
                c = conn.cursor()
                c.execute("SELECT id, bot_id, command, status FROM tasks")
                tasks = c.fetchall()
                conn.close()
                with open(file_path, mode="w", newline="") as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["ID", "Bot ID", "Command", "Status"])
                    writer.writerows(tasks)
                messagebox.showinfo("Export Successful", f"Tasks data exported to {file_path}")
                logging.info(f"Tasks data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export tasks data: {e}")
            logging.error(f"Failed to export tasks data: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = C2GUI(root)
    root.mainloop()
