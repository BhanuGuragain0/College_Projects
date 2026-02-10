#!/usr/bin/env python3
"""
Enhanced Launcher for the C2 Server Tool.
This script:
  - Loads environment variables from .env,
  - Validates configuration,
  - Initializes the database,
  - Sets up robust logging (with command-line options),
  - Optionally shows a splash screen,
  - Optionally applies a custom title bar (hackeristic look),
  - And launches the Tkinter-based GUI.

Command-line options:
  --debug             : Enable verbose debug logging.
  --no-splash         : Skip the splash screen.
  --splash-duration N : Set splash screen duration in milliseconds (default: 3000).
  --version           : Print version information and exit.
  --logfile FILE      : Specify a custom log file (default: launcher.log).
  --custom-titlebar   : Enable custom title bar (removes OS title bar).
"""

import os
import sys
import time
import logging
import argparse
import tkinter as tk
from tkinter import PhotoImage, Toplevel, Frame, Label, Button
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

from server.config import Config
from server.models import init_db as init_database  # Database initialization
from server.gui import C2GUI  # Our advanced GUI

APP_VERSION = "1.0.0"  # Update as needed

def parse_arguments():
    parser = argparse.ArgumentParser(description="Launcher for C2 Server Tool")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode (verbose logging)")
    parser.add_argument("--no-splash", action="store_true", help="Do not show splash screen")
    parser.add_argument("--splash-duration", type=int, default=3000, help="Splash screen duration in ms")
    parser.add_argument("--version", action="store_true", help="Show version info and exit")
    parser.add_argument("--logfile", type=str, default="launcher.log", help="Log file name")
    parser.add_argument("--custom-titlebar", action="store_true", help="Enable custom title bar (hackeristic look)")
    return parser.parse_args()

def global_exception_handler(exctype, value, tb):
    logging.critical("Uncaught exception", exc_info=(exctype, value, tb))
    sys.__excepthook__(exctype, value, tb)

def setup_logging(debug=False, logfile="launcher.log"):
    level = logging.DEBUG if debug else logging.INFO
    log_format = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(logfile, mode="a")
        ]
    )
    logging.info("Logging is set up.")
    if debug:
        logging.debug("Debug mode enabled.")

def ensure_directories():
    upload_folder = Config.UPLOAD_FOLDER
    if not os.path.exists(upload_folder):
        try:
            os.makedirs(upload_folder)
            logging.info(f"Created upload folder at {upload_folder}")
        except Exception as e:
            logging.error(f"Failed to create upload folder at {upload_folder}: {e}")
            sys.exit(1)

def set_window_icon(root):
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
        if os.path.exists(icon_path):
            img = PhotoImage(file=icon_path)
            root.iconphoto(False, img)
            logging.info(f"Window icon set from {icon_path}")
        else:
            logging.warning(f"Icon file not found at {icon_path}")
    except Exception as e:
        logging.warning(f"Could not load icon: {e}")

def show_splash(root, duration=3000):
    splash = Toplevel(root)
    splash.overrideredirect(True)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    width, height = 400, 300
    x = int((screen_width - width) / 2)
    y = int((screen_height - height) / 2)
    splash.geometry(f"{width}x{height}+{x}+{y}")
    icon_path = os.path.join(os.path.dirname(__file__), "icon.png")
    if os.path.exists(icon_path):
        try:
            img = PhotoImage(file=icon_path)
            label = tk.Label(splash, image=img, bg="#000")
            label.image = img  # Keep reference
            label.pack(expand=True)
        except Exception as e:
            tk.Label(splash, text="C2 Server Tool", fg="#0f0", bg="#000", font=("Courier New", 24)).pack(expand=True)
            logging.warning(f"Failed to load splash icon: {e}")
    else:
        tk.Label(splash, text="C2 Server Tool", fg="#0f0", bg="#000", font=("Courier New", 24)).pack(expand=True)
    root.after(duration, splash.destroy)
    root.update()

def create_custom_title_bar(root):
    """Create a custom title bar with drag-to-move functionality."""
    root.overrideredirect(True)
    title_bar = Frame(root, bg="#222", relief="raised", bd=0)
    title_bar.pack(fill="x")
    title_label = Label(title_bar, text="C2 Server Administration Tool", bg="#222", fg="#0f0", font=("Courier New", 12))
    title_label.pack(side="left", padx=10)
    close_button = Button(title_bar, text="X", bg="#222", fg="#f00", command=root.destroy, bd=0, padx=5, pady=2)
    close_button.pack(side="right")
    def start_move(event):
        root.x = event.x
        root.y = event.y
    def stop_move(event):
        root.x = None
        root.y = None
    def on_move(event):
        x = event.x_root - root.x
        y = event.y_root - root.y
        root.geometry(f"+{x}+{y}")
    title_bar.bind("<ButtonPress-1>", start_move)
    title_bar.bind("<ButtonRelease-1>", stop_move)
    title_bar.bind("<B1-Motion>", on_move)

def validate_config():
    missing = []
    if not getattr(Config, "SECRET_KEY", None):
        missing.append("SECRET_KEY")
    if not getattr(Config, "UPLOAD_FOLDER", None):
        missing.append("UPLOAD_FOLDER")
    if missing:
        logging.error(f"Missing configuration: {', '.join(missing)}")
        sys.exit(1)
    logging.info("Configuration validated.")

def main():
    sys.excepthook = global_exception_handler
    args = parse_arguments()
    if args.version:
        print(f"C2 Server Tool Version: {APP_VERSION}")
        sys.exit(0)
    setup_logging(debug=args.debug, logfile=args.logfile)
    ensure_directories()
    validate_config()
    
    # Initialize database (creates tables if not present)
    try:
        init_database()
        logging.info("Database initialized successfully.")
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
        sys.exit(1)

    root = tk.Tk()
    root.withdraw()  # Hide main window during splash

    if not args.no_splash:
        show_splash(root, duration=args.splash_duration)
    else:
        logging.info("Splash screen skipped (--no-splash).")

    root.deiconify()
    root.title(f"C2 Server Administration Tool v{APP_VERSION}")
    set_window_icon(root)
    
    if args.custom_titlebar:
        create_custom_title_bar(root)

    try:
        app = C2GUI(root)
        logging.info("Launching the C2 Server GUI.")
        root.mainloop()
    except Exception as e:
        logging.error(f"An error occurred while launching the GUI: {e}")
        sys.exit(1)
    finally:
        logging.info("C2 Server Tool exited.")

if __name__ == "__main__":
    main()
