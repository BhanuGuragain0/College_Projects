# bot/stealth.py
import platform
import time
import random
import logging

def anti_debugging():
    try:
        if platform.system() == "Windows":
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent():
                logging.error("Debugger detected! Exiting.")
                exit(1)
        elif platform.system() == "Linux":
            try:
                with open("/proc/self/status", "r") as status_file:
                    for line in status_file:
                        if line.startswith("TracerPid:") and int(line.split()[1]) > 0:
                            logging.error("Debugger detected! Exiting.")
                            exit(1)
            except Exception as e:
                logging.warning(f"Could not verify debugger status: {e}")
    except Exception as e:
        logging.error(f"Anti-debugging error: {e}")


class StealthManager:
    @staticmethod
    def random_sleep():
        sleep_time = random.uniform(1, 5)
        time.sleep(sleep_time)
        logging.info(f"Bot slept for {sleep_time} seconds to evade detection.")