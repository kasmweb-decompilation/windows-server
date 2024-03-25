# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.19 (default, Mar 25 2024, 14:51:23) 
# [GCC 12.2.0]
# Embedded file name: screenshot.py
import os, sys, logging
from mss import mss
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if os.name == "nt":
    from windows_eventlog_handler import WindowsEventLogHandler
    handler = WindowsEventLogHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

def save_screenshot():
    try:
        screenshot_path = os.path.join(sys.argv[1]) if len(sys.argv) == 2 else None
        if not screenshot_path:
            raise Exception("Failed to take session screenshot. No valid path provided")
        with mss() as sct:
            sct.shot(output=screenshot_path)
    except Exception as e:
        try:
            print(str(e))
            logger.error(e)
        finally:
            e = None
            del e


if __name__ == "__main__":
    save_screenshot()

# okay decompiling screenshot/screenshot.pyc
