"""
InnoSleuth Configuration Module
"""
import sys
import os

APP_NAME = "InnoSleuth"
APP_VERSION = "2.0"
APP_DESCRIPTION = "InnoDB Forensic Analysis Tool"

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller"""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# InnoDB Constants
PAGE_SIZE = 16384
FIL_PAGE_DATA = 38
FIL_PAGE_TYPE_ALLOCATED = 0
FIL_PAGE_UNDO_LOG = 2
FIL_PAGE_INODE = 3
FIL_PAGE_TYPE_FSP_HDR = 8
FIL_PAGE_TYPE_XDES = 9
FIL_PAGE_TYPE_BLOB = 10
FIL_PAGE_INDEX = 17855
FIL_PAGE_TYPE_ZBLOB = 0x0A
FIL_PAGE_TYPE_ZBLOB2 = 0x0B

PAGE_TYPE_NAMES = {
    0: "Freshly Allocated",
    2: "Undo Log",
    3: "Inode",
    8: "FSP Header",
    9: "Extent Descriptor",
    10: "BLOB",
    17855: "B-tree Index",
    0x0A: "Compressed BLOB",
    0x0B: "Compressed BLOB2"
}

# Settings
ENTROPY_LOW = 3.0
ENTROPY_MEDIUM = 5.0
ENTROPY_HIGH = 7.0
MAX_WORKERS = 4
CHUNK_SIZE = 1024 * 1024
HASH_BUFFER_SIZE = 65536
WINDOW_MIN_WIDTH = 1200
WINDOW_MIN_HEIGHT = 800
IOC_TIMEOUT = 10
IOC_MAX_RETRIES = 3
