import os
import logging
from enum import Enum, IntEnum

# ==============================================================================
# 1. LOGGING SETUP
# ==============================================================================
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("OverseerrBot")

# ==============================================================================
# 2. CREDENTIAL LOADING
# ==============================================================================
# Priority:
# 1. Environment Variables (Docker/Server)
# 2. config.py (User File)

# Defaults
API_URL = None
API_KEY = None
TOKEN   = None
PASS    = ""

# Try loading from config.py
try:
    from config import OVERSEERR_API_URL, OVERSEERR_API_KEY, TELEGRAM_TOKEN, PASSWORD
    API_URL = OVERSEERR_API_URL
    API_KEY = OVERSEERR_API_KEY
    TOKEN = TELEGRAM_TOKEN
    PASS = PASSWORD
    logger.info("Credentials loaded from config.py")
except ImportError:
    # This is fine if running purely on ENV vars (e.g. Docker without volume mount)
    pass 

# Environment Variables override config.py (or serve as fallback)
OVERSEERR_API_URL = os.environ.get("OVERSEERR_API_URL", API_URL)
OVERSEERR_API_KEY = os.environ.get("OVERSEERR_API_KEY", API_KEY)
TELEGRAM_TOKEN    = os.environ.get("TELEGRAM_TOKEN", TOKEN)
PASSWORD          = os.environ.get("PASSWORD", PASS)

# Validation
if not all([OVERSEERR_API_URL, OVERSEERR_API_KEY, TELEGRAM_TOKEN]):
    logger.error("CRITICAL: Credentials missing! Please fill config.py or set ENV variables.")

# ==============================================================================
# 3. BOT CONSTANTS & PATHS
# ==============================================================================
VERSION = "4.0.0"
BUILD = "2025.12.14.310"

DATA_DIR = "data"
CONFIG_FILE = f"{DATA_DIR}/bot_config.json"
USER_SELECTION_FILE = f"{DATA_DIR}/api_mode_selections.json"
USER_SESSIONS_FILE = f"{DATA_DIR}/normal_mode_sessions.json"
SHARED_SESSION_FILE = f"{DATA_DIR}/shared_mode_session.json"

os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_POSTER_URL = "https://raw.githubusercontent.com/sct/overseerr/refs/heads/develop/public/images/overseerr_poster_not_found.png"

PERMISSION_4K_MOVIE = 2048
PERMISSION_4K_TV = 4096

# ==============================================================================
# 4. ENUMS
# ==============================================================================
class MediaStatus(IntEnum):
    UNKNOWN = 1
    PENDING = 2
    PROCESSING = 3
    PARTIALLY_AVAILABLE = 4
    AVAILABLE = 5

ISSUE_TYPES = {
    1: "Video",
    2: "Audio",
    3: "Subtitle",
    4: "Other"
}

class BotMode(Enum):
    NORMAL = "normal"
    API = "api"
    SHARED = "shared"

CURRENT_MODE = BotMode.NORMAL