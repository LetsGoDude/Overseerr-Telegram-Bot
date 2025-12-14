import json
import os
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

# Import constants and logger from bot_settings
import bot_settings
from bot_settings import (
    CONFIG_FILE,
    USER_SELECTION_FILE,
    USER_SESSIONS_FILE,
    SHARED_SESSION_FILE,
    logger
)

# ==============================================================================
# CONFIGURATION MANAGEMENT
# ==============================================================================

def load_config() -> dict:
    """
    Loads the configuration from bot_config.json.
    Returns a dictionary with default values if the file is missing or invalid.
    """
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
            # Ensure default structure exists
            config.setdefault("group_mode", False)
            config.setdefault("send_startup_notification", False)
            config.setdefault("primary_chat_id", {"chat_id": None, "message_thread_id": None})
            config["primary_chat_id"].setdefault("chat_id", None)
            config["primary_chat_id"].setdefault("message_thread_id", None)
            config.setdefault("mode", "normal")
            config.setdefault("users", {})
            return config
    except (FileNotFoundError, json.JSONDecodeError, PermissionError) as e:
        logger.warning(f"Failed to load {CONFIG_FILE}: {e}. Using defaults.")
        default_config = {
            "group_mode": False,
            "primary_chat_id": {"chat_id": None, "message_thread_id": None},
            "mode": "normal",
            "users": {}
        }
        # Save defaults immediately so the file exists next time
        save_config(default_config)
        return default_config

def save_config(config: dict):
    """
    Saves the configuration to bot_config.json.
    """
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
        logger.info(f"Configuration saved to {CONFIG_FILE}")
    except (IOError, PermissionError) as e:
        logger.error(f"Failed to save {CONFIG_FILE}: {e}")

# ==============================================================================
# PERMISSION & LOGIC CHECKS
# ==============================================================================

def is_command_allowed(chat_id: int, message_thread_id: Optional[int], config: dict, telegram_user_id: int) -> bool:
    """
    Checks if a command is allowed based on Group Mode, chat/thread ID, and user status.
    Admins can always use commands in private chats, even if Group Mode is enabled.
    """
    user_id_str = str(telegram_user_id)
    user = config["users"].get(user_id_str, {})
    is_admin = user.get("is_admin", False)
    is_blocked = user.get("is_blocked", False)

    if is_blocked:
        logger.debug(f"User {telegram_user_id} is blocked, denying command")
        return False

    # Positive chat_id indicates a private chat (User <-> Bot)
    if is_admin and chat_id > 0:
        logger.debug(f"Admin {telegram_user_id} in private chat {chat_id}, allowing command")
        return True

    if not config["group_mode"]:
        return True

    primary = config["primary_chat_id"]
    if primary["chat_id"] is None:
        logger.debug(f"Group Mode on, primary_chat_id unset, allowing command in chat {chat_id}")
        return True
    
    # Check if we are in the correct chat/thread
    if chat_id != primary["chat_id"]:
        logger.info(f"Ignoring command in chat {chat_id}: Group Mode restricts to primary chat {primary['chat_id']}")
        return False
    
    if primary["message_thread_id"] is not None and message_thread_id != primary["message_thread_id"]:
        logger.info(f"Ignoring command in thread {message_thread_id}: Group Mode restricts to thread {primary['message_thread_id']}")
        return False

    return True

def user_is_authorized(telegram_user_id: int) -> bool:
    """
    Checks if a Telegram user is authorized based on the bot_config.json.
    """
    config = load_config()
    user_id_str = str(telegram_user_id)
    user = config["users"].get(user_id_str, {})
    return user.get("is_authorized", False) and not user.get("is_blocked", False)

def ensure_data_directory():
    """Ensures data directory exists (also done in bot_settings, but good as helper)."""
    os.makedirs(bot_settings.DATA_DIR, exist_ok=True)

# ==============================================================================
# SESSION MANAGEMENT (NORMAL MODE)
# ==============================================================================

def load_user_sessions() -> dict:
    """Loads all user sessions from normal_mode_sessions.json."""
    try:
        with open(USER_SESSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def load_user_session(telegram_user_id: int) -> Optional[dict]:
    """Load a specific user's session data."""
    try:
        with open(USER_SESSIONS_FILE, "r", encoding="utf-8") as f:
            all_sessions = json.load(f)
            return all_sessions.get(str(telegram_user_id))
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def save_user_sessions(sessions: dict):
    """Saves the entire sessions dictionary to file."""
    with open(USER_SESSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2)
    logger.info("Saved user sessions")

def save_user_session(telegram_user_id: int, session_data: dict):
    """Updates/Saves a single user's session data."""
    try:
        all_sessions = load_user_sessions()
        all_sessions[str(telegram_user_id)] = session_data
        save_user_sessions(all_sessions)
        logger.info(f"Saved session for Telegram user {telegram_user_id}")
    except Exception as e:
        logger.error(f"Failed to save session for Telegram user {telegram_user_id}: {e}")

# ==============================================================================
# SESSION MANAGEMENT (SHARED MODE)
# ==============================================================================

def load_shared_session() -> Optional[dict]:
    """Loads the shared session from shared_mode_session.json."""
    try:
        with open(SHARED_SESSION_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def save_shared_session(session_data: dict):
    """Saves the shared session data."""
    with open(SHARED_SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(session_data, f, indent=2)
    logger.info("Saved shared session")

def clear_shared_session():
    """Clear the shared session data (logout for shared mode)."""
    if os.path.exists(SHARED_SESSION_FILE):
        try:
            os.remove(SHARED_SESSION_FILE)
            logger.info("Cleared shared session")
        except OSError as e:
            logger.error(f"Error removing shared session file: {e}")

# ==============================================================================
# USER SELECTION MANAGEMENT (API MODE)
# ==============================================================================

def load_user_selections() -> dict:
    """
    Load a dict from api_mode_selections.json.
    Format: { "<telegram_user_id>": { "userId": 10, "userName": "DisplayName" } }
    """
    if not os.path.exists(USER_SELECTION_FILE):
        return {}
    try:
        with open(USER_SELECTION_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning("api_mode_selections.json not found or invalid. Returning empty dictionary.")
        return {}

def save_user_selection(telegram_user_id: int, overseerr_user_id: int, user_name: str):
    """
    Store the user's Overseerr selection mapping.
    """
    data = load_user_selections()
    data[str(telegram_user_id)] = {
        "userId": overseerr_user_id,
        "userName": user_name
    }
    try:
        with open(USER_SELECTION_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Saved user selection for Telegram user {telegram_user_id}: (Overseerr user {overseerr_user_id})")
    except Exception as e:
        logger.error(f"Failed to save user selection: {e}")

def get_saved_user_for_telegram_id(telegram_user_id: int) -> Tuple[Optional[int], Optional[str]]:
    """
    Return (overseerr_user_id, overseerr_user_name) or (None, None) if not found.
    """
    data = load_user_selections()
    entry = data.get(str(telegram_user_id))
    if entry:
        return entry["userId"], entry["userName"]
    return None, None