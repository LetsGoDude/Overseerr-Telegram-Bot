import httpx
import urllib.parse
import logging
from typing import Optional, List, Dict, Tuple
import uuid

# Import directly from bot_settings
import bot_settings
from bot_settings import (
    OVERSEERR_API_URL,
    OVERSEERR_API_KEY,
    logger
)

# ==============================================================================
# USER FETCHING
# ==============================================================================

async def get_overseerr_users() -> List[Dict]:
    """
    Fetch all Overseerr users via /api/v1/user.
    Returns a list of users or an empty list on error.
    """
    try:
        url = f"{OVERSEERR_API_URL}/user?take=256"
        logger.info(f"Fetching Overseerr users from: {url}")
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers={"X-Api-Key": OVERSEERR_API_KEY},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            results = data.get("results", [])
            logger.info(f"Fetched {len(results)} Overseerr users.")
            return results
    except httpx.HTTPError as e:
        logger.error(f"Error fetching Overseerr users: {e}")
        return []

# ==============================================================================
# SEARCH & PROCESSING
# ==============================================================================

async def search_media(media_name: str) -> Optional[Dict]:
    """
    Search for media by title in Overseerr.
    Returns the JSON result or None on error.
    """
    try:
        logger.info(f"Searching for media: {media_name}")
        query_params = {'query': media_name}
        encoded_query = urllib.parse.urlencode(query_params, quote_via=urllib.parse.quote)
        url = f"{OVERSEERR_API_URL}/search?{encoded_query}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers={"X-Api-Key": OVERSEERR_API_KEY},
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as e:
        logger.error(f"Error during media search: {e}")
        return None

def process_search_results(results: List[Dict]) -> List[Dict]:
    """
    Process Overseerr search results into a simplified list of dicts.
    Note: This remains synchronous (def) because it's purely CPU processing, no I/O.
    """
    processed_results = []
    for result in results:
        media_title = (
            result.get("name")
            or result.get("originalName")
            or result.get("title")
            or "Unknown Title"
        )

        date_key = "firstAirDate" if result["mediaType"] == "tv" else "releaseDate"
        full_date_str = result.get(date_key, "")  # e.g. "2024-05-12"

        # Extract just the year from the date (if it exists)
        media_year = full_date_str.split("-")[0] if "-" in full_date_str else "Unknown Year"

        media_info = result.get("mediaInfo", {})
        overseerr_media_id = media_info.get("id")
        hd_status = media_info.get("status", 1) # Default to UNKNOWN (1)
        uhd_status = media_info.get("status4k", 1)

        processed_results.append({
            "title": media_title,
            "year": media_year,
            "id": result["id"],  # usually the TMDb ID
            "mediaType": result["mediaType"],
            "poster": result.get("posterPath"),
            "description": result.get("overview", "No description available"),
            "overseerr_id": overseerr_media_id,
            "release_date_full": full_date_str,
            "status_hd": hd_status,
            "status_4k": uhd_status
        })

    logger.info(f"Processed {len(results)} search results.")
    return processed_results

# ==============================================================================
# AUTHENTICATION
# ==============================================================================

async def overseerr_login(email: str, password: str) -> Optional[str]:
    """
    Performs a login via the Overseerr API and returns the session cookie.
    """
    url = f"{OVERSEERR_API_URL}/auth/local"
    payload = {"email": email, "password": password}
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            # httpx cookies work slightly differently but .get on jar usually works or simple dict access
            # We iterate to find the specific cookie if needed, but dictionary access is easiest for a single cookie
            cookie = response.cookies.get("connect.sid")
            logger.info(f"Login successful for {email}")
            return cookie
    except httpx.HTTPError as e:
        logger.error(f"Login failed for {email}: {e}")
        return None

async def overseerr_logout(session_cookie: str) -> bool:
    """Performs a logout via the Overseerr API."""
    url = f"{OVERSEERR_API_URL}/auth/logout"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers={"Cookie": f"connect.sid={session_cookie}"},
                timeout=10
            )
            response.raise_for_status()
            logger.info("Logout successful")
            return True
    except httpx.HTTPError as e:
        logger.error(f"Logout failed: {e}")
        return False

async def check_session_validity(session_cookie: str) -> bool:
    """Checks if the session cookie is valid by making a simple API request."""
    url = f"{OVERSEERR_API_URL}/auth/me"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers={"Cookie": f"connect.sid={session_cookie}"},
                timeout=5
            )
            response.raise_for_status()
            return True
    except httpx.HTTPError:
        return False

# ==============================================================================
# REQUESTS & ISSUES
# ==============================================================================

async def request_media(
    media_id: int, 
    media_type: str, 
    requested_by: int = None, 
    is4k: bool = False, 
    session_cookie: str = None
) -> Tuple[bool, str]:
    """
    Sends a media request to Overseerr.
    """
    payload = {"mediaType": media_type, "mediaId": media_id, "is4k": is4k}
    
    if requested_by is not None:
        payload["userId"] = requested_by
    
    if media_type == "tv":
        payload["seasons"] = "all"

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    
    if session_cookie:
        headers["Cookie"] = f"connect.sid={session_cookie}"
    elif bot_settings.CURRENT_MODE == bot_settings.BotMode.API:
        headers["X-Api-Key"] = OVERSEERR_API_KEY
    else:
        return False, "No authentication provided."

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OVERSEERR_API_URL}/request", 
                json=payload, 
                headers=headers, 
                timeout=10
            )
            logger.info(f"Request response: Status {response.status_code}, Body: {response.text}")
            
            if response.status_code == 201:
                return True, "Request successful"
            return False, f"Failed: {response.status_code} - {response.text}"
    except httpx.HTTPError as e:
        logger.error(f"Request failed: {e}")
        return False, f"Error: {str(e)}"

async def create_issue(
    media_id: int, 
    media_type: str, 
    issue_description: str, 
    issue_type: int, 
    telegram_user_id: int = None, 
    session_cookie: str = None
) -> bool:
    """
    Create an issue on Overseerr via the API.
    """
    payload = {
        "mediaId": media_id,
        "mediaType": media_type,
        "issueType": issue_type,
        "message": issue_description,
    }
    if telegram_user_id is not None:
        payload["userId"] = telegram_user_id

    logger.info(f"Sending issue payload to Overseerr: {payload}")

    headers = {"Content-Type": "application/json"}
    
    if session_cookie and bot_settings.CURRENT_MODE != bot_settings.BotMode.API:
        headers["Cookie"] = f"connect.sid={session_cookie}"
    else:
        headers["X-Api-Key"] = OVERSEERR_API_KEY

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OVERSEERR_API_URL}/issue",
                headers=headers,
                json=payload,
                timeout=10,
            )
            response.raise_for_status()
            logger.info(f"Issue creation successful for mediaId {media_id}.")
            return True
    except httpx.HTTPError as e:
        logger.error(f"Error during issue creation: {e}")
        return False

# ==============================================================================
# NOTIFICATIONS & VERSION CHECK
# ==============================================================================

async def get_latest_version_from_github() -> str:
    """
    Check GitHub releases to find the latest version name (if any).
    """
    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.get(
                "https://api.github.com/repos/LetsGoDude/OverseerrRequestViaTelegramBot/releases/latest",
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            latest_version = data.get("tag_name", "")
            return latest_version
    except httpx.HTTPError as e:
        logger.warning(f"Failed to check latest version on GitHub: {e}")
        return ""

async def get_global_telegram_notifications() -> Optional[Dict]:
    """
    Retrieves the current global Telegram notification settings from Overseerr.
    """
    try:
        url = f"{OVERSEERR_API_URL}/settings/notifications/telegram"
        headers = {
            "X-Api-Key": OVERSEERR_API_KEY
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            settings = response.json()
            logger.info(f"Current Global Telegram notification settings: {settings}")
            return settings
    except httpx.HTTPError as e:
        logger.error(f"Error when retrieving Telegram notification settings: {e}")
        return None

async def set_global_telegram_notifications(bot_username: str, telegram_token: str, chat_id: str) -> bool:
    """
    Activates the global Telegram notifications in Overseerr.
    """
    payload = {
        "enabled": True,
        "types": 1,
        "options": {
            "botUsername": bot_username,
            "botAPI": telegram_token,
            "chatId": chat_id,
            "sendSilently": True
        }
    }
    try:
        url = f"{OVERSEERR_API_URL}/settings/notifications/telegram"
        headers = {
            "Content-Type": "application/json",
            "X-Api-Key": OVERSEERR_API_KEY
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Global Telegram notifications have been successfully activated.")
            return True
    except httpx.HTTPError as e:
        logger.error(f"Error when activating global Telegram notifications: {e}")
        return False

async def get_user_notification_settings(overseerr_user_id: int) -> Dict:
    """
    Fetch the user's notification settings from Overseerr.
    """
    try:
        url = f"{OVERSEERR_API_URL}/user/{overseerr_user_id}/settings/notifications"
        headers = {
            "X-Api-Key": OVERSEERR_API_KEY,
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            logger.info(f"Fetched notification settings for Overseerr user {overseerr_user_id}: {data}")
            return data
    except httpx.HTTPError as e:
        logger.error(f"Failed to fetch settings for user {overseerr_user_id}: {e}")
        return {}

async def update_telegram_settings_for_user(
    overseerr_user_id: int,
    telegram_bitmask: int,
    chat_id: str,
    send_silently: bool
) -> bool:
    """
    Sends a partial update to user notification settings.
    """
    payload = {
        "notificationTypes": {
            "telegram": telegram_bitmask
        },
        "telegramEnabled": True,
        "telegramChatId": chat_id,
        "telegramSendSilently": send_silently
    }

    url = f"{OVERSEERR_API_URL}/user/{overseerr_user_id}/settings/notifications"
    headers = {
        "X-Api-Key": OVERSEERR_API_KEY,
        "Content-Type": "application/json"
    }
    logger.info(f"Updating user {overseerr_user_id} with payload: {payload}")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            logger.info(f"Successfully updated telegram bitmask for user {overseerr_user_id}.")
            return True
    except httpx.HTTPError as e:
        logger.error(f"Failed to update telegram bitmask for user {overseerr_user_id}: {e}")
        return False
    

# ==============================================================================
# PLEX AUTHENTICATION FLOW
# ==============================================================================

# Generate a unique client identifier so Plex recognizes this specific bot instance
CLIENT_IDENTIFIER = str(uuid.uuid4())
PLEX_PRODUCT_NAME = "Overseerr-Telegram-Bot"

async def get_plex_auth_pin() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Request a PIN and Auth-URL from plex.tv.
    Returns: (pin_id, code, auth_url)
    """
    url = "https://plex.tv/api/v2/pins"
    headers = {
        "X-Plex-Product": PLEX_PRODUCT_NAME,
        "X-Plex-Client-Identifier": CLIENT_IDENTIFIER,
        "Accept": "application/json"
    }
    # 'strong=true' ensures we get a secure PIN flow
    params = {"strong": "true"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, headers=headers, params=params, timeout=10)
            if response.status_code == 201:
                data = response.json()
                pin_id = data.get("id")
                code = data.get("code")
                # Construct the official Plex auth URL
                auth_url = (
                    f"https://app.plex.tv/auth#?clientID={CLIENT_IDENTIFIER}"
                    f"&code={code}"
                    f"&context%5Bdevice%5D%5Bproduct%5D={PLEX_PRODUCT_NAME}"
                )
                return pin_id, code, auth_url
    except httpx.HTTPError as e:
        logger.error(f"Plex PIN request failed: {e}")
    
    return None, None, None

async def check_plex_pin(pin_id: int) -> Optional[str]:
    """
    Checks if the user has authorized the PIN on plex.tv.
    Returns the Plex authToken if authorized, else None.
    """
    url = f"https://plex.tv/api/v2/pins/{pin_id}"
    headers = {
        "X-Plex-Product": PLEX_PRODUCT_NAME,
        "X-Plex-Client-Identifier": CLIENT_IDENTIFIER,
        "Accept": "application/json"
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                # The 'authToken' field is only present if the user confirmed the login
                return data.get("authToken")
    except httpx.HTTPError as e:
        logger.error(f"Plex PIN check failed: {e}")
    
    return None

async def overseerr_login_via_plex(plex_token: str) -> Optional[str]:
    """
    Exchanges the Plex Auth Token for an Overseerr Session Cookie.
    """
    url = f"{OVERSEERR_API_URL}/auth/plex"
    payload = {"authToken": plex_token}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            cookie = response.cookies.get("connect.sid")
            logger.info("Plex Login successful")
            return cookie
    except httpx.HTTPError as e:
        logger.error(f"Overseerr Plex Login failed: {e}")
        return None