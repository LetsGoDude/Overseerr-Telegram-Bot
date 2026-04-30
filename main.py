import logging
import base64
import os
import httpx # NEW IMPORT for manual requests in login
from datetime import datetime, timezone
from typing import Optional
import i18n

from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    CallbackQuery,
)
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# ==============================================================================
# IMPORTS FROM OUR NEW MODULES
# ==============================================================================
import bot_settings
from bot_settings import (
    VERSION, BUILD, TELEGRAM_TOKEN, PASSWORD,
    DEFAULT_POSTER_URL,
    ISSUE_TYPES,
    PERMISSION_4K_MOVIE, PERMISSION_4K_TV,
    I18N_DIR, I18N_OVERRIDE_DIR, APP_LOCALE,
    BotMode, MediaStatus, # Wir behalten nur MediaStatus
    logger
)

# Utility Functions (Local Files)
from utils import (
    load_config, save_config,
    load_user_sessions, load_user_session, save_user_sessions, save_user_session, # Hier fehlte load_user_sessions
    load_shared_session, save_shared_session, clear_shared_session,
    load_user_selections, save_user_selection, get_saved_user_for_telegram_id,
    is_command_allowed, user_is_authorized, ensure_data_directory
)

# API Functions (Overseerr Communication)
# NOTE: All these are now async and must be awaited!
from overseerr_api import (
    get_overseerr_users, search_media, process_search_results,
    overseerr_login, overseerr_logout, check_session_validity,
    request_media, create_issue,
    get_latest_version_from_github,
    get_global_telegram_notifications, set_global_telegram_notifications,
    get_user_notification_settings, update_telegram_settings_for_user,
    get_plex_auth_pin, check_plex_pin, overseerr_login_via_plex
)

i18n.load_path.append(I18N_DIR)
i18n.load_path.append(I18N_OVERRIDE_DIR)
i18n.set('locale', APP_LOCALE)
i18n.set('fallback', 'en')

# ==============================================================================
# HELPER: SEND WELCOME MESSAGE
# ==============================================================================
async def send_welcome_message(context: ContextTypes.DEFAULT_TYPE, chat_id: int, message_thread_id: Optional[int] = None, show_login_button: bool = False):
    """
    Centralized function to generate and send the welcome message.
    """
    # Version Check (Async)
    latest_ver = await get_latest_version_from_github()
    newer_ver_text = f"\n{i18n.t('messages.version_available', version=latest_ver)}" if latest_ver and latest_ver.lstrip("v") > VERSION else ""

    text = i18n.t('messages.welcome_message', current_version=VERSION, newer_version=newer_ver_text)

    reply_markup = None
    if show_login_button:
        reply_markup = InlineKeyboardMarkup([[InlineKeyboardButton(i18n.t('auth.login_button'), callback_data="login")]])

    await send_message(context, chat_id, text, reply_markup=reply_markup, message_thread_id=message_thread_id)


# ==============================================================================
# HELPER: SEND MESSAGE
# ==============================================================================
async def send_message(context: ContextTypes.DEFAULT_TYPE, chat_id: int, text: str, reply_markup=None, allow_sending=True, message_thread_id: Optional[int]=None):
    """
    Sends a message. Redirects to primary_chat_id if Group Mode is enabled,
    UNLESS the target is an Admin in a private chat.
    Returns the Message object so we can delete it later.
    """
    if not allow_sending:
        logger.debug(f"Skipped sending message to chat {chat_id}: sending not allowed")
        return None  # Return None if blocked

    conf = load_config()
    
    # Check if we should redirect
    if conf["group_mode"] and conf["primary_chat_id"]["chat_id"] is not None:
        primary_id = conf["primary_chat_id"]["chat_id"]
        primary_thread = conf["primary_chat_id"]["message_thread_id"]
        
        is_target_admin = conf["users"].get(str(chat_id), {}).get("is_admin", False)
        is_private_chat = chat_id > 0 
        
        if is_target_admin and is_private_chat:
            pass # Send directly
        elif chat_id == primary_id:
            pass # Already group
        else:
            # Redirect
            chat_id = primary_id
            message_thread_id = primary_thread

    try:
        kwargs = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "reply_markup": reply_markup
        }
        if message_thread_id is not None:
            kwargs["message_thread_id"] = message_thread_id
        
        return await context.bot.send_message(**kwargs)

    except Exception as e:
        logger.error(f"Failed to send message to chat {chat_id}, thread {message_thread_id}: {e}")
        return None

# ==============================================================================
# STARTUP LOADER (Middleware)
# ==============================================================================
async def user_data_loader(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Load user data, including session data and user selections, at the start of each update.
    Ensures overseerr_telegram_user_id is available across restarts.
    """
    if not update.effective_user and not (update.callback_query and update.callback_query.from_user):
        return

    telegram_user_id = update.effective_user.id if update.effective_user else update.callback_query.from_user.id
    
    # Normal mode: Load session data
    if bot_settings.CURRENT_MODE == BotMode.NORMAL:
        session_data = load_user_session(telegram_user_id)
        if session_data and "cookie" in session_data:
            context.user_data["session_data"] = session_data
            context.user_data["overseerr_telegram_user_id"] = session_data.get("overseerr_telegram_user_id")
            context.user_data["overseerr_user_name"] = session_data.get("overseerr_user_name", "Unknown")

    # API mode: Load user selection
    elif bot_settings.CURRENT_MODE == BotMode.API:
        overseerr_telegram_user_id, overseerr_user_name = get_saved_user_for_telegram_id(telegram_user_id)
        if overseerr_telegram_user_id:
            context.user_data["overseerr_telegram_user_id"] = overseerr_telegram_user_id
            context.user_data["overseerr_user_name"] = overseerr_user_name

    # Shared mode: Load shared session (global)
    elif bot_settings.CURRENT_MODE == BotMode.SHARED:
        shared_session = load_shared_session()
        if shared_session and "cookie" in shared_session:
            context.application.bot_data["shared_session"] = shared_session
            context.user_data["overseerr_telegram_user_id"] = shared_session.get("overseerr_telegram_user_id")
            context.user_data["overseerr_user_name"] = shared_session.get("overseerr_user_name", "Shared User")


# ==============================================================================
# NOTIFICATION LOGIC
# ==============================================================================
# WARNING: We cannot await at module level. We initialize this lazily or via a startup hook.
# For now, we set it to None and load it when needed.
GLOBAL_TELEGRAM_NOTIFICATION_STATUS = None

async def enable_global_telegram_notifications(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Activates global Telegram notifications if not already enabled.
    """
    global GLOBAL_TELEGRAM_NOTIFICATION_STATUS
    
    # Initialize if not set
    if GLOBAL_TELEGRAM_NOTIFICATION_STATUS is None:
        GLOBAL_TELEGRAM_NOTIFICATION_STATUS = await get_global_telegram_notifications()

    if GLOBAL_TELEGRAM_NOTIFICATION_STATUS:
        enabled = GLOBAL_TELEGRAM_NOTIFICATION_STATUS.get("enabled", False)
        if enabled:
            logger.info("Global Telegram notifications are already activated.")
        else:
            logger.info("Activate global Telegram notifications...")
            
            bot_info = await context.bot.get_me()
            chat_id = str(update.effective_chat.id)
            
            success = await set_global_telegram_notifications(bot_info.username, TELEGRAM_TOKEN, chat_id)
            if success:
                GLOBAL_TELEGRAM_NOTIFICATION_STATUS = await get_global_telegram_notifications()
    else:
        # Retry fetching if it failed initially
        GLOBAL_TELEGRAM_NOTIFICATION_STATUS = await get_global_telegram_notifications()

# ==============================================================================
# AUTH & LOGIN FLOWS
# ==============================================================================
async def start_login(update_or_query: Update | CallbackQuery, context: ContextTypes.DEFAULT_TYPE):
    """Shows the login method selection menu."""
    # 1. Determine IDs cleanly (depending on the type of call)
    if isinstance(update_or_query, Update):
        # Call via command (Nachricht)
        telegram_user_id = update_or_query.effective_user.id
        chat_id = update_or_query.effective_chat.id
        message = update_or_query.message
    else:
        # Call via button (CallbackQuery)
        telegram_user_id = update_or_query.from_user.id
        chat_id = update_or_query.message.chat_id
        message = update_or_query.message

    # Cleanup old messages if it's a callback
    if isinstance(update_or_query, CallbackQuery):
        try: await message.delete()
        except Exception: pass

    # Check restrictions (API Mode / Shared Admin)
    if bot_settings.CURRENT_MODE == BotMode.API:
        await context.bot.send_message(chat_id, "In API Mode, no login is required.")
        return

    if bot_settings.CURRENT_MODE == BotMode.SHARED:
        conf = load_config()
        user_id_str = str(telegram_user_id)
        user = conf["users"].get(user_id_str, {})
        if not user.get("is_admin", False):
            await context.bot.send_message(chat_id, "In Shared Mode, only admins can log in.")
            return

    text = i18n.t('auth.login_method_desc')
    
    keyboard = [
        [InlineKeyboardButton(i18n.t('auth.login_email_password_btn'), callback_data="login_method_email")],
        [InlineKeyboardButton(i18n.t('auth.login_plex_btn'), callback_data="login_method_plex")],
        [InlineKeyboardButton(i18n.t('messages.cancel_btn'), callback_data="cancel_settings")]
    ]
    
    await context.bot.send_message(chat_id, text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

# ==============================================================================
# TEXT INPUT HANDLER
# ==============================================================================
async def handle_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    telegram_user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    message_thread_id = getattr(update.message, "message_thread_id", None)
    text = update.message.text
    
    conf = load_config()
    user_id_str = str(telegram_user_id)
    user = conf["users"].get(user_id_str, {})

    current_username = update.effective_user.username or update.effective_user.full_name
    if not user or user.get("username") != current_username:
        conf["users"][user_id_str] = {
            "username": current_username,
            "is_authorized": user.get("is_authorized", False),
            "is_blocked": user.get("is_blocked", False),
            "is_admin": user.get("is_admin", False),
            "created_at": user.get("created_at", datetime.now(timezone.utc).isoformat() + "Z")
        }
        save_config(conf)
        user = conf["users"][user_id_str]

    # 1. Handle Issue Reporting
    if 'reporting_issue' in context.user_data:
        issue_description = text
        reporting_issue = context.user_data['reporting_issue']
        issue_type_id = reporting_issue['issue_type']
        
        selected_result = context.user_data.get('selected_result')
        if not selected_result:
            await update.message.reply_text(i18n.t('reports.issue_report_error'))
            return

        media_id = selected_result.get('overseerr_id')
        media_title = selected_result['title']
        media_type = selected_result['mediaType']

        telegram_user_id_for_issue = context.user_data.get("overseerr_telegram_user_id")
        user_display_name = context.user_data.get("overseerr_user_name", "Unknown User")
        
        final_issue_description = i18n.t('reports.issue_report_final', user_name=user_display_name, issue_description=issue_description)

        success = await create_issue(
            media_id=media_id,
            media_type=media_type,
            issue_description=final_issue_description,
            issue_type=issue_type_id,
            telegram_user_id=telegram_user_id_for_issue
        )

        if success:
            await update.message.reply_text(i18n.t('reports.issue_report_success', media_title=media_title), parse_mode="Markdown")
        else:
            await update.message.reply_text(i18n.t('reports.issue_report_failure', media_title=media_title), parse_mode="Markdown")

        context.user_data.pop('reporting_issue', None)
        context.user_data.pop('selected_result', None)
        
        media_message_id = context.user_data.get('media_message_id')
        if media_message_id:
            try:
                await context.bot.delete_message(chat_id=chat_id, message_id=media_message_id)
            except Exception: pass
        context.user_data.pop('media_message_id', None)
        return

      # 2. Handle Password Authentication
    if context.user_data.get("awaiting_password"):
        if text == PASSWORD:
            is_admin = user.get("is_admin", False)
            if not user.get("is_authorized", False):
                conf["users"][user_id_str]["is_authorized"] = True
                conf["users"][user_id_str]["is_blocked"] = False
                save_config(conf)
                logger.info(f"User {telegram_user_id} authorized via password.")
            
            context.user_data.pop("awaiting_password")
            
            # --- PRIVAT: Erfolg ---
            await context.bot.send_message(chat_id, i18n.t('auth.login_success_private'), parse_mode="Markdown")
            
            # --- GRUPPE: Aufräumen & Begrüßen ---
            grp_msg_id = context.user_data.get("auth_group_msg_id")
            grp_chat_id = context.user_data.get("auth_group_chat_id")
            
            if grp_msg_id and grp_chat_id:
                try: await context.bot.delete_message(chat_id=grp_chat_id, message_id=grp_msg_id)
                except Exception: pass
            
            if grp_chat_id:
                try:
                    # 1. Info-Nachricht
                    name_escaped = current_username.replace("_", "\\_").replace("*", "\\*")
                    await context.bot.send_message(
                        chat_id=grp_chat_id,
                        text=i18n.t('auth.login_success_group', user_name=name_escaped),
                        parse_mode="Markdown"
                    )

                    # 2. Die STANDARD Welcome Message (wiederverwendet!)
                    # Hier zeigen wir KEINEN Login-Button an, da der User ja gerade auth hat.
                    await send_welcome_message(context, grp_chat_id, show_login_button=False)

                except Exception as e:
                    logger.warning(f"Could not send success messages to group: {e}")

            context.user_data.pop("auth_group_msg_id", None)
            context.user_data.pop("auth_group_chat_id", None)

            try: await context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
            except Exception: pass
            
            if not is_admin and bot_settings.CURRENT_MODE == BotMode.API:
                await handle_change_user(update, context, is_initial=True)
            
        else:
            await context.bot.send_message(chat_id, i18n.t('auth.login_failure'), parse_mode="Markdown")
            try: await context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
            except Exception: pass
        return

    # 3. Check Group Mode Restrictions
    if not is_command_allowed(chat_id, message_thread_id, conf, telegram_user_id):
        return

    # 4. Handle Overseerr Login Steps
    if "login_step" in context.user_data:
        if "login_message_id" in context.user_data:
            try:
                await context.bot.delete_message(chat_id, context.user_data["login_message_id"])
            except Exception: pass
        try:
            await context.bot.delete_message(chat_id, update.message.message_id)
        except Exception: pass

        is_admin = user.get("is_admin", False)

        if context.user_data["login_step"] == "email":
            context.user_data["login_email"] = text
            context.user_data["login_step"] = "password"
            msg = await context.bot.send_message(chat_id, i18n.t('auth.seerr_password_prompt'), parse_mode="Markdown")
            context.user_data["login_message_id"] = msg.message_id
        
        elif context.user_data["login_step"] == "password":
            email = context.user_data["login_email"]
            password = text
            session_cookie = await overseerr_login(email, password)
            
            if session_cookie:
                credentials = base64.b64encode(f"{email}:{password}".encode()).decode()
                
                # Fetch user details manual (async with httpx)
                try:
                    async with httpx.AsyncClient() as client:
                        me_resp = await client.get(
                            f"{bot_settings.OVERSEERR_API_URL}/auth/me",
                            headers={"Cookie": f"connect.sid={session_cookie}"},
                            timeout=10
                        )
                        me_resp.raise_for_status()
                        user_info = me_resp.json()
                        overseerr_id = user_info.get("id")
                    
                    if not overseerr_id:
                        raise ValueError("No ID in response")

                    session_data = {
                        "cookie": session_cookie,
                        "credentials": credentials,
                        "overseerr_telegram_user_id": overseerr_id,
                        "overseerr_user_name": user_info.get("displayName", "Unknown")
                    }
                    context.user_data["session_data"] = session_data
                    
                    if bot_settings.CURRENT_MODE == BotMode.NORMAL:
                        save_user_session(telegram_user_id, session_data)
                    elif bot_settings.CURRENT_MODE == BotMode.SHARED and is_admin:
                        save_shared_session(session_data)
                        context.application.bot_data["shared_session"] = session_data
                    
                    await context.bot.send_message(chat_id, i18n.t('auth.seerr_login_success', user_name=user_info.get('displayName', 'Unknown')), parse_mode="Markdown")
                except Exception as e:
                    logger.error(f"Error fetching user info after login: {e}")
                    await context.bot.send_message(chat_id, i18n.t('auth.seerr_login_success_user_failure'), parse_mode="Markdown")
            else:
                await context.bot.send_message(chat_id, i18n.t('auth.seerr_login_failure'), parse_mode="Markdown")
            
            context.user_data.pop("login_step", None)
            context.user_data.pop("login_email", None)
            context.user_data.pop("login_message_id", None)
            
            await show_settings_menu(update, context, is_admin=is_admin)
        return

    await update.message.reply_text(i18n.t('messages.unknown_command'))

# ==============================================================================
# USER MANAGEMENT MENU (Admin)
# ==============================================================================
async def show_user_management_menu(update_or_query, context: ContextTypes.DEFAULT_TYPE, offset=0):
    conf = load_config()
    if isinstance(update_or_query, Update):
        telegram_user_id = update_or_query.effective_user.id
        chat_id = update_or_query.effective_chat.id
        message_thread_id = getattr(update_or_query.message, "message_thread_id", None)
    else:
        telegram_user_id = update_or_query.from_user.id
        chat_id = update_or_query.message.chat_id
        message_thread_id = getattr(update_or_query.message, "message_thread_id", None)

    if not conf["users"].get(str(telegram_user_id), {}).get("is_admin", False):
        await send_message(context, chat_id, i18n.t('admin.userman_only_admins_error'), message_thread_id=message_thread_id)
        return

    users_list = [
        {
            "telegram_id": uid,
            "username": details.get("username", "Unknown"),
            "is_admin": details.get("is_admin", False),
            "is_blocked": details.get("is_blocked", False)
        }
        for uid, details in conf["users"].items()
    ]

    page_size = 5
    total_users = len(users_list)
    current_users = users_list[offset:offset + page_size]

    text = i18n.t('admin.userman_body') if users_list else i18n.t('admin.userman_body_no_users')
    keyboard = []
    
    for u in current_users:
        status = i18n.t('admin.userman_status_blocked') if u["is_blocked"] else i18n.t('admin.userman_status_admin') if u["is_admin"] else i18n.t('admin.userman_status_user')
        btn_txt = f"{u['username']} (ID: {u['telegram_id']}) - {status}"
        keyboard.append([InlineKeyboardButton(btn_txt, callback_data=f"manage_user_{u['telegram_id']}")])

    keyboard.append([InlineKeyboardButton(i18n.t('admin.userman_create_user_btn'), callback_data="create_user")])

    nav_buttons = []
    if offset > 0:
        nav_buttons.append(InlineKeyboardButton(i18n.t('messages.back_btn'), callback_data=f"users_page_{offset - page_size}"))
    if offset + page_size < total_users:
        nav_buttons.append(InlineKeyboardButton(i18n.t('messages.more_btn'), callback_data=f"users_page_{offset + page_size}"))
    
    nav_buttons.append(InlineKeyboardButton(i18n.t('admin.userman_back_to_settings_btn'), callback_data="back_to_settings"))
    if nav_buttons:
        keyboard.append(nav_buttons)

    reply_markup = InlineKeyboardMarkup(keyboard)

    if isinstance(update_or_query, Update):
        await send_message(context, chat_id, text, reply_markup=reply_markup, message_thread_id=message_thread_id)
    else:
        await update_or_query.edit_message_text(text, parse_mode="Markdown", reply_markup=reply_markup)

async def manage_specific_user(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE, target_telegram_id: str):
    conf = load_config()
    telegram_user_id = query.from_user.id
    
    # Security check
    if not conf["users"].get(str(telegram_user_id), {}).get("is_admin", False):
        await query.edit_message_text(i18n.t('admin.userman_only_admins_error'))
        return

    # Load target data
    user = conf["users"].get(target_telegram_id, {})
    username = user.get("username", "Unknown")
    is_admin = user.get("is_admin", False)
    is_blocked = user.get("is_blocked", False)
    is_auth = user.get("is_authorized", False)
    created_raw = user.get("created_at", "").split("T")[0] # Simple date formatting

    # Status Determination
    if is_blocked:
        status_line = i18n.t('admin.userman_status_blocked')
    elif is_admin:
        status_line = i18n.t('admin.userman_status_admin')
    elif is_auth:
        status_line = i18n.t('admin.userman_status_user')
    else:
        status_line = i18n.t('admin.userman_status_guest')

    text = i18n.t('admin.userman_edit_body', username=username, telegram_id=target_telegram_id, joined_date=created_raw, user_status=status_line)

    keyboard = []
    
    # Logic: Toggle Block
    if is_blocked:
        keyboard.append([InlineKeyboardButton(i18n.t('admin.userman_edit_action_unblock_btn'), callback_data=f"unblock_user_{target_telegram_id}")])
    else:
        keyboard.append([InlineKeyboardButton(i18n.t('admin.userman_edit_action_block_btn'), callback_data=f"block_user_{target_telegram_id}")])
    
    # Logic: Toggle Admin (prevent self-demotion if not careful, but logic handled in callback)
    if is_admin and target_telegram_id != str(telegram_user_id):
        keyboard.append([InlineKeyboardButton(i18n.t('admin.userman_edit_action_demote_btn'), callback_data=f"demote_user_{target_telegram_id}")])
    elif not is_admin and not is_blocked:
        keyboard.append([InlineKeyboardButton(i18n.t('admin.userman_edit_action_promote_btn'), callback_data=f"promote_user_{target_telegram_id}")])
    
    keyboard.append([InlineKeyboardButton(i18n.t('admin.userman_edit_action_back_btn'), callback_data="manage_users")])

    reply_markup = InlineKeyboardMarkup(keyboard)
    await query.edit_message_text(text, parse_mode="Markdown", reply_markup=reply_markup)


# ==============================================================================
# COMMAND: /START
# ==============================================================================
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    telegram_user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    message_thread_id = getattr(update.message, "message_thread_id", None)
    
    conf = load_config()

    # --- 1. AUTH CHECK ---
    if PASSWORD and not user_is_authorized(telegram_user_id):
        
        # Case A: User is in a Group Chat
        if chat_id < 0:
            # 1. Delete the user's "/start" message to keep chat clean
            try:
                await context.bot.delete_message(chat_id=chat_id, message_id=update.message.message_id)
            except Exception as e:
                # Happens if bot is not admin or message is too old -> ignore
                logger.debug(f"Could not delete user /start message: {e}")

            # 2. Prepare button for private chat auth
            bot_info = await context.bot.get_me()
            url = f"https://t.me/{bot_info.username}?start=auth"
            kb = [[InlineKeyboardButton(i18n.t('auth.password_prompt_button'), url=url)]]
            
            # 3. Send the prompt to the group
            sent_msg = await send_message(
                context, 
                chat_id, 
                i18n.t('auth.password_prompt_group'), 
                reply_markup=InlineKeyboardMarkup(kb),
                message_thread_id=message_thread_id
            )
            
            # 4. Save message ID to delete it later once auth is complete
            if sent_msg:
                context.user_data["auth_group_msg_id"] = sent_msg.message_id
                context.user_data["auth_group_chat_id"] = chat_id
            return
        
        # Case B: User is in a Private Chat
        else:
            # CHECK: Did the user come via the button (Payload 'auth')?
            # If so, delete the prompt in the group IMMEDIATELY.
            if context.args and "auth" in context.args:
                grp_msg_id = context.user_data.get("auth_group_msg_id")
                grp_chat_id = context.user_data.get("auth_group_chat_id")
                if grp_msg_id and grp_chat_id:
                    try:
                        await context.bot.delete_message(chat_id=grp_chat_id, message_id=grp_msg_id)
                    except Exception: pass
                    # Clear data to avoid double deletion attempts
                    context.user_data.pop("auth_group_msg_id", None)

            # Send password prompt (Directly, bypassing send_message wrapper)
            await context.bot.send_message(
                chat_id=chat_id,
                text=i18n.t('auth.password_prompt'),
                parse_mode="Markdown"
            )
            context.user_data["awaiting_password"] = True
            return
    # ---------------------

    # --- 2. GROUP MODE RESTRICTION ---
    # Check if the user is allowed to issue commands here (if already authorized)
    if not is_command_allowed(chat_id, message_thread_id, conf, telegram_user_id):
        if chat_id > 0 and conf["group_mode"]:
             await context.bot.send_message(chat_id, i18n.t('auth.login_success_groupmode'))
        return

    # --- 3. CONFIGURATION & INIT ---
    
    # Group Mode Init (Only save actual groups, ignore private chats)
    if conf["group_mode"]:
        current_primary = conf["primary_chat_id"].get("chat_id")
        if current_primary is None and chat_id < 0:
            conf["primary_chat_id"] = {
                "chat_id": chat_id,
                "message_thread_id": message_thread_id
            }
            save_config(conf)
            logger.info(f"Group Mode: Set primary chat to {chat_id}")
        elif chat_id > 0:
            logger.debug("Admin started in private chat (Group Mode active but ignored for config)")

    # First Admin Init (If no admin exists yet)
    user_id_str = str(telegram_user_id)
    if not any(u.get("is_admin", False) for u in conf["users"].values()):
        conf["users"][user_id_str] = {
            "username": update.effective_user.username or update.effective_user.full_name,
            "is_authorized": True,
            "is_blocked": False,
            "is_admin": True,
            "created_at": datetime.now(timezone.utc).isoformat() + "Z"
        }
        save_config(conf)
        logger.info(f"Set user {telegram_user_id} as admin")

    await enable_global_telegram_notifications(update, context)

    # --- 4. SEND WELCOME MESSAGE ---
    is_admin = conf["users"].get(user_id_str, {}).get("is_admin", False)
    
    # Show login button only if needed (Normal Mode + not Admin + no active session)
    need_login = (
        bot_settings.CURRENT_MODE == BotMode.NORMAL 
        and not is_admin 
        and "session_data" not in context.user_data
    )
    
    await send_welcome_message(context, chat_id, message_thread_id, show_login_button=need_login)


# ==============================================================================
# SETTINGS & MENUS (PRO DESIGN)
# ==============================================================================
async def show_settings_menu(update_or_query, context: ContextTypes.DEFAULT_TYPE, is_admin=False):
    # 1. Determine User & Chat
    if isinstance(update_or_query, Update):
        telegram_user_id = update_or_query.effective_user.id
        chat_id = update_or_query.effective_chat.id
        message_thread_id = getattr(update_or_query.message, "message_thread_id", None)
    else:
        telegram_user_id = update_or_query.from_user.id
        chat_id = update_or_query.message.chat_id
        message_thread_id = getattr(update_or_query.message, "message_thread_id", None)

    conf = load_config()

    # 2. Permission Checks
    if not is_command_allowed(chat_id, message_thread_id, conf, telegram_user_id):
        return

    user_id_str = str(telegram_user_id)
    user = conf["users"].get(user_id_str, {})
    is_admin = user.get("is_admin", False)

    if bot_settings.CURRENT_MODE == BotMode.SHARED and not is_admin:
        await send_message(context, chat_id, i18n.t('admin.shared_mode_error'), message_thread_id=message_thread_id)
        return

    if PASSWORD and not user_is_authorized(telegram_user_id):
        await send_message(context, chat_id, i18n.t('auth.access_denied'), message_thread_id=message_thread_id)
        return

    # 3. Prepare Data for Dashboard
    overseerr_user_name = context.user_data.get("overseerr_user_name", "Unknown")
    overseerr_id = context.user_data.get("overseerr_telegram_user_id")
    
    # --- ACCOUNT TYPE DETECTION ---
    account_type_icon = ""
    
    if bot_settings.CURRENT_MODE == BotMode.API:
        account_type_icon = " (via 🔑 API)"
    else:
        # Try to find session (User Data oder Shared Data)
        session = context.user_data.get("session_data") or context.application.bot_data.get("shared_session")
        
        if session:
            creds = session.get("credentials", "")
            if creds == "PLEX_AUTH":
                account_type_icon = " (▶️ Plex)"
            elif creds:
                account_type_icon = " (📧 Local)"
    # ------------------------------

    # Connection Status Logic
    if overseerr_id:
        connection_status = i18n.t('controlpanel.connection_status_connected')
        # Anzeige: Name + Account-Typ
        user_display = f"*{overseerr_user_name}*{account_type_icon}"
    else:
        connection_status = i18n.t('controlpanel.connection_status_not_connected')
        user_display = i18n.t('controlpanel.user_display_no_user')

    # Group Mode Logic
    group_support = f"🟢 (ID: `{conf['primary_chat_id']['chat_id']}`)" if conf["group_mode"] else "🔴"

    # Mode Logic & Symbol
    mode_map = {
        BotMode.NORMAL: (i18n.t('controlpanel.mode_normal_symbol'), i18n.t('controlpanel.mode_normal')),
        BotMode.API:    (i18n.t('controlpanel.mode_api_symbol'), i18n.t('controlpanel.mode_api')),
        BotMode.SHARED: (i18n.t('controlpanel.mode_shared_symbol'), i18n.t('controlpanel.mode_shared'))
    }
    mode_sym, mode_desc = mode_map.get(bot_settings.CURRENT_MODE, ("❓", "Unknown"))

    # 4. Build the Dashboard Text
    text = i18n.t('controlpanel.body_user',
                  user_display=user_display,
                  connection_status=connection_status
    )

    # Section: System (Admin only)
    if is_admin:
        startup_notify = "🟢" if conf.get("send_startup_notification") else "🔴"
        bot_mode = f"{mode_sym} *{mode_desc}*"
        text = i18n.t('controlpanel.body_admin',
                        user_display=user_display,
                        connection_status=connection_status,
                        bot_mode=bot_mode,
                        group_support=group_support,
                        startup_notify=startup_notify
        )

    # 5. Build Buttons
    keyboard = []
    
    # Row 1: Account Management
    acc_btns = []
    if bot_settings.CURRENT_MODE == BotMode.API:
        acc_btns.append(InlineKeyboardButton(i18n.t('controlpanel.change_user_btn'), callback_data="change_user"))
    elif bot_settings.CURRENT_MODE == BotMode.NORMAL:
        if context.user_data.get("session_data"):
            acc_btns.append(InlineKeyboardButton(i18n.t('controlpanel.logout_btn'), callback_data="logout"))
        else:
            acc_btns.append(InlineKeyboardButton(i18n.t('controlpanel.login_btn'), callback_data="login"))
    elif bot_settings.CURRENT_MODE == BotMode.SHARED and is_admin:
        if context.application.bot_data.get("shared_session"):
            acc_btns.append(InlineKeyboardButton(i18n.t('controlpanel.logout_btn'), callback_data="logout"))
        else:
            acc_btns.append(InlineKeyboardButton(i18n.t('controlpanel.login_btn'), callback_data="login"))
    if acc_btns:
        keyboard.append(acc_btns)

    # Row 2 & 3: Admin Tools
    if is_admin:
        keyboard.extend([
            [InlineKeyboardButton(i18n.t('controlpanel.change_operation_mode_btn'), callback_data="mode_select")],
            [InlineKeyboardButton(i18n.t('controlpanel.toggle_group_mode_on_btn') if conf['group_mode'] else i18n.t('controlpanel.toggle_group_mode_off_btn'), callback_data="toggle_group_mode")],
            [InlineKeyboardButton(i18n.t('controlpanel.toggle_startup_notify_on_btn') if conf.get('send_startup_notification') else i18n.t('controlpanel.toggle_startup_notify_off_btn'), callback_data="toggle_startup_notify")], # <--- NEUER BUTTON
            [InlineKeyboardButton(i18n.t('controlpanel.userman_btn'), callback_data="manage_users")]
        ])

    # Row 4: Notifications (Only if logged in)
    if overseerr_id:
        keyboard.append([InlineKeyboardButton(i18n.t('controlpanel.notifs_btn'), callback_data="manage_notifications")])

    # Footer
    keyboard.append([InlineKeyboardButton(i18n.t('controlpanel.close_menu_btn'), callback_data="cancel_settings")])
    
    reply_markup = InlineKeyboardMarkup(keyboard)

    # 6. Send/Edit Message
    if isinstance(update_or_query, Update):
        await send_message(context, chat_id, text, reply_markup=reply_markup, message_thread_id=message_thread_id)
    else:
        await update_or_query.edit_message_text(text, parse_mode="Markdown", reply_markup=reply_markup)


# ==============================================================================
# NOTIFICATION MENU
# ==============================================================================
async def show_manage_notifications_menu(update_or_query, context: ContextTypes.DEFAULT_TYPE):
    if isinstance(update_or_query, Update):
        query = None
    else:
        query = update_or_query

    overseerr_id = context.user_data.get("overseerr_telegram_user_id")
    if not overseerr_id:
        msg = i18n.t('notifs.no_selected_user')
        if query: await query.edit_message_text(msg)
        else: await update_or_query.message.reply_text(msg)
        return

    # Fetch fresh settings
    settings = await get_user_notification_settings(overseerr_id)
    if not settings:
        msg = i18n.t('notifs.settings_retrieve_fail')
        if query: await query.edit_message_text(msg)
        else: await update_or_query.message.reply_text(msg)
        return

    # Logic
    tele_bitmask = settings.get("notificationTypes", {}).get("telegram", 0)
    is_enabled = (tele_bitmask != 0)
    is_silent = settings.get("telegramSendSilently", False)

    # Visual Indicators
    status_icon = i18n.t('notifs.icon_active') if is_enabled else i18n.t('notifs.icon_inactive')
    sound_icon = i18n.t('notifs.icon_silent') if is_silent else i18n.t('notifs.icon_standard')
    
    overseerr_name = context.user_data.get("overseerr_user_name", "User")
    text = i18n.t('notifs.notifs_body',
                  user_name=overseerr_name,
                  status_icon=status_icon,
                  sound_icon=sound_icon
    )

    # Dynamic Button Labels
    btn_toggle = i18n.t('notifs.disable_notifs_btn') if is_enabled else i18n.t('notifs.enable_notifs_btn')
    btn_silent = i18n.t('notifs.sound_on_btn') if is_silent else i18n.t('notifs.sound_off_btn')

    keyboard = [
        [InlineKeyboardButton(btn_toggle, callback_data="toggle_user_notifications")],
        [InlineKeyboardButton(btn_silent, callback_data="toggle_user_silent")],
        [InlineKeyboardButton(i18n.t('messages.back_btn'), callback_data="back_to_settings")]
    ]
    
    markup = InlineKeyboardMarkup(keyboard)

    if query:
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=markup)
    else:
        await update_or_query.message.reply_text(text, parse_mode="Markdown", reply_markup=markup)

async def toggle_user_notifications(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE):
    overseerr_id = context.user_data.get("overseerr_telegram_user_id")
    if not overseerr_id: return

    settings = await get_user_notification_settings(overseerr_id)
    current_val = settings.get("notificationTypes", {}).get("telegram", 0)
    new_val = 3657 if current_val == 0 else 0
    
    is_silent = settings.get("telegramSendSilently", False)
    chat_id = str(query.message.chat_id)

    success = await update_telegram_settings_for_user(overseerr_id, new_val, chat_id, is_silent)
    if success:
        await show_manage_notifications_menu(query, context)
    else:
        await query.edit_message_text(i18n.t('notifs.settings_update_fail'))

async def toggle_user_silent(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE):
    overseerr_id = context.user_data.get("overseerr_telegram_user_id")
    if not overseerr_id: return

    settings = await get_user_notification_settings(overseerr_id)
    current_val = settings.get("notificationTypes", {}).get("telegram", 0)
    current_silent = settings.get("telegramSendSilently", False)
    chat_id = str(query.message.chat_id)

    success = await update_telegram_settings_for_user(overseerr_id, current_val, chat_id, not current_silent)
    if success:
        await show_manage_notifications_menu(query, context)
    else:
        await query.edit_message_text(i18n.t('notifs.settings_update_fail'))


# ==============================================================================
# COMMAND: /CHECK (SEARCH)
# ==============================================================================
async def check_media(update: Update, context: ContextTypes.DEFAULT_TYPE):
    telegram_user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    message_thread_id = getattr(update.message, "message_thread_id", None)
    
    conf = load_config()
    if not is_command_allowed(chat_id, message_thread_id, conf, telegram_user_id):
        return

    if PASSWORD and not user_is_authorized(telegram_user_id):
        await send_message(context, chat_id, i18n.t('check.error_auth'), message_thread_id=message_thread_id)
        return

    if "overseerr_telegram_user_id" not in context.user_data:
        await send_message(context, chat_id, i18n.t('check.error_no_user'), message_thread_id=message_thread_id)
        await show_settings_menu(update, context)
        return

    if not context.args:
        await send_message(context, chat_id, i18n.t('check.usage'), message_thread_id=message_thread_id)
        return

    media_name = " ".join(context.args)

    search_data = await search_media(media_name)
    if not search_data:
        await send_message(context, chat_id, i18n.t('check.error_search'), message_thread_id=message_thread_id)
        return

    results = search_data.get("results", [])
    if not results:
        await send_message(context, chat_id, i18n.t('check.error_no_results', media_name=media_name), message_thread_id=message_thread_id)
        return

    processed = process_search_results(results)
    context.user_data["search_results"] = processed
    
    sent = await display_results_with_buttons(update, context, processed, offset=0)
    context.user_data["results_message_id"] = sent.message_id


async def display_results_with_buttons(update_or_query, context, results, offset, new_message=False):
    keyboard = []
    for idx, res in enumerate(results[offset : offset + 5]):
        btn_text = f"{res['title']} ({res['year']})"
        keyboard.append([InlineKeyboardButton(btn_text, callback_data=f"select_{offset + idx}")])

    total = len(results)
    nav_btns = []
    
    if offset > 0:
        nav_btns.append(InlineKeyboardButton(i18n.t('messages.back_btn'), callback_data=f"page_{offset - 5}"))
    
    nav_btns.append(InlineKeyboardButton(i18n.t('messages.cancel_btn'), callback_data="cancel_search"))
    
    if offset + 5 < total:
        nav_btns.append(InlineKeyboardButton(i18n.t('messages.more_btn'), callback_data=f"page_{offset + 5}"))

    if nav_btns: keyboard.append(nav_btns)

    markup = InlineKeyboardMarkup(keyboard)
    text = i18n.t('check.select_result')

    if new_message:
        return await context.bot.send_message(chat_id=update_or_query.message.chat_id, text=text, reply_markup=markup)
    elif isinstance(update_or_query, Update):
        return await update_or_query.message.reply_text(text=text, reply_markup=markup)
    else:
        await update_or_query.edit_message_text(text=text, reply_markup=markup)


async def process_user_selection(update_or_query, context, result, edit_message=False):
    query = update_or_query if isinstance(update_or_query, CallbackQuery) else update_or_query.callback_query
    
    context.user_data["selected_result"] = result
    
    title = result.get("title")
    year = result.get("year")
    desc = result.get("description", "")
    poster = result.get("poster")
    
    status_hd = result.get("status_hd", 1)
    status_4k = result.get("status_4k", 1)

    ov_user_id = context.user_data.get("overseerr_telegram_user_id")
    has_4k = False
    if ov_user_id:
        has_4k = await user_can_request_4k(ov_user_id, result.get("mediaType"))

    # SAUBER: Nutzt jetzt die MediaStatus Klasse
    REQUESTED = [
        MediaStatus.PENDING, 
        MediaStatus.PROCESSING, 
        MediaStatus.PARTIALLY_AVAILABLE, 
        MediaStatus.AVAILABLE
    ]

    def can_req(code): return code not in REQUESTED

    keyboard = []
    req_btns = []
    
    if can_req(status_hd):
        req_btns.append(InlineKeyboardButton(i18n.t('check.library_1080p_label'), callback_data=f"confirm_1080p_{result['id']}"))
    
    if has_4k and can_req(status_4k):
        req_btns.append(InlineKeyboardButton(i18n.t('check.library_4k_label'), callback_data=f"confirm_4k_{result['id']}"))
        
    if has_4k and can_req(status_hd) and can_req(status_4k):
        req_btns.append(InlineKeyboardButton(i18n.t('check.library_both_label'), callback_data=f"confirm_both_{result['id']}"))

    if req_btns: keyboard.append(req_btns)

    if (status_hd in REQUESTED or status_4k in REQUESTED) and result.get("overseerr_id"):
        keyboard.append([InlineKeyboardButton(i18n.t('check.report_btn'), callback_data=f"report_{result.get('overseerr_id')}")])

    keyboard.append([InlineKeyboardButton(i18n.t('messages.back_btn'), callback_data="back_to_results")])

    # Helper function for status text with emojis
    def get_status_text(code):
        try:
            status = MediaStatus(code)
            if status == MediaStatus.AVAILABLE: return i18n.t('check.media_status_available')
            if status == MediaStatus.PARTIALLY_AVAILABLE: return i18n.t('check.media_status_partially_available')
            if status == MediaStatus.PROCESSING: return i18n.t('check.media_status_processing')
            if status == MediaStatus.PENDING: return i18n.t('check.media_status_pending')
            return ""
        except ValueError:
            return ""

    stat_txt = ""
    txt_hd = get_status_text(status_hd)
    txt_4k = get_status_text(status_4k)

    # SMART LABEL LOGIC:
    # If 4K status is UNKNOWN (1), it implies no separate 4K server is configured (Single Server Setup).
    # In this case, labeling the standard status as "1080p" is misleading because the content could be 4K.
    # So we change the label to a generic "Status".
    # If 4K status is KNOWN, we keep the distinction "1080p" vs "4K".
    label_hd = i18n.t('check.library_1080p_label')
    if status_4k == MediaStatus.UNKNOWN:
        label_hd = i18n.t('check.library_only_1080p_label')

    if txt_hd: stat_txt += f"\n• {label_hd}: {txt_hd}"
    if txt_4k: stat_txt += f"\n• {i18n.t('check.library_4k_label')}: {txt_4k}"
    
    msg_text = f"*{title} ({year})*\n\n{desc}\n{stat_txt}"
    markup = InlineKeyboardMarkup(keyboard)
    img_url = f"https://image.tmdb.org/t/p/w500{poster}" if poster else DEFAULT_POSTER_URL

    old_id = context.user_data.get("results_message_id")
    if old_id:
        try: await context.bot.delete_message(query.message.chat_id, old_id)
        except Exception: pass
        context.user_data.pop("results_message_id", None)

    if edit_message:
        if query.message.photo:
            await query.edit_message_caption(caption=msg_text, parse_mode="Markdown", reply_markup=markup)
        else:
            await query.edit_message_text(text=msg_text, parse_mode="Markdown", reply_markup=markup)
        context.user_data["media_message_id"] = query.message.message_id
    else:
        sent = await context.bot.send_photo(chat_id=query.message.chat_id, photo=img_url, caption=msg_text, parse_mode="Markdown", reply_markup=markup)
        context.user_data["media_message_id"] = sent.message_id

async def user_can_request_4k(overseerr_id: int, media_type: str) -> bool:
    users = await get_overseerr_users()
    u = next((x for x in users if x["id"] == overseerr_id), None)
    if not u: return False
    perms = u.get("permissions", 0)
    
    if perms == 2: return True # Admin
    if media_type == "movie": return (perms & PERMISSION_4K_MOVIE) == PERMISSION_4K_MOVIE
    if media_type == "tv": return (perms & PERMISSION_4K_TV) == PERMISSION_4K_TV
    return False

async def mode_select(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE):

    # Link to the specific wiki section
    wiki_url = "https://github.com/LetsGoDude/Overseerr-Telegram-Bot/wiki#operation-modes"

    text = i18n.t('operation_mode.body', wiki_url=wiki_url)

    keyboard = [
        [InlineKeyboardButton(i18n.t('operation_mode.normal_btn'), callback_data="activate_normal")],
        [InlineKeyboardButton(i18n.t('operation_mode.api_btn'), callback_data="activate_api")],
        [InlineKeyboardButton(i18n.t('operation_mode.shared_btn'), callback_data="activate_shared")],
        [InlineKeyboardButton(i18n.t('operation_mode.back_btn'), callback_data="back_to_settings")]
    ]

    await query.edit_message_text(text=text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard), disable_web_page_preview=True)


async def handle_login_method(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE):
    """Handles the selection of the login method."""
    method = query.data
    chat_id = query.message.chat_id

    if method == "login_method_email":
        # Standard Email Flow
        context.user_data["login_step"] = "email"
        msg = await context.bot.send_message(chat_id, i18n.t('auth.email_prompt'), parse_mode="Markdown")
        context.user_data["login_message_id"] = msg.message_id
        await query.message.delete()

    elif method == "login_method_plex":
        # 1. Request PIN from Plex
        pin_id, code, url = await get_plex_auth_pin()
        if not pin_id:
            await query.edit_message_text(i18n.t('auth.plex_error'))
            return

        # 2. Store PIN ID to verify later
        context.user_data["plex_pin_id"] = pin_id
        
        # 3. Show instructions
        text = i18n.t('auth.plex_instructions')
        
        kb = [
            [InlineKeyboardButton(i18n.t('auth.plex_auth_btn'), url=url)],
            [InlineKeyboardButton(i18n.t('auth.plex_logged_in_btn'), callback_data="check_plex_login")],
            [InlineKeyboardButton(i18n.t('messages.cancel_btn'), callback_data="cancel_settings")]
        ]
        
        await query.edit_message_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(kb))

async def check_plex_login_callback(query: CallbackQuery, context: ContextTypes.DEFAULT_TYPE):
    """Verifies if the user has completed the Plex login flow."""
    pin_id = context.user_data.get("plex_pin_id")
    
    if not pin_id:
        await query.answer(i18n.t('auth.session_expired'))
        await start_login(query, context)
        return

    # 1. Check status with Plex
    plex_token = await check_plex_pin(pin_id)
    
    if not plex_token:
        # Not authorized yet
        await query.answer("⏳ Not authorized yet. Please login in the browser first.", show_alert=True)
        return

    # 2. Exchange Plex Token for Overseerr Session
    await query.edit_message_text("🔄 Verifying with Overseerr...")
    session_cookie = await overseerr_login_via_plex(plex_token)

    if session_cookie:
        # --- SUCCESS ---
        try:
            # Fetch User Info from Overseerr to get ID and Name
            async with httpx.AsyncClient() as client:
                me_resp = await client.get(
                    f"{bot_settings.OVERSEERR_API_URL}/auth/me",
                    headers={"Cookie": f"connect.sid={session_cookie}"},
                    timeout=10
                )
                user_info = me_resp.json()
                overseerr_id = user_info.get("id")

            # Prepare Session Data
            session_data = {
                "cookie": session_cookie,
                "credentials": "PLEX_AUTH", # Placeholder, as we don't have a password
                "overseerr_telegram_user_id": overseerr_id,
                "overseerr_user_name": user_info.get("displayName", "Plex User")
            }
            
            # Save Session (Normal or Shared Mode)
            telegram_user_id = query.from_user.id
            is_admin = load_config()["users"].get(str(telegram_user_id), {}).get("is_admin", False)

            if bot_settings.CURRENT_MODE == BotMode.NORMAL:
                save_user_session(telegram_user_id, session_data)
            elif bot_settings.CURRENT_MODE == BotMode.SHARED and is_admin:
                save_shared_session(session_data)
                context.application.bot_data["shared_session"] = session_data
            
            # Update Context
            context.user_data["session_data"] = session_data
            context.user_data["overseerr_telegram_user_id"] = overseerr_id
            context.user_data["overseerr_user_name"] = session_data["overseerr_user_name"]

            await query.edit_message_text(f"✅ Successfully logged in as *{session_data['overseerr_user_name']}*!", parse_mode="Markdown")
            
            # Cleanup
            context.user_data.pop("plex_pin_id", None)
            
            # Return to Settings
            await show_settings_menu(query, context, is_admin)

        except Exception as e:
            logger.error(f"Plex Login Success but Info Fetch failed: {e}")
            await query.edit_message_text("❌ Login worked, but failed to fetch user data from Overseerr.")
    else:
        await query.edit_message_text(i18n.t('auth.plex_rejected'))


# ==============================================================================
# BUTTON HANDLER (CALLBACKS)
# ==============================================================================
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data
    telegram_user_id = query.from_user.id
    
    conf = load_config()
    is_admin = conf["users"].get(str(telegram_user_id), {}).get("is_admin", False)

    if PASSWORD and not user_is_authorized(telegram_user_id):
        await query.edit_message_text("Authorization required.")
        return

    # 1. Navigation
    if data == "settings":
        await show_settings_menu(query, context, is_admin)
        return
    elif data == "cancel_settings":
        await query.edit_message_text("⚙️ Settings closed.")
        return
    elif data == "back_to_settings":
        await show_settings_menu(query, context, is_admin)
        return
    
    # 2. User Management
    elif data == "manage_users":
        await show_user_management_menu(query, context)
        return
    elif data.startswith("users_page_"):
        await show_user_management_menu(query, context, offset=int(data.split("_")[2]))
        return
    elif data.startswith("manage_user_"):
        await manage_specific_user(query, context, data.split("_")[2])
        return
    
    # 3. User Actions
    elif data.startswith(("block_user_", "unblock_user_", "promote_user_", "demote_user_")):
        action, _, target_id = data.partition("_user_")
        target_id = target_id
        
        if action == "block":
            if target_id == str(telegram_user_id): 
                await query.answer("Cannot block yourself!")
                return
            conf["users"][target_id]["is_blocked"] = True
            conf["users"][target_id]["is_authorized"] = False
        elif action == "unblock":
            conf["users"][target_id]["is_blocked"] = False
            conf["users"][target_id]["is_authorized"] = True
        elif action == "promote":
            conf["users"][target_id]["is_admin"] = True
            conf["users"][target_id]["is_authorized"] = True
        elif action == "demote":
             if target_id == str(telegram_user_id): return
             conf["users"][target_id]["is_admin"] = False
             
        save_config(conf)
        await manage_specific_user(query, context, target_id)
        return

    elif data == "create_user":
        await query.answer("Feature not fully implemented.")
        return

    # 4. Settings
    elif data == "toggle_group_mode":
        conf["group_mode"] = not conf["group_mode"]
        if not conf["group_mode"]: conf["primary_chat_id"] = {"chat_id": None, "message_thread_id": None}
        save_config(conf)
        await show_settings_menu(query, context, is_admin)
        return

    elif data == "mode_select":
        await mode_select(query, context)
        return

    elif data == "toggle_startup_notify":
        current_state = conf.get("send_startup_notification", False)
        conf["send_startup_notification"] = not current_state
        save_config(conf)
        await show_settings_menu(query, context, is_admin)
        return
        
    elif data.startswith("activate_"):
        mode_str = data.split("_")[1]
        conf["mode"] = mode_str
        bot_settings.CURRENT_MODE = BotMode[mode_str.upper()]
        save_config(conf)

        # 1. Clear any existing session data from the previous mode
        context.user_data.pop("session_data", None)
        context.user_data.pop("overseerr_telegram_user_id", None)
        context.user_data.pop("overseerr_user_name", None)
        
        # 2. Load data relevant to the NEW mode immediately
        if bot_settings.CURRENT_MODE == BotMode.SHARED:
            # Try to load the shared session file from disk
            shared_sess = load_shared_session()
            if shared_sess:
                # Update global bot data
                context.application.bot_data["shared_session"] = shared_sess
                # Update current user context for immediate display
                context.user_data["overseerr_telegram_user_id"] = shared_sess.get("overseerr_telegram_user_id")
                context.user_data["overseerr_user_name"] = shared_sess.get("overseerr_user_name")
        
        elif bot_settings.CURRENT_MODE == BotMode.NORMAL:
            # Try to load the individual session for this admin
            user_sess = load_user_session(telegram_user_id)
            if user_sess:
                context.user_data["session_data"] = user_sess
                context.user_data["overseerr_telegram_user_id"] = user_sess.get("overseerr_telegram_user_id")
                context.user_data["overseerr_user_name"] = user_sess.get("overseerr_user_name")

        elif bot_settings.CURRENT_MODE == BotMode.API:
            # Try to load the API user selection
            ov_id, ov_name = get_saved_user_for_telegram_id(telegram_user_id)
            if ov_id:
                context.user_data["overseerr_telegram_user_id"] = ov_id
                context.user_data["overseerr_user_name"] = ov_name

        await show_settings_menu(query, context, is_admin)
        return

  

    # 5. Auth
    elif data == "login":
        await start_login(query, context)
        return
    
    elif data.startswith("login_method_"):
        await handle_login_method(query, context)
        return

    elif data == "check_plex_login":
        await check_plex_login_callback(query, context)
        return

    elif data == "logout":
        context.user_data.pop("session_data", None)
        context.user_data.pop("overseerr_telegram_user_id", None)
        
        if bot_settings.CURRENT_MODE == BotMode.NORMAL:
            sessions = load_user_sessions()
            sessions.pop(str(telegram_user_id), None)
            save_user_sessions(sessions)
        elif bot_settings.CURRENT_MODE == BotMode.SHARED:
            clear_shared_session()
            context.application.bot_data.pop("shared_session", None)
            
        await query.edit_message_text(i18n.t('auth.logout_success'))
        return
    
    # 6. Change User
    elif data == "change_user":
        await handle_change_user(query, context)
        return
    elif data.startswith("user_page_"):
        await handle_change_user(query, context, offset=int(data.split("_")[2]))
        return
    elif data.startswith("select_user_"):
        target_uid = int(data.split("_")[2])
        users = await get_overseerr_users()
        u = next((x for x in users if x["id"] == target_uid), None)
        if u:
            name = u.get("displayName") or u.get("username")
            context.user_data["overseerr_telegram_user_id"] = target_uid
            context.user_data["overseerr_user_name"] = name
            save_user_selection(telegram_user_id, target_uid, name)
            await show_settings_menu(query, context, is_admin)
        return
    
    # 7. Notifications
    elif data == "manage_notifications":
        await show_manage_notifications_menu(query, context)
        return
    elif data == "toggle_user_notifications":
        await toggle_user_notifications(query, context)
        return
    elif data == "toggle_user_silent":
        await toggle_user_silent(query, context)
        return

    # 8. Search
    elif data.startswith("page_"):
        results = context.user_data.get("search_results", [])
        await display_results_with_buttons(query, context, results, int(data.split("_")[1]))
        return
    elif data == "cancel_search":
        await query.message.delete()
        context.user_data.pop("search_results", None)
        return
    elif data.startswith("select_"):
        idx = int(data.split("_")[1])
        results = context.user_data.get("search_results", [])
        if 0 <= idx < len(results):
            await process_user_selection(query, context, results[idx])
        return
    elif data == "back_to_results":
        results = context.user_data.get("search_results", [])
        await query.message.delete()
        sent = await display_results_with_buttons(query, context, results, 0, new_message=True)
        context.user_data["results_message_id"] = sent.message_id
        return

    # 9. Requests
    elif data.startswith("confirm_"):
        parts = data.split("_")
        req_type = parts[1] # 1080p, 4k, both
        mid = int(parts[2])
        
        results = context.user_data.get("search_results", [])
        res = next((r for r in results if r["id"] == mid), None)
        if not res: 
            await query.answer("Error: Media not found in cache.")
            return

        # Determine Auth
        cookie = None
        req_by = None
        
        if bot_settings.CURRENT_MODE == BotMode.NORMAL:
            cookie = context.user_data.get("session_data", {}).get("cookie")
        elif bot_settings.CURRENT_MODE == BotMode.SHARED:
            cookie = context.application.bot_data.get("shared_session", {}).get("cookie")
        elif bot_settings.CURRENT_MODE == BotMode.API:
            req_by = context.user_data.get("overseerr_telegram_user_id")

        # Execute Requests
        succ_hd, msg_hd, succ_4k, msg_4k = None, None, None, None
        
        if req_type in ["1080p", "both"]:
            succ_hd, msg_hd = await request_media(mid, res["mediaType"], req_by, False, cookie)
        
        if req_type in ["4k", "both"]:
            succ_4k, msg_4k = await request_media(mid, res["mediaType"], req_by, True, cookie)
        
        # Determine Label (Same logic as in process_user_selection)
        # We check the cached result 'res' for status_4k
        label_hd = i18n.t('check.library_1080p_label')
        if res.get("status_4k", 1) == MediaStatus.UNKNOWN:
            label_hd = i18n.t('check.library_only_1080p_label')
        
        statuses = ""
        if succ_hd is not None:
            status = i18n.t('check.request_status_success') if succ_hd else i18n.t('check.request_status_error', error_msg=msg_hd)
            statuses += f"• *{label_hd}:* {status}\n"
            
        if succ_4k is not None:
            status = i18n.t('check.request_status_success') if succ_4k else i18n.t('check.request_status_error', error_msg=msg_4k)
            statuses += f"• *{i18n.t('check.library_4k_label')}:* {status}\n"
        
        txt = i18n.t('check.request_sent_body', title=res['title'], year=res['year'], request_statuses=status)
        # -------------------------------
        
        await query.edit_message_caption(txt, parse_mode="Markdown")
        return

    # 10. Issues
    elif data.startswith("report_"):
        ov_id = int(data.split("_")[1])
        res = context.user_data.get("selected_result")
        if not res: res = next((r for r in context.user_data.get("search_results", []) if r.get("overseerr_id") == ov_id), None)
        
        if res:
            context.user_data['selected_result'] = res
            kb = []
            for k,v in ISSUE_TYPES.items():
                kb.append([InlineKeyboardButton(v, callback_data=f"issue_type_{k}")])
            kb.append([InlineKeyboardButton(i18n.t('messages.cancel_btn'), callback_data="cancel_issue")])
            await query.edit_message_caption(i18n.t('reports.issue_type_prompt', media_title=res['title']), parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(kb))
        return
        
    elif data.startswith("issue_type_"):
        tid = int(data.split("_")[2])
        tname = ISSUE_TYPES.get(tid, "Other")
        context.user_data['reporting_issue'] = {'issue_type': tid, 'issue_type_name': tname}
        
        await query.edit_message_caption(
            i18n.t('reports.issue_desc_prompt', issue_type=tname),
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton(i18n.t('messages.cancel_btn'), callback_data="cancel_issue")]])
        )
        return

    elif data == "cancel_issue":
        context.user_data.pop('reporting_issue', None)
        res = context.user_data.get('selected_result')
        if res: await process_user_selection(query, context, res, edit_message=True)
        return

    await query.answer("Unknown Action")


async def handle_change_user(update_or_query, context, is_initial=False, offset=0):
    if isinstance(update_or_query, Update):
        chat_id = update_or_query.effective_chat.id
    else:
        chat_id = update_or_query.message.chat_id

    if "all_users" not in context.user_data:
        context.user_data["all_users"] = await get_overseerr_users()

    users = context.user_data["all_users"]
    page_size = 8
    start = offset
    end = offset + page_size
    subset = users[start:end]

    kb = []
    for u in subset:
        name = u.get("displayName") or u.get("username")
        kb.append([InlineKeyboardButton(f"{name}", callback_data=f"select_user_{u['id']}")])
    
    nav = []
    if start > 0: nav.append(InlineKeyboardButton("⬅️", callback_data=f"user_page_{start - page_size}"))
    nav.append(InlineKeyboardButton("❌", callback_data="cancel_settings"))
    if end < len(users): nav.append(InlineKeyboardButton("➡️", callback_data=f"user_page_{end}"))
    kb.append(nav)

    txt = "Select Overseerr User:"
    markup = InlineKeyboardMarkup(kb)

    if isinstance(update_or_query, Update):
        await context.bot.send_message(chat_id, txt, reply_markup=markup)
    else:
        await update_or_query.edit_message_text(txt, reply_markup=markup)


# ==============================================================================
# LIFECYCLE HOOKS
# ==============================================================================
def get_primary_admin_id() -> Optional[int]:
    """
    Helper to find the first admin ID from the config.
    Used to send system notifications.
    """
    conf = load_config()
    for user_id, data in conf["users"].items():
        if data.get("is_admin"):
            return int(user_id)
    return None

async def post_init(application: Application):
    """
    Runs after the bot has successfully started up.
    Sends a notification to the admin if enabled in settings.
    """
    conf = load_config()
    
    # Check if the feature is enabled
    if not conf.get("send_startup_notification", False):
        return

    admin_id = get_primary_admin_id()
    if admin_id:
        try:
            await application.bot.send_message(
                chat_id=admin_id,
                text=i18n.t('messages.system_online', version=VERSION),
                parse_mode="Markdown"
            )
            logger.info("Startup notification sent to admin.")
        except Exception as e:
            logger.warning(f"Failed to send startup message: {e}")


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================
def main():
    ensure_data_directory()
    
    # Load Initial Config and Set Mode
    conf = load_config()
    mode_str = conf.get("mode", "normal")
    try:
        bot_settings.CURRENT_MODE = BotMode[mode_str.upper()]
    except KeyError:
        bot_settings.CURRENT_MODE = BotMode.NORMAL
    
    logger.info(f"Bot started. Version: {VERSION}. Mode: {bot_settings.CURRENT_MODE.value}")

    # Build App
    app = (
        ApplicationBuilder()
        .token(TELEGRAM_TOKEN)
        .post_init(post_init)
        .build()
    )

    # Shared Session Init
    if bot_settings.CURRENT_MODE == BotMode.SHARED:
        sess = load_shared_session()
        if sess: 
            app.bot_data["shared_session"] = sess
            logger.info("Loaded shared session.")

    # Handlers
    app.add_handler(MessageHandler(filters.ALL, user_data_loader), group=-1) # Run before everything
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("settings", show_settings_menu))
    app.add_handler(CommandHandler("check", check_media))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_input))

    app.run_polling()

if __name__ == "__main__":
    main()