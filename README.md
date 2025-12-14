# Overseerr Telegram Bot

The **Overseerr Telegram Bot** enables seamless interaction with your Overseerr instance through Telegram. Search for movies and TV shows, check availability, request new titles, report issues, and manage notifications—all from your Telegram chat. 

With **Version 4.0.0**, the bot has been rebuilt for high performance (Async) and includes powerful features like **Plex Authentication** and **Smart Group Chat Integration**.

📚 **Detailed Documentation**: Explore the [Wiki](https://github.com/LetsGoDude/Overseerr-Telegram-Bot/wiki) for comprehensive guides on setup, configuration, and advanced usage.

🐳 **Docker Image**: Pull the latest bot image from [Docker Hub](https://hub.docker.com/r/chimpanzeesweetrolls/overseerrrequestviatelegrambot).

---

## ✨ Features

- **Media Search**: Use `/check <title>` to find movies or TV shows (e.g., `/check The Matrix`) and view detailed results, including posters and availability.
- **Smart Availability**: Instantly see if a title is available. Handles single-server setups gracefully by adjusting status labels automatically.
- **Title Requests**: Request missing titles in HD (1080p) or 4K, respecting Overseerr user permissions for quality settings.
- **Authentication**: Log in securely via **Email/Password** or your **Plex Account** (PIN Flow).
- **Issue Reporting**: Report issues like video glitches, audio sync problems, or missing subtitles directly to Overseerr.
- **Notification Management**: Customize Telegram notifications for Overseerr events (e.g., request approvals, media availability).
- **Admin Dashboard**: A completely redesigned `/settings` menu allows admins to switch operation modes, manage users, and toggle system notifications.
- **Smart Group Mode**: Use the bot safely in group chats.

> [!Note]
> The language of media titles and descriptions matches the language setting configured in Overseerr (e.g., German titles if Overseerr is set to German), while the bot's interface remains in English.

![1 Start](https://github.com/user-attachments/assets/55cc4796-7a4f-4909-a260-0395e7fb202a)

---

## 🚀 Installation

For detailed installation instructions, refer to the [Wiki](https://github.com/LetsGoDude/Overseerr-Telegram-Bot/wiki#installation).

### Quick Start (Docker Compose)

```yaml
version: "3.9"
services:
  telegram-bot:
    image: chimpanzeesweetrolls/overseerrrequestviatelegrambot:latest
    container_name: overseerr-bot
    environment:
      OVERSEERR_API_URL: "http://your-overseerr-ip:5055/api/v1"
      OVERSEERR_API_KEY: "your_overseerr_api_key"
      TELEGRAM_TOKEN: "your_telegram_token"
      PASSWORD: "your_password"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

---

## Operation Modes

The bot supports three operation modes, configurable by the admin via `/settings`:

- **🌟 Normal Mode** (Default):
  - Users log in individually using their **Overseerr Email** or **Plex Account**.
  - Requests are tracked to the specific user's account.
  - Best for: Public bots or multi-user households.

- **🔑 API Mode**:
  - No login required. Users select an existing Overseerr user from a list.
  - Uses the Admin API key for all requests.
  - Best for: Personal bots or trusted groups where individual logins are too cumbersome.

- **👥 Shared Mode**:
  - The Admin logs in once (via Email or Plex).
  - All Telegram users share this single session.
  - Users cannot change settings.
  - Best for: Families sharing a single media server account.

Learn more about configuring modes in the [Wiki](https://github.com/LetsGoDude/Overseerr-Telegram-Bot/wiki#operation-modes).

---

## Commands

### User Commands

- **/start**:
  - Initializes the bot and prompts for a password (if enabled).
  - **Smart Auth**: If run in a group, it provides a "🔐 Enter Password Privately" button to keep your password safe.
  - **First Run**: The first user to run `/start` automatically becomes the Admin.

- **/check <title>**:
  - Searches Overseerr for movies or TV shows.
  - Returns a paginated list with buttons to request media or report issues.
  - Example: `/check Breaking Bad`

- **/settings**:
  - Opens the interactive **Dashboard**.
  - Users can: Log in/out (Email or Plex), manage their notification preferences.
  - Admins can: Change bot modes, manage users, toggle group mode.

### Admin Features

All admin actions are performed via the Dashboard:
- **Change Operation Mode**: Switch between Normal, API, and Shared modes.
- **User Management**: Block/Unblock users, promote to Admin, or create new Overseerr users.
- **System Notifications**: Enable/Disable startup notifications ("System Online").

![2 settings](https://github.com/user-attachments/assets/7ecd389c-e931-42a4-bcec-c5c45fe4029b)
![3 settings - User Management](https://github.com/user-attachments/assets/95c6d9fd-eb3d-44ed-8b5a-eb7e43c1eb22)

---

## Smart Group Mode

Group Mode allows you to restrict the bot to a specific Telegram group or thread, making it perfect for shared servers.

**How it works in v4.0.0:**
1.  Admin enables Group Mode in `/settings`.
2.  Admin types `/start` in the group to link it.
3.  **New Users:** When a user types `/start` in the group, the bot sends a button **[🔐 Enter Password Privately]**.
4.  The user authenticates in a private chat.
5.  Once successful, the bot automatically notifies the group: *"✅ User is now authorized!"*.

*No need to disable Telegram's "Group Privacy Mode" via BotFather anymore!*

![4 Check - Status](https://github.com/user-attachments/assets/4dd828ed-df99-4861-bff9-b40c758c0b24)

---

## FAQ

- **How do I log in with Plex?**  
  Go to `/settings` -> Login. Select **"▶️ Plex Account"**. The bot will provide a link to authorize the device.

- **Why does the bot say "Status" instead of "1080p"?**  
  The bot detects your Overseerr configuration. If you don't have a separate 4K server configured, it neutrally labels the availability as "Status" to avoid confusion (since the file could be 4K even on a standard server).

- **What if I forget the bot password?**  
  The password is set via the `PASSWORD` environment variable. Check your Docker or Config file.

- **Why don't I see "Manage Notifications"?**  
  You must be logged in (Normal/Shared Mode) or have a user selected (API Mode) to configure notifications.

---

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](https://github.com/LetsGoDude/Overseerr-Telegram-Bot/blob/main/LICENSE) file for details.

---

## Contact

For issues or feature requests, open an issue on [GitHub](https://github.com/LetsGoDude/Overseerr-Telegram-Bot/issues).

---

Built with ❤️ for media enthusiasts!
```
