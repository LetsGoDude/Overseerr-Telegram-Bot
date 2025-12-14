# Overseerr Telegram Bot

The **Overseerr Telegram Bot** enables seamless interaction with your Overseerr instance through Telegram. Search for movies and TV shows, check availability, request new titles, report issues, and manage notifications—all from your Telegram chat. With flexible operation modes, admin controls, and optional password protection, the bot is designed for both individual and group use, making media management effortless.

📚 **Detailed Documentation**: Explore the [Wiki](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki) for comprehensive guides on setup, configuration, and advanced usage.

🐳 **Docker Image**: Pull the latest bot image from [Docker Hub](https://hub.docker.com/r/chimpanzeesweetrolls/overseerrrequestviatelegrambot).

---

## Features

- **Media Search**: Use `/check <title>` to find movies or TV shows (e.g., `/check The Matrix`) and view detailed results, including posters and availability.
- **Availability Check**: Instantly see if a title is available in HD (1080p) or 4K, based on your Overseerr library.
- **Title Requests**: Request missing titles in HD, 4K, or both, respecting Overseerr user permissions for quality settings.
- **Issue Reporting**: Report issues like video glitches, audio sync problems, missing subtitles, or other playback errors for existing titles.
- **Notification Management**: Customize Telegram notifications for Overseerr events (e.g., request approvals, media availability) with options to enable/disable or use silent mode.
- **Admin Controls**: Admins can switch operation modes, toggle Group Mode, create new Overseerr users, and manage bot settings via an intuitive menu.
- **Password Protection**: Secure bot access with an optional password, ensuring only authorized users can interact.
- **Group Mode**: Restrict bot usage to a specific Telegram group or thread, ideal for collaborative media management in shared environments like family or friend groups.

> [!Note]
> The language of media titles and descriptions matches the language setting configured in Overseerr (e.g., German titles and descriptions if Overseerr is set to German), while the bot's interface remains in English.

![1 Start](https://github.com/user-attachments/assets/55cc4796-7a4f-4909-a260-0395e7fb202a)


---

## Installation

For detailed installation instructions, refer to the [Wiki](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki#installation):

- **Ubuntu (Source Installation)**: Follow the guide at [Installation on Ubuntu](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki#source-installation-ubuntulinux).
- **Docker**: Deploy with [Docker](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki#docker-installation-without-compose), [Docker Compose](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki#docker-installation-with-compose) or [NAS Container](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki#nas-container-setup) using the instructions at the wiki.

---

## Operation Modes

The bot supports three operation modes, configurable by the admin via `/settings`, catering to different use cases:

- **Normal Mode**:

  - Users log in with their individual Overseerr credentials (email and password).
  - Requests and issue reports are tied to each user’s Overseerr account, ensuring personalized tracking.
  - Ideal for users with their own Overseerr accounts who want full control over their requests and notifications.

- **API Mode**:

  - Users select an existing Overseerr user from a list without needing credentials, using the Overseerr API key for requests.
  - Simplifies access for users without Overseerr accounts, with requests automatically approved by Overseerr.
  - Issue reports are attributed to the admin’s account due to API key usage.
  - Best for environments where quick access is prioritized over individual account management.

- **Shared Mode**:

  - All users share a single Overseerr account configured by the admin, streamlining group usage.
  - The admin logs in once, and all requests and issue reports use this shared account.
  - Perfect for small groups (e.g., families or friends) sharing a media server, with notifications sent to a common Telegram chat.

Learn more about configuring modes in the [Wiki](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki#operation-modes).

---

### User Commands


- **/start**:

  - Initializes the bot, displaying a welcome message with the bot’s version and prompting for a password (if enabled).
  - The first user to run `/start` becomes an admin if no admins exist.
  - In Group Mode, sets the current chat/thread as the primary chat for bot interactions.
  - Guides users to log in (Normal Mode), select a user (API Mode), or rely on the shared account (Shared Mode).
  - Example: `/start`


- **/check <title>**:

  - Searches Overseerr for movies or TV shows and returns a paginated list with detailed results (e.g., title, availability, request status).
  - Displays availability status (e.g., 1080p available, 4K requestable) and options to request missing formats or report issues for existing media.
  - Supports Overseerr’s language settings for titles and descriptions.
  - Example: `/check Breaking Bad`


- **/settings**:

  - Opens an interactive menu to manage Overseerr accounts and bot settings.
  - **For Users**:
    - Normal Mode: Log in with Overseerr credentials (email/password) or log out.
    - API Mode: Select an Overseerr user from a list.
    - Shared Mode: Limited to viewing the shared account status (set by the admin).
    - Manage notifications (enable/disable, silent mode) after selecting an Overseerr user.
  - Example: `/settings`


### Admin Commands

All admin actions are performed via the `/settings` menu:

- **Change Operation Mode**: Switch between Normal, API, and Shared modes to adjust bot behavior.
- **Toggle Group Mode**: Enable/disable Group Mode and set the primary chat/thread for bot interactions.
- **User Management**:
  - Authorize or block users to control bot access.
  - Promote users to admin or demote them.
  - Create new Overseerr users by providing an email and username.
  - View and manage all users in a paginated list.
- **Login/Logout (Shared Mode)**: Admins manage the shared Overseerr account login.

![2 settings](https://github.com/user-attachments/assets/7ecd389c-e931-42a4-bcec-c5c45fe4029b)
![3 settings - User Management](https://github.com/user-attachments/assets/95c6d9fd-eb3d-44ed-8b5a-eb7e43c1eb22)

---

## Managing Notifications

Users can configure Overseerr Telegram notifications via `/settings`:

- **Enable/Disable Notifications**: Turn on/off notifications for events like request approvals, media availability, or errors.
- **Silent Mode**: Opt for silent notifications without sound, ideal for minimizing disruptions during quiet hours.
- In Shared Mode, only admins configure notifications for the shared account, applying to all users.

Example: Enable notifications to receive a Telegram message when "The Witcher" becomes available, or set silent mode for nighttime updates.

---

## Reporting Issues

From media details returned by `/check`, users can report issues for pending or available titles, such as:

- Video issues (e.g., pixelation, buffering)
- Audio issues (e.g., out-of-sync, missing tracks)
- Subtitle issues (e.g., incorrect timing, missing files)
- Other playback problems

Reports are submitted to Overseerr, with attribution based on the operation mode (individual user in Normal Mode, admin in API Mode, shared account in Shared Mode).

![4 Check - Status der anforderung und problem melden](https://github.com/user-attachments/assets/4dd828ed-df99-4861-bff9-b40c758c0b24)
![7 Problem](https://github.com/user-attachments/assets/8cb1322e-4b32-4b44-8873-65f6a9e6b471)

---

## Group Mode

Group Mode enhances collaborative usage by restricting bot interactions to a designated Telegram group or thread:

- **Enable Group Mode**: Only the admin can activate this via `/settings`, storing the setting in `data/bot_config.json`.
- **Set Primary Chat**: Running `/start` in a group or thread sets it as the primary chat, identified by `primary_chat_id`.
- **Usage**: When active, all commands (`/start`, `/check`) and notifications are confined to the primary chat/thread, ignoring other chats. This ensures a unified experience for group members.
- **Example**: In a family Telegram group, users request "Toy Story" via `/check`, and the bot responds only in that group, with notifications (e.g., “Toy Story is available”) sent to all members.
- **Use Case**: Ideal for shared media servers (e.g., Plex) where a group collaborates on requests, keeping communication centralized.

For setup details, visit the [Wiki](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki#group-mode).

---

## FAQ and Troubleshooting

- **How do I set up the bot for the first time?**\
  Follow the installation guides in the [Wiki](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki) for Ubuntu or Docker.

- **What if I forget the bot password?**\
  The password is set via the `PASSWORD` environment variable or `config.py`. Admins can reset it by updating the configuration. See the [Wiki](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki) for details.

- **Why can’t I request 4K titles?**  
  4K requests depend on Overseerr permissions:
  - Normal Mode: Tied to the user’s account permissions.
  - API Mode: Tied to the selected user’s permissions.
  - Shared Mode: Tied to the shared account’s permissions.  
  Check Overseerr settings or contact your admin.

- **Why don’t I see the “Manage Notifications” option in /settings?**  
  The “Manage Notifications” button appears only after selecting an Overseerr user (via login in Normal Mode, user selection in API Mode, or admin login in Shared Mode). Use `/settings` to log in or select a user first.

- **How do I troubleshoot bot errors?**  
  Check the bot logs in the console or `data/` directory. Common issues include incorrect `TELEGRAM_TOKEN`, `OVERSEERR_API_URL`, or `OVERSEERR_API_KEY`. Refer to the [Wiki](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/wiki) for troubleshooting tips.

---

## Contributing

Contributions are welcome!

---

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/blob/main/LICENSE) file for details.

---

## Contact

For issues or feature requests, open an issue on [GitHub](https://github.com/LetsGoDude/OverseerrRequestViaTelegramBot/issues).

---

Built with :heart: for media enthusiasts!
