# SneakyBot
SneakyBot is a lightweight, asynchronous Python bot designed for monitoring Urban Terror 4.3+ game servers. It tracks `games.log` in real-time to provide in-game automation, chat commands, and Discord integration.

## Features
- **Real-time Log Monitoring**: Tracks connects, disconnects, and chat events.
- **Dynamic Discord Notifications**: Sends updates to a Discord webhook based on player count and server state (empty, single player, full, etc.).
- **In-Game Chat Commands**:
    - `!rules`: Displays server rules from configuration.
    - `!nextmap`: Informs players of the next map and gametype in rotation.
    - `!ping`: A simple connectivity check.
    - `!sneakybot`: Shows version and GitHub link.
    - `!help`: Lists available commands.
- **Automated Broadcasts**: Periodic messages and next-map announcements to keep players informed.
- **Config Auto-Validation**: Checks `server.cfg` for required logging variables (`g_logsync`, `g_loghits`) and automatically configures them.
- **RCON Integration**: Securely fetches the RCON password directly from your `server.cfg`.

## Installation
1. Clone the repository:
    ```
    git clone https://github.com/netsecninja/sneakybot.git
    cd sneakybot
    ```
2. Install dependencies:
    ```
    pip install -r requirements.txt
    ```
3. Run the bot once to generate the default `sneakybot.cfg`:
    ```
    python main.py
    ```
4. Edit `sneakybot.cfg` with your server paths and Discord webhook.

## Configuration Highlights
### PATHS
Ensure `q3ut4_path` point to the correct directory on your server.

### RULES
Define your game server rules you want to share with players.

### BROADCAST
You can configure periodic in-game broadcasts. Additionally, you can announce the next map in the cycle.

### DISCORD
If you create a webhook for your Discord server, you can enable player count and map messages. You can customize the messages sent to Discord. Use `{count}` for the current player number and `{max}` for the server capacity.

## Requirements
- Python 3.9+
- Read/Write access to the Urban Terror server files
    
## License
Created by Jeremiah Bess - [SBs]PenguinGeek with significant help from Google Gemini. Released under the GPL-3.0 license.