# SneakyBot v3.1.0

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
    git clone [https://github.com/netsecninja/sneakybot.git](https://github.com/netsecninja/sneakybot.git)
    cd sneakybot
    ```
    
2. Install dependencies:
    
    ```
    pip install -r requirements.txt
    ```
    
3. Run the bot once to generate the default `config.ini`:
    
    ```
    python main.py
    ```
    
4. Edit `config.ini` with your server paths and Discord webhook.
    

## Configuration Highlights

### Paths

Ensure `log_path`, `server_cfg`, and `mapcycle_path` point to the correct files on your server.

### Discord Notifications

You can customize the messages sent to Discord. Use `{count}` for the current player number and `{max}` for the server capacity.

```
[DISCORD_NOTIFICATIONS]
empty_server = No more players online.
single_player = Someone is lonely on the server!
```

### Map Cycle

The `!nextmap` feature relies on parsing your `mapcycle.txt`. It supports identifying gametypes (TS, CTF, etc.) and specific modes like Instagib or Low Gravity.

## Requirements

- Python 3.7+
    
- `aiohttp` library
    
- Read/Write access to the Urban Terror server files
    

## License

Created by Jeremiah Bess - [SBs]PenguinGeek. Released under the MIT License.