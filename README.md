# SneakyBot
SneakyBot is a lightweight, asynchronous administration and monitoring tool designed specifically for **Urban Terror 4.3+**. It monitors your server logs in real-time to provide automated welcomes, in-game broadcasts, and Discord integration.

## 🚀 Features
- **Log Tailing**: High-performance, non-blocking monitoring of `games.log`.
- **Auto-Welcome**: Greets players by name when they join the server.
- **Periodic Broadcasts**: Automatically rotates custom server messages/rules at defined intervals.
- **Chat Commands**: Support for basic commands like `!rules`. More to come later!
- **Discord Integration**: Real-time server status updates via Webhooks (Player count, Map name, and Player list).
- **Config Auto-Validation**: Automatically checks and updates `server.cfg` to ensure `g_logsync` and `g_loghits` are enabled for proper monitoring.
- **Dual Logging**: Logs bot activity to both the console and a local `sneakybot.log` file.
- **Security**: Supports environment variables for sensitive RCON and Discord credentials.

## 🛠 Installation
Installation occurs on the Urban Terror server.

### Prerequisites
- Python 3.8 or higher.
- A running Urban Terror 4.3+ Server.
- Access to the command line of the UT server.
- Read access to the server's `games.log` file.

### Setup using Virtual Environment (venv)
1. **Clone the repository**:
    ```
    git clone [https://github.com/your-username/sneakybot.git](https://github.com/your-username/sneakybot.git)
    cd sneakybot
    ```
2. **Create and activate a virtual environment**:
    ```
    # Linux/macOS
    python3 -m venv venv
    source venv/bin/activate
    
    # Windows
    python -m venv venv
    venv\Scripts\activate
    ```
3. **Install dependencies**:
    ```
    pip install -r requirements.txt
    ```

## ⚙️ Configuration
1. **Generate Default Config**: Run the bot once to generate the template `config.ini`:
    ```
    python main.py
    ```
2. **Edit `config.ini`**:
    - Set `log_path` to the location of your `games.log`.
    - Enter your server's RCON password.
    - (Optional) Provide a Discord Webhook URL.

### Security (Environment Variables)
For extra security (especially in Docker or shared environments), you can set sensitive values via environment variables instead of plain text in the config file:
- `URT_RCON_PASSWORD`: Overrides the RCON password.
- `URT_DISCORD_WEBHOOK`: Overrides/Sets the Discord Webhook URL.

## 🏃 Running the Bot
Always ensure your virtual environment is active before running:
```
python main.py
```

## 📝 License
This project is licensed under the GNU GPLv3 License - see the [LICENSE](https://www.gnu.org/licenses/gpl-3.0.html "null") file for details.

## 🙌 Credits
Created by **Jeremiah Bess ([SBs]PenguinGeek)** with significant help from Google's Gemini Canvas.