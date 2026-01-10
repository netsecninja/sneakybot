"""
SneakyBot - Urban Terror 4.3+ Admin and Monitoring Bot
A lightweight, asynchronous bot for monitoring games.log, 
broadcasting messages, and Discord integration via Webhooks.

GitHub: https://github.com/netsecninja/sneakybot
"""

import asyncio
import os
import re
import sys
import logging
import configparser
import aiohttp
import random
import signal
from typing import Dict, List, Tuple, Set

# --- METADATA ---
__version__ = "3.0.0"
__author__ = "Jeremiah Bess - [SBs]PenguinGeek"

# --- CONFIGURATION MANAGEMENT ---
CONFIG_FILE = "config.ini"
LOG_FILE = "sneakybot.log"

# --- LOGGING SETUP ---
logger = logging.getLogger("SneakyBot")
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def load_config():
    """
    Generates a default config.ini and loads settings.
    Uses environment variables as overrides for security.
    """
    config = configparser.ConfigParser(allow_no_value=True)

    if not os.path.exists(CONFIG_FILE):
        config['PATHS'] = {
            '; Path to the Urban Terror games.log file': None,
            'log_path': '/opt/urbanterror43/q3ut4/games.log',
            '; Path to the server.cfg for auto-validation': None,
            'server_cfg': '/opt/urbanterror43/q3ut4/server.cfg'
        }
        config['SERVER'] = {
            '; Quake3 server connection details': None,
            'host': '127.0.0.1',
            'port': '27960',
            'rcon_password': 'your_password_here'
        }
        config['RULES'] = {
            '; Rules shown when a player types !rules. Separate with | for multi-line display.': None,
            'rule_list': '1. Listen to Admins and clan members | 2. No swearing, bullying, or offensive comments | 3. Camping is allowed | 4. Spawn killing is allowed | 5. Rules are flexible'
        }
        config['DISCORD'] = {
            '; Toggle Discord integration and set webhook URL': None,
            'enabled': 'false',
            'webhook_url': '',
            'update_interval': '60'
        }
        config['BROADCAST'] = {
            '; In-game periodic messages. Use | to separate multiple messages.': None,
            'enabled': 'true',
            'interval': '300',
            'messages': (
                "This is a family-oriented server, watch your language and behavior|"
                "Server rules listed at sneakybs.com|"
                "Join our Discord voice - link at sneakybs.com"
            )
        }
        config['DISCORD_NOTIFICATIONS'] = {
            '; Templates for Discord posts. {count} and {max} are variables.': None,
            'empty_server': "No more players online, hope you didn't miss the fun.",
            'single_player': "A player is online looking for some competition.",
            'full_server': "{count} players are online. The server is full!",
            'almost_full': "{count} players are online. One more slot open!",
            'imbalance_messages': (
                "{count} players are online. Log in to even up the teams!|"
                "{count} players are online. Things are heating up!"
            )
        }
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)

        logger.info("=" * 50)
        logger.info(f"CREATED DEFAULT CONFIGURATION: {CONFIG_FILE}")
        logger.info("Please edit config.ini or set environment variables before running.")
        logger.info("=" * 50)
        sys.exit(0)

    config.read(CONFIG_FILE)

    # Ensure RULES section exists
    if 'RULES' not in config:
        config['RULES'] = {'rule_list': '1. No Cheating | 2. Respect Others | 3. Have Fun'}

    # Environment variable overrides
    env_rcon = os.getenv('URT_RCON_PASSWORD')
    if env_rcon:
        config['SERVER']['rcon_password'] = env_rcon

    env_webhook = os.getenv('URT_DISCORD_WEBHOOK')
    if env_webhook:
        config['DISCORD']['webhook_url'] = env_webhook
        config['DISCORD']['enabled'] = 'true'

    return config

# --- REGEX PATTERNS ---
RE_USERINFO = re.compile(r'ClientUserinfoChanged:\s(\d+)\s.*n\\([^\\]+)')
RE_BEGIN = re.compile(r'ClientBegin:\s(\d+)')
RE_DISCONNECT = re.compile(r'ClientDisconnect:\s(\d+)')
RE_CHAT = re.compile(r'say:\s*\d+\s+(?:\d+\s+)?(.*?):\s*(.*)', re.IGNORECASE)

class RCONProtocol(asyncio.DatagramProtocol):
    def __init__(self, message, done, response_future=None):
        self.message = message
        self.done = done
        self.response_future = response_future
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        self.transport.sendto(self.message)
        if not self.response_future:
            self.transport.close()

    def datagram_received(self, data, addr):
        if self.response_future and not self.response_future.done():
            self.response_future.set_result(data)
        if self.transport:
            self.transport.close()

    def error_received(self, exc):
        if self.response_future and not self.response_future.done():
            self.response_future.set_exception(exc)

    def connection_lost(self, exc):
        if not self.done.done():
            self.done.set_result(True)

class RCONClient:
    def __init__(self, host: str, port: int, password: str):
        self.host = host
        self.port = port
        self.password = password
        self.prefix = b'\xff\xff\xff\xff'

    async def send_command(self, cmd: str) -> str:
        logger.info(f"[RCON] Sending command: {cmd}")
        loop = asyncio.get_running_loop()
        full_cmd = f'rcon "{self.password}" {cmd}\n'
        message = self.prefix + full_cmd.encode('utf-8')
        done = loop.create_future()
        try:
            await loop.create_datagram_endpoint(
                lambda: RCONProtocol(message, done),
                remote_addr=(self.host, self.port)
            )
            await asyncio.wait_for(done, timeout=1.0)
        except asyncio.TimeoutError:
            pass
        return "Command Sent"

    async def get_status(self) -> Tuple[Dict[str, str], List[str]]:
        loop = asyncio.get_running_loop()
        message = self.prefix + b'getstatus\n'
        done = loop.create_future()
        response_future = loop.create_future()
        try:
            await loop.create_datagram_endpoint(
                lambda: RCONProtocol(message, done, response_future),
                remote_addr=(self.host, self.port)
            )
            raw_data = await asyncio.wait_for(response_future, timeout=2.0)
            await done
            content = raw_data[4:].decode('utf-8', errors='replace').split('\n')
            if len(content) < 2: return {}, []
            cvars_raw = content[1].split('\\')
            cvars = {cvars_raw[i]: cvars_raw[i+1] for i in range(1, len(cvars_raw), 2)}
            players = []
            for line in content[2:]:
                if line.strip():
                    p_match = re.search(r'\d+\s+\d+\s+"(.*)"', line)
                    if p_match: players.append(p_match.group(1))
            return cvars, players
        except Exception as e:
            logger.error(f"Failed to get server status: {e}")
            return {}, []

class SneakyBot:
    def __init__(self, config):
        self.config = config
        self.version = __version__
        self.rcon = RCONClient(
            host=config.get('SERVER', 'host', fallback='127.0.0.1'),
            port=config.getint('SERVER', 'port', fallback=27960),
            password=config.get('SERVER', 'rcon_password', fallback='')
        )
        self.log_path = config.get('PATHS', 'log_path', fallback='')
        self.running = True
        self.players: Dict[str, str] = {}
        self.welcomed_players: Set[str] = set()
        self.last_player_count = 0

    async def check_server_config(self):
        required_vars = {"g_logsync": "1", "g_loghits": "1"}
        cfg_path = self.config.get('PATHS', 'server_cfg', fallback='')
        if not cfg_path or not os.path.exists(cfg_path): return
        try:
            with open(cfg_path, 'r') as f: lines = f.readlines()
            modified = False
            for var, val in required_vars.items():
                found = False
                pattern = rf'^(set[a]?\s+{var}\s+["\']?)(\d+)(["\']?.*)'
                for i, line in enumerate(lines):
                    match = re.match(pattern, line, re.IGNORECASE)
                    if match:
                        found = True
                        if match.group(2) != val:
                            lines[i] = f"{match.group(1)}{val}{match.group(3)}\n"
                            modified = True
                        break
                if not found:
                    lines.append(f"set {var} \"{val}\" // Added by SneakyBot\n")
                    modified = True
            if modified:
                with open(cfg_path, 'w') as f: f.writelines(lines)
                logger.critical("!!! server.cfg updated. PLEASE RESTART THE SERVER !!!")
                sys.exit(1)
        except SystemExit: raise
        except Exception as e: logger.error(f"Config check failed: {e}")

    async def tail_log(self):
        logger.info(f"Starting log tail on {self.log_path}")
        if not os.path.exists(self.log_path):
            logger.error(f"Log file not found at {self.log_path}")
            return

        with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(0, os.SEEK_END)
            last_pos = f.tell()

            while self.running:
                line = f.readline()
                if not line:
                    if os.path.getsize(self.log_path) < last_pos:
                        logger.info("Log file truncated/rotated. Resetting pointer.")
                        f.seek(0)
                    else:
                        await asyncio.sleep(0.5)
                    last_pos = f.tell()
                    continue

                last_pos = f.tell()
                await self.parse_line(line.strip())

    async def parse_line(self, line: str):
        if 'say:' in line:
            match = RE_CHAT.search(line)
            if match:
                await self.on_chat(match.group(1), match.group(2))
            else:
                logger.debug(f"Unmatched chat line: {line}")

        elif 'ClientUserinfoChanged:' in line:
            match = RE_USERINFO.search(line)
            if match:
                self.players[match.group(1)] = match.group(2)

        elif 'ClientBegin:' in line:
            match = RE_BEGIN.search(line)
            if match: await self.on_connect(match.group(1))

        elif 'ClientDisconnect:' in line:
            match = RE_DISCONNECT.search(line)
            if match:
                cid = match.group(1)
                player_name = self.players.get(cid, f"Client {cid}")
                logger.info(f"[DISCONNECT] {player_name} left the server.")
                if cid in self.players: del self.players[cid]
                if cid in self.welcomed_players: self.welcomed_players.remove(cid)

    async def on_chat(self, name: str, message: str):
        msg = message.strip().lower()
        logger.info(f"[CHAT] {name}: {msg}")

        if msg == '!rules':
            rule_config = self.config.get('RULES', 'rule_list', fallback='1. No Cheating | 2. Respect Others')
            rules = [r.strip() for r in rule_config.split('|')]
            for rule in rules:
                await self.rcon.send_command(f'say ^2RULES ^7{rule}')
                await asyncio.sleep(0.1)

        elif msg == '!ping':
            await self.rcon.send_command('say ^3Pong!')

    async def on_connect(self, client_id: str):
        player_name = self.players.get(client_id, f"Client {client_id}")
        logger.info(f"[CONNECT] {player_name} joined.")

        if client_id in self.welcomed_players: return
        await self.rcon.send_command(f'say ^7Welcome ^3{player_name}^7! - Powered by SneakyBot')
        self.welcomed_players.add(client_id)

    async def send_discord_webhook(self, message: str):
        webhook_url = self.config.get('DISCORD', 'webhook_url', fallback='')
        if not webhook_url: return
        logger.info(f"[DISCORD] Posting notification: {message.splitlines()[0]}...")
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(webhook_url, json={"content": message}) as resp:
                    if resp.status not in [200, 204]:
                        logger.error(f"Discord webhook failed: {resp.status}")
            except Exception as e: logger.error(f"Error sending Discord webhook: {e}")

    async def discord_update_task(self):
        if not self.config.getboolean('DISCORD', 'enabled', fallback=False): return
        interval = self.config.getint('DISCORD', 'update_interval', fallback=60)
        logger.info(f"Discord Monitoring Task started ({interval}s).")
        while self.running:
            cvars, player_list = await self.rcon.get_status()
            count = len(player_list)
            max_slots = int(cvars.get('sv_maxclients', 16))
            map_name = cvars.get('mapname', 'Unknown')
            if count != self.last_player_count:
                msg_template = None
                if count == 0:
                    msg_template = self.config.get('DISCORD_NOTIFICATIONS', 'empty_server')
                elif count == 1:
                    msg_template = self.config.get('DISCORD_NOTIFICATIONS', 'single_player')
                elif count == max_slots:
                    msg_template = self.config.get('DISCORD_NOTIFICATIONS', 'full_server')
                elif count == max_slots - 1:
                    msg_template = self.config.get('DISCORD_NOTIFICATIONS', 'almost_full')
                elif count % 2 != 0:
                    pool = self.config.get('DISCORD_NOTIFICATIONS', 'imbalance_messages').split('|')
                    msg_template = random.choice(pool)
                if msg_template:
                    msg = msg_template.format(count=count, max=max_slots)
                    if count == 0:
                        payload = msg
                    else:
                        players_str = "\n".join(player_list)
                        payload = f"{msg}\n**Map:** {map_name}\n**Players:**\n{players_str}"
                    await self.send_discord_webhook(payload)
            self.last_player_count = count
            await asyncio.sleep(interval)

    async def broadcast_task(self):
        if not self.config.getboolean('BROADCAST', 'enabled', fallback=False): return
        interval = self.config.getint('BROADCAST', 'interval', fallback=300)
        messages = self.config.get('BROADCAST', 'messages', fallback='').split('|')
        if not messages or not messages[0]: return
        logger.info(f"Broadcast Task started ({interval}s).")
        idx = 0
        while self.running:
            await asyncio.sleep(interval)
            _, player_list = await self.rcon.get_status()
            if len(player_list) > 0:
                current_msg = messages[idx]
                await self.rcon.send_command(f'say ^7{current_msg}')
                idx = (idx + 1) % len(messages)

    async def run(self):
        logger.info(f"Initializing SneakyBot v{self.version}")
        await self.check_server_config()

        loop = asyncio.get_running_loop()
        for s in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(s, lambda: asyncio.create_task(self.shutdown()))

        try:
            await asyncio.gather(
                self.tail_log(),
                self.discord_update_task(),
                self.broadcast_task()
            )
        except asyncio.CancelledError:
            pass

    async def shutdown(self):
        logger.info("Shutdown signal received. Cleaning up...")
        self.running = False
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        [task.cancel() for task in tasks]
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("SneakyBot has shut down gracefully.")
        sys.exit(0)

if __name__ == "__main__":
    cfg = load_config()
    bot = SneakyBot(cfg)
    try:
        asyncio.run(bot.run())
    except (KeyboardInterrupt, SystemExit):
        pass