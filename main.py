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
import traceback
from pathlib import Path
from typing import Dict, List, Tuple, Set

# --- METADATA ---
__version__: str = "3.1.5"
__author__: str = "Jeremiah Bess - [SBs]PenguinGeek"

# --- CONFIGURATION MANAGEMENT ---
CONFIG_FILE: str = "sneakybot.cfg"
LOG_FILE: str = "sneakybot.log"
REQUIRED_SERVER_SETTINGS: dict = {'g_logsync': '1', 'g_loghits': '1'}

# Map Quake gametype IDs to human-readable names
GAMETYPES: dict = {
    "0": "Free For All",
    "1": "Last Man Standing",
    "2": "Free For All",
    "3": "Team Death Match",
    "4": "Team Survivor",
    "5": "Follow the Leader",
    "6": "Capture and Hold",
    "7": "Capture the Flag",
    "8": "Bomb Mode",
    "9": "Jump Training",
    "10": "Freeze Tag",
    "11": "Gun Game"
}

# --- REGEX PATTERNS ---
RE_USERINFO: re.Pattern = re.compile(r'ClientUserinfoChanged:\s(\d+)\s.*n\\([^\\]+)')
RE_BEGIN: re.Pattern = re.compile(r'ClientBegin:\s(\d+)')
RE_DISCONNECT: re.Pattern = re.compile(r'ClientDisconnect:\s(\d+)')
RE_CHAT: re.Pattern = re.compile(r'say:\s*\d+\s+(?:\d+\s+)?(.*?):\s*(.*)', re.IGNORECASE)
RE_RCONPASSWORD: re.Pattern = re.compile(r'set[a]?\s+rconpassword\s+["\']?([^"\']+)["\']?', re.IGNORECASE)
RE_SERVER_VARS: re.Pattern = re.compile(r'^set[asu]?\s+"?(\w+)"?\s+"([^"]*)"', re.IGNORECASE)

# --- LOGGING SETUP ---
logger: logging.Logger = logging.getLogger("SneakyBot")
logger.setLevel(logging.INFO)

formatter: logging.Formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')

console_handler: logging.StreamHandler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler: logging.FileHandler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def load_bot_config() -> configparser.ConfigParser:
    """
    Loads settings from sneakybot.cfg, or generates a default one if it doesn't exist
    """
    config = configparser.ConfigParser(allow_no_value=True)

    if not os.path.exists(CONFIG_FILE):
        config['PATHS'] = {
            '; Path to the q3ut4 folder, which has your server.cfg': None,
            'q3ut4_path': '/opt/urbanterror43/q3ut4',
        }
        config['SERVER'] = {
            '; Quake3 server connection details': None,
            'host': '127.0.0.1',
            'port': '27960'
        }
        config['RULES'] = {
            '; Rules shown when a player types !rules. Separate with | for multi-line display.': None,
            'rule_list': (
                '1. Listen to Admins and clan members|2. No swearing, bullying, or offensive comments|'
                '3 and 4. Camping and Spawn killing are allowed|5. Rules are flexible'
            )
        }
        config['BROADCAST'] = {
            '; In-game periodic messages. Use | to separate multiple messages.': None,
            'enabled': 'true',
            'interval': '300',
            'messages': (
                "This is a family-oriented server, watch your language and behavior|"
                "Server rules listed at sneakybs.com|"
                "Join our Discord voice - link at sneakybs.com"
            ),
            '; If enabled, "Next Map" info will be added to the rotation of periodic messages': None,
            'include_nextmap': 'true'
        }
        config['DISCORD'] = {
            '; Toggle Discord integration and set webhook URL': None,
            'enabled': 'false',
            'webhook_url': '',
            'update_interval': '60',
            '; Templates for Discord posts. {count} and {max} are variables.': None,
            'empty_server': "No more players online, hope you didn't miss the fun.",
            'single_player': "A player is online looking for some competition.",
            'full_server': "{count} players are online. The server is full!",
            'almost_full': "{count} players are online. One more slot open!",
            '; use | in imbalance_messages to provide random variety.': None,
            'imbalance_messages': (
                "{count} players are online. Log in to even up the teams!|"
                "{count} players are online. Things are heating up!|"
                "{count} players are online. You do NOT want to miss this!|"
                "The battle is raging with {count} players. Join now!"
            )
        }

        with open(CONFIG_FILE, 'w') as f:
            config.write(f)

        logger.info("=" * 50)
        logger.info(f"CREATED DEFAULT CONFIGURATION: {CONFIG_FILE}")
        logger.info("Please edit sneakybot.cfg before running.")
        logger.info("=" * 50)
        sys.exit(0)

    config.read(CONFIG_FILE)

    if 'RULES' not in config:
        config['RULES'] = {'rule_list': '1. No Cheating | 2. Respect Others | 3. Have Fun'}
        logger.warning(f'[RULES] section of the {CONFIG_FILE} is missing. Defaulting to basic rules: '
                       f'{config["RULES"]["rule_list"]}')

    return config

def load_server_config(bot_config: configparser.ConfigParser) -> None:
    """Loads the server.cfg file, collects information needed, and corrects required settings"""
    server_cfg = Path(bot_config['PATHS']['q3ut4_path']) / 'server.cfg'
    server_config = {'rconpassword': '', 'g_log': '', 'g_mapcycle': ''}
    updated_lines: list[str] = []
    lines_changed = False

    try:
        with open(server_cfg, 'r') as f:
            for line in f:
                match = RE_SERVER_VARS.match(line)
                if not match:
                    updated_lines.append(line)
                    continue

                setting, value = match.groups()
                if setting in server_config:
                    server_config[setting] = value
                    updated_lines.append(line)
                    continue

                if setting not in REQUIRED_SERVER_SETTINGS:
                    updated_lines.append(line)
                    continue

                if value != REQUIRED_SERVER_SETTINGS[setting]:
                    line = f'set\t{setting}\t"{REQUIRED_SERVER_SETTINGS[setting]}"\t// Required by Sneakbot\n'
                    updated_lines.append(line)
                    lines_changed = True

        if lines_changed:
            with open(server_cfg, 'w') as f:
                f.writelines(updated_lines)

            logger.critical('!!! server.cfg updated. PLEASE RESTART THE URBAN TERROR SERVER !!!')
            sys.exit(1)

        if any(not value for value in server_config.values()):
            logger.critical(f'One or more of the settings in server.cfg is empty\n{server_cfg}')
            sys.exit(1)

        bot_config['PATHS']['games_log'] = str(Path(bot_config['PATHS']['q3ut4_path']) / server_config['g_log'])
        bot_config['PATHS']['mapcycle_txt'] = str(Path(bot_config['PATHS']['q3ut4_path']) / server_config['g_mapcycle'])
        bot_config['SERVER']['rconpassword'] = server_config['rconpassword']
        logger.info('Successfully parsed server.cfg')

    except SystemExit:
        raise
    except FileNotFoundError:
        logger.critical(f"Error: Configuration file '{server_cfg}' not found.")
    except Exception as e:
        logger.critical(f"Config check failed: {e}")

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
        if not self.password:
            logger.error("[RCON] No password available. Command aborted.")
            return "No Password"

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
        if not self.password: return {}, []
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
        self.log_path = config.get('PATHS', 'games_log')
        self.mapcycle_path = config.get('PATHS', 'mapcycle_txt')
        self.rconpassword = config.get('SERVER', 'rconpassword')

        self.rcon = RCONClient(
            host=config.get('SERVER', 'host', fallback='127.0.0.1'),
            port=config.getint('SERVER', 'port', fallback=27960),
            password=self.rconpassword
        )

        self.running = True
        self.players: Dict[str, str] = {}
        self.welcomed_players: Set[str] = set()
        self.last_player_count = 0

        # Centralized Message Orchestration
        self.message_queue = asyncio.Queue()

    async def run(self):
        logger.info(f"Starting SneakyBot v{self.version}")
        try:
            loop = asyncio.get_running_loop()
            for s in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(s, lambda: asyncio.create_task(self.shutdown()))

            # Start all tasks
            await asyncio.gather(
                self.tail_log(),
                self.orchestrator_task(),
                self.discord_update_task(),
                self.automated_broadcast_timer()
            )
        except asyncio.CancelledError:
            # Expected during shutdown
            pass
        except Exception as e:
            logger.error(f"Critical error in bot loop: {e}")
            logger.debug(traceback.format_exc())
        finally:
            await self.shutdown()

    async def shutdown(self):
        if not self.running: return
        self.running = False
        logger.info("Shutting down SneakyBot...")
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()

        # Give tasks a moment to wrap up
        await asyncio.gather(*tasks, return_exceptions=True)
        sys.exit(0)

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

    async def orchestrator_task(self):
        """Processes the message queue with a staggered delay to prevent flood kicks/spam."""
        logger.info("Message Orchestrator started.")
        while self.running:
            try:
                message = await self.message_queue.get()
                # Fast check for players before sending
                _, player_list = await self.rcon.get_status()
                if len(player_list) > 0:
                    await self.rcon.send_command(f'say {message}')
                    # Stagger automated messages by 2 seconds to avoid clogging the screen
                    await asyncio.sleep(2)
                self.message_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in orchestrator: {e}")
                await asyncio.sleep(1)

    async def discord_update_task(self):
        if not self.config.getboolean('DISCORD', 'enabled', fallback=False): return
        interval = self.config.getint('DISCORD', 'update_interval', fallback=60)
        while self.running:
            cvars, player_list = await self.rcon.get_status()
            count = len(player_list)
            max_slots = int(cvars.get('sv_maxclients', 16))
            map_name = cvars.get('mapname', 'Unknown')
            if count != self.last_player_count:
                msg_template = None
                if count == 0: msg_template = self.config.get('DISCORD', 'empty_server')
                elif count == 1: msg_template = self.config.get('DISCORD', 'single_player')
                elif count == max_slots: msg_template = self.config.get('DISCORD', 'full_server')
                elif count == max_slots - 1: msg_template = self.config.get('DISCORD', 'almost_full')
                elif count % 2 != 0:
                    pool = self.config.get('DISCORD', 'imbalance_messages').split('|')
                    msg_template = random.choice(pool)
                if msg_template:
                    msg = msg_template.format(count=count, max=max_slots)
                    payload = f"{msg}\n**Map:** {map_name}\n**Players:**\n" + "\n".join(player_list) if count > 0 else msg
                    await self.send_discord_webhook(payload)
            self.last_player_count = count
            await asyncio.sleep(interval)

    async def automated_broadcast_timer(self):
        """Timer for general periodic messages and optional nextmap announcements."""
        if not self.config.getboolean('BROADCAST', 'enabled', fallback=False): return
        interval = self.config.getint('BROADCAST', 'interval', fallback=300)
        messages_raw = self.config.get('BROADCAST', 'messages', fallback='')
        include_nextmap = self.config.getboolean('BROADCAST', 'include_nextmap', fallback=True)

        messages = [m.strip() for m in messages_raw.split('|') if m.strip()]
        if not messages and not include_nextmap: return

        idx = 0
        while self.running:
            try:
                await asyncio.sleep(interval)

                # Logic: Cycle through configured messages.
                # If include_nextmap is true, every alternate message is a nextmap update.
                if include_nextmap and (idx % 2 != 0 or not messages):
                    resp = await self.get_next_map_info()
                    await self.broadcast(f'^7{resp}')
                elif messages:
                    # Adjust index to point to correct message list item
                    msg_idx = (idx // 2) % len(messages) if include_nextmap else idx % len(messages)
                    await self.broadcast(f'^7{messages[msg_idx]}')

                idx += 1
            except asyncio.CancelledError:
                break

    async def parse_line(self, line: str):
        if 'say:' in line:
            match = RE_CHAT.search(line)
            if match:
                await self.on_chat(match.group(1), match.group(2))

        elif 'ClientUserinfoChanged:' in line:
            match = RE_USERINFO.search(line)
            if match: self.players[match.group(1)] = match.group(2)

        elif 'ClientBegin:' in line:
            match = RE_BEGIN.search(line)
            if match: await self.on_connect(match.group(1))
            cid = match.group(1)
            logger.info(f'[CONNECT] Player {cid} - {self.players[cid]} connected')

        elif 'ClientDisconnect:' in line:
            match = RE_DISCONNECT.search(line)
            if match:
                cid = match.group(1)
                if cid in self.players:
                    logger.info(f'[DISCONNECT] Player {cid} - {self.players[cid]} disconnected')
                    del self.players[cid]
                else:
                    logger.info(f'[DISCONNECT] Player {cid} - Unknown disconnected')
                if cid in self.welcomed_players: self.welcomed_players.remove(cid)

    async def on_chat(self, name: str, message: str):
        msg = message.strip().lower()
        logger.info(f"[CHAT] {name}: {msg}")

        if msg == '!rules':
            rule_config = self.config.get('RULES', 'rule_list', fallback='1. No Cheating | 2. Respect Others')
            rules = [r.strip() for r in rule_config.split('|')]
            rules_reply = ''
            for rule in rules:
                reply = f'^2RULES: ^7{rule}'
                await self.broadcast(reply, priority=True)
                rules_reply += reply
                await asyncio.sleep(0.1)

        elif msg == '!ping':
            reply = '^3Pong!'
            await self.broadcast(reply, priority=True)

        elif msg == '!sneakybot':
            reply = f'^7SneakyBot v{self.version}: ^3https://github.com/netsecninja/sneakybot'
            await self.broadcast(reply, priority=True)

        elif msg == '!nextmap':
            resp = await self.get_next_map_info()
            reply = f'^7{resp}'
            await self.broadcast(reply, priority=True)

        elif msg in ['!forgive', '!forgiveall', '!fp', '!fa']:
            reply = "^1Bwahahaha! ^7There's no forgiveness here!"
            await self.broadcast(reply, priority=True)

        elif msg == '!help':
            commands = "!help, !rules, !ping, !sneakybot, !nextmap"
            reply = f'^7Available commands: ^3{commands}'
            await self.broadcast(reply, priority=True)

    async def get_next_map_info(self) -> str:
        """Parses mapcycle.txt to find the next map info based on current map."""
        if not self.mapcycle_path or not os.path.exists(self.mapcycle_path):
            return "Mapcycle file not found."

        cvars, _ = await self.rcon.get_status()
        current_map = cvars.get('mapname', '').lower()

        try:
            with open(self.mapcycle_path, 'r') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]

            next_line = None
            for i, line in enumerate(lines):
                if line.lower().startswith(current_map):
                    next_line = lines[(i + 1) % len(lines)]
                    break

            if not next_line and lines:
                next_line = lines[0]

            if next_line:
                map_match = re.match(r'^([^\s{]+)', next_line)
                if not map_match: return "Could not parse next map name."

                target_map = map_match.group(1)

                gt = re.search(r'g_gametype\s+(\d+)', next_line)
                insta = re.search(r'g_instagib\s+(\d+)', next_line)
                grav = re.search(r'g_gravity\s+(\d+)', next_line)

                gametype_str = GAMETYPES.get(gt.group(1) if gt else "0", "Unknown Mode")
                is_instagib = (insta.group(1) == "1") if insta else False
                is_lowgrav = (int(grav.group(1)) < 800) if grav else False

                prefix = []
                if is_lowgrav: prefix.append("Low gravity")
                if is_instagib: prefix.append("Instagib")

                prefix_str = " ".join(prefix)
                if prefix_str:
                    return f"Next map: {prefix_str} {gametype_str} on {target_map}"
                else:
                    return f"Next map: {gametype_str} on {target_map}"

        except Exception as e:
            logger.error(f"Error parsing mapcycle: {e}")
            return "Error reading map rotation."

        return "Map cycle empty or current map not found."

    async def on_connect(self, client_id: str):
        player_name = self.players.get(client_id, f"Client {client_id}")
        if client_id in self.welcomed_players: return
        await self.broadcast(f'^7Welcome ^3{player_name}^7! - Powered by SneakyBot', priority=True)
        self.welcomed_players.add(client_id)

    async def broadcast(self, message: str, priority: bool = False):
        """Adds a message to the orchestrator queue."""
        if priority:
            # High priority responses bypass the queue for immediate feedback
            await self.rcon.send_command(f'say {message}')
        else:
            await self.message_queue.put(message)

    async def send_discord_webhook(self, message: str):
        webhook_url = self.config.get('DISCORD', 'webhook_url', fallback='')
        if not webhook_url: return
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(webhook_url, json={"content": message}) as resp:
                    if resp.status not in [200, 204]:
                        logger.error(f"Discord webhook failed: {resp.status}")
                    else:
                        logger.info(f'[DISCORD] Posted message: {message}')
            except Exception as e: logger.error(f"Error sending Discord webhook: {e}")

if __name__ == "__main__":
    try:
        bot_config: configparser.ConfigParser = load_bot_config()
        load_server_config(bot_config)
        bot = SneakyBot(bot_config)
        asyncio.run(bot.run())
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        logger.critical(f"Bot failed to start: {e}")
        logger.debug(traceback.format_exc())