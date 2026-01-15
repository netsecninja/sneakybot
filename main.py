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
from typing import Dict, List, Tuple, Set, Optional

# --- METADATA ---
__version__ = "3.1.2"
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

# Map Quake gametype IDs to human readable names
GAMETYPES = {
    "0": "Free For All",
    "3": "Team Death Match",
    "4": "Team Survivor",
    "5": "Follow the Leader",
    "6": "Capture and Hold",
    "7": "Capture the Flag",
    "8": "Bomb Mode"
}

def load_config():
    """
    Generates a default config.ini and loads settings.
    Ensures all required sections exist.
    """
    config = configparser.ConfigParser(allow_no_value=True)

    if not os.path.exists(CONFIG_FILE):
        config['PATHS'] = {
            '; Path to the Urban Terror games.log file': None,
            'log_path': '/opt/urbanterror43/q3ut4/games.log',
            '; Path to the server.cfg for auto-validation': None,
            'server_cfg': '/opt/urbanterror43/q3ut4/server.cfg',
            '; Path to the mapcycle.txt file': None,
            'mapcycle_path': '/opt/urbanterror43/q3ut4/mapcycle.txt'
        }
        config['SERVER'] = {
            '; Quake3 server connection details': None,
            'host': '127.0.0.1',
            'port': '27960'
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
            ),
            '; If enabled, "Next Map" info will be added to the rotation of periodic messages': None,
            'include_nextmap': 'true'
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
        logger.info("Please edit config.ini before running.")
        logger.info("=" * 50)
        sys.exit(0)

    config.read(CONFIG_FILE)

    # Validation for existing configs
    sections_added = False
    for section in ['RULES', 'BROADCAST', 'DISCORD', 'DISCORD_NOTIFICATIONS']:
        if section not in config:
            config[section] = {}
            sections_added = True

    if sections_added:
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)

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
        self.log_path = config.get('PATHS', 'log_path', fallback='')
        self.server_cfg = config.get('PATHS', 'server_cfg', fallback='')
        self.mapcycle_path = config.get('PATHS', 'mapcycle_path', fallback='')

        self.rcon = RCONClient(
            host=config.get('SERVER', 'host', fallback='127.0.0.1'),
            port=config.getint('SERVER', 'port', fallback=27960),
            password=""
        )

        self.running = True
        self.players: Dict[str, str] = {}
        self.welcomed_players: Set[str] = set()
        self.last_player_count = -1 # Start at -1 to trigger initial post if server has people

        self.message_queue = asyncio.Queue()

    def _get_rcon_from_cfg(self):
        if not self.server_cfg or not os.path.exists(self.server_cfg):
            return None
        try:
            with open(self.server_cfg, 'r') as f:
                content = f.read()
                match = re.search(rf'set[a]?\s+rconpassword\s+["\']?([^"\']+)["\']?', content, re.IGNORECASE)
                if match:
                    return match.group(1)
        except Exception as e:
            logger.error(f"Error reading RCON password from server.cfg: {e}")
        return None

    async def broadcast(self, message: str, priority: bool = False):
        if priority:
            await self.rcon.send_command(f'say {message}')
        else:
            await self.message_queue.put(message)

    async def get_next_map_info(self) -> str:
        if not self.mapcycle_path or not os.path.exists(self.mapcycle_path):
            return "Mapcycle file not found."
        cvars, _ = await self.rcon.get_status()
        current_map = cvars.get('mapname', '').lower()
        if not current_map: return "Cannot determine current map."
        try:
            with open(self.mapcycle_path, 'r') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            next_line = None
            for i, line in enumerate(lines):
                if line.lower().startswith(current_map):
                    next_line = lines[(i + 1) % len(lines)]
                    break
            if not next_line and lines: next_line = lines[0]
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
                return f"Next map: {prefix_str + ' ' if prefix_str else ''}{gametype_str} on {target_map}"
        except Exception as e:
            logger.error(f"Error parsing mapcycle: {e}")
            return "Error reading map rotation."
        return "Map cycle empty or current map not found."

    async def check_server_config(self):
        required_vars = {"g_logsync": "1", "g_loghits": "1"}
        if not self.server_cfg or not os.path.exists(self.server_cfg):
            logger.warning(f"server.cfg not found. RCON functionality limited.")
            return
        extracted_pw = self._get_rcon_from_cfg()
        if extracted_pw:
            self.rcon.password = extracted_pw
            logger.info("Successfully extracted RCON password from server.cfg")
        try:
            with open(self.server_cfg, 'r') as f: lines = f.readlines()
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
                with open(self.server_cfg, 'w') as f: f.writelines(lines)
                logger.critical("!!! server.cfg updated. PLEASE RESTART THE SERVER !!!")
                sys.exit(1)
        except SystemExit: raise
        except Exception as e: logger.error(f"Config check failed: {e}")

    async def tail_log(self):
        if not os.path.exists(self.log_path): return
        with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(0, os.SEEK_END)
            last_pos = f.tell()
            while self.running:
                line = f.readline()
                if not line:
                    if os.path.getsize(self.log_path) < last_pos: f.seek(0)
                    else: await asyncio.sleep(0.5)
                    last_pos = f.tell()
                    continue
                await self.parse_line(line.strip())

    async def parse_line(self, line: str):
        if 'say:' in line:
            match = RE_CHAT.search(line)
            if match: await self.on_chat(match.group(1), match.group(2))
        elif 'ClientUserinfoChanged:' in line:
            match = RE_USERINFO.search(line)
            if match: self.players[match.group(1)] = match.group(2)
        elif 'ClientBegin:' in line:
            match = RE_BEGIN.search(line)
            if match: await self.on_connect(match.group(1))
        elif 'ClientDisconnect:' in line:
            match = RE_DISCONNECT.search(line)
            if match:
                cid = match.group(1)
                if cid in self.players: del self.players[cid]
                if cid in self.welcomed_players: self.welcomed_players.remove(cid)

    async def on_chat(self, name: str, message: str):
        msg = message.strip().lower()
        if msg == '!rules':
            rule_config = self.config.get('RULES', 'rule_list', fallback='1. No Cheating | 2. Respect Others')
            rules = [r.strip() for r in rule_config.split('|')]
            for rule in rules:
                await self.broadcast(f'^2RULES: ^7{rule}', priority=True)
                await asyncio.sleep(0.2)
        elif msg == '!ping': await self.broadcast('^3Pong!', priority=True)
        elif msg == '!sneakybot': await self.broadcast(f'^7SneakyBot v{self.version}: ^3https://github.com/netsecninja/sneakybot', priority=True)
        elif msg == '!nextmap':
            resp = await self.get_next_map_info()
            await self.broadcast(f'^7{resp}', priority=True)
        elif msg in ['!forgive', '!forgiveall', '!fp', '!fa']:
            await self.broadcast("^1Bwahahaha! ^7There's no forgiveness here!", priority=True)
        elif msg == '!help':
            await self.broadcast('^7Available commands: ^3!help, !rules, !ping, !sneakybot, !nextmap', priority=True)

    async def on_connect(self, client_id: str):
        player_name = self.players.get(client_id, f"Client {client_id}")
        if client_id in self.welcomed_players: return
        await self.broadcast(f'^7Welcome ^3{player_name}^7! - Powered by SneakyBot', priority=True)
        self.welcomed_players.add(client_id)

    async def orchestrator_task(self):
        logger.info("Message Orchestrator started.")
        while self.running:
            try:
                message = await self.message_queue.get()
                _, player_list = await self.rcon.get_status()
                if len(player_list) > 0:
                    await self.rcon.send_command(f'say {message}')
                    await asyncio.sleep(2)
                self.message_queue.task_done()
            except asyncio.CancelledError: break
            except Exception as e:
                logger.error(f"Error in orchestrator: {e}")
                await asyncio.sleep(1)

    async def send_discord_webhook(self, content: str):
        url = self.config.get('DISCORD', 'webhook_url', fallback='')
        if not url: return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json={"content": content}) as resp:
                    if resp.status not in [200, 204]:
                        logger.error(f"Discord Webhook failed with status {resp.status}")
        except Exception as e:
            logger.error(f"Discord Webhook error: {e}")

    async def discord_update_task(self):
        if not self.config.getboolean('DISCORD', 'enabled', fallback=False): return
        interval = self.config.getint('DISCORD', 'update_interval', fallback=60)
        logger.info("Discord Update Task started.")

        while self.running:
            try:
                cvars, player_list = await self.rcon.get_status()
                count = len(player_list)
                max_players = int(cvars.get('sv_maxclients', '20'))

                if count != self.last_player_count:
                    msg = ""
                    notifs = self.config['DISCORD_NOTIFICATIONS']

                    if count == 0:
                        msg = notifs.get('empty_server', "Server is empty.")
                    elif count == 1:
                        msg = notifs.get('single_player', "A player is online.")
                    elif count == max_players:
                        msg = notifs.get('full_server', "{count} players. Full!").format(count=count, max=max_players)
                    elif count == max_players - 1:
                        msg = notifs.get('almost_full', "{count} players. One slot left!").format(count=count, max=max_players)
                    else:
                        imb_msgs = notifs.get('imbalance_messages', "{count} players online.").split('|')
                        msg = random.choice(imb_msgs).format(count=count, max=max_players)

                    if msg:
                        await self.send_discord_webhook(msg)
                    self.last_player_count = count

                await asyncio.sleep(interval)
            except asyncio.CancelledError: break
            except Exception as e:
                logger.error(f"Error in Discord task: {e}")
                await asyncio.sleep(10)

    async def automated_broadcast_timer(self):
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
                if include_nextmap and (idx % 2 != 0 or not messages):
                    resp = await self.get_next_map_info()
                    await self.broadcast(f'^7{resp}')
                elif messages:
                    msg_idx = (idx // 2) % len(messages) if include_nextmap else idx % len(messages)
                    await self.broadcast(f'^7{messages[msg_idx]}')
                idx += 1
            except asyncio.CancelledError: break

    async def run(self):
        logger.info(f"Starting SneakyBot v{self.version}")
        try:
            await self.check_server_config()
            loop = asyncio.get_running_loop()
            for s in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(s, lambda: asyncio.create_task(self.shutdown()))
            await asyncio.gather(
                self.tail_log(),
                self.orchestrator_task(),
                self.discord_update_task(),
                self.automated_broadcast_timer()
            )
        except asyncio.CancelledError: pass
        finally: await self.shutdown()

    async def shutdown(self):
        if not self.running: return
        self.running = False
        logger.info("Shutting down SneakyBot...")
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        sys.exit(0)

if __name__ == "__main__":
    try:
        cfg = load_config()
        bot = SneakyBot(cfg)
        asyncio.run(bot.run())
    except (KeyboardInterrupt, SystemExit): pass
    except Exception as e:
        logger.critical(f"Bot failed: {e}")
        logger.debug(traceback.format_exc())