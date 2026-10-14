import time
import datetime
import asyncio
from collections import defaultdict, deque
import os
import logging
from typing import Optional, Dict, List, Set
import discord
from discord.ext import tasks
import traceback
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Bisou')

# --- RAILWAY HEALTH CHECK SERVER ---
class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Bot is active and running!")
    
    def log_message(self, format, *args):
        pass

def run_health_check_server():
    port = int(os.getenv("PORT", 8080))
    server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
    logger.info(f"Health check server running on port {port}")
    server.serve_forever()

threading.Thread(target=run_health_check_server, daemon=True).start()

# --- CONFIGURATION ---
BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN or BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
    logger.critical("BOT_TOKEN is missing or not set in environment variables.")
    raise ValueError("Please provide a valid BOT_TOKEN in Railway variables.")

LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "1559214858048766022"))

WHITELISTED_USERS: Set[int] = { 
    133844298306172120
       
}

# --- RATE LIMIT CONFIGURATION ---
RATE_LIMITS = {
    'spam': {'limit': 5, 'window': 5},
    'poll': {'limit': 3, 'window': 5},
    'thread': {'limit': 3, 'window': 5},
    'kick': {'limit': 5, 'window': 5},
    'ban': {'limit': 3, 'window': 5},
    'role_delete': {'limit': 3, 'window': 5},
    'channel_delete': {'limit': 3, 'window': 5},
    'webhook_delete': {'limit': 3, 'window': 5},
    'emoji_delete': {'limit': 5, 'window': 5},
    'join_spam': {'limit': 3, 'window': 10},
}

# --- INTENTS ---
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.moderation = True
intents.voice_states = True

bot = discord.Client(intents=intents)

# --- MEMORY STORAGE ---
kick_tracker: Dict[int, List[float]] = defaultdict(list)
ban_tracker: Dict[int, List[float]] = defaultdict(list)
spam_tracker: Dict[int, List[float]] = defaultdict(list)
poll_tracker: Dict[int, List[float]] = defaultdict(list)
thread_tracker: Dict[int, List[float]] = defaultdict(list)
role_delete_tracker: Dict[int, List[float]] = defaultdict(list)
channel_delete_tracker: Dict[int, List[float]] = defaultdict(list)
webhook_delete_tracker: Dict[int, List[float]] = defaultdict(list)
emoji_delete_tracker: Dict[int, List[float]] = defaultdict(list)
join_spam_tracker: Dict[int, List[float]] = defaultdict(list)

MAX_HISTORY_SIZE = 1000
join_history = deque(maxlen=MAX_HISTORY_SIZE)
leave_history = deque(maxlen=MAX_HISTORY_SIZE)

# --- HELPERS ---

async def is_whitelisted(user_or_member, guild: Optional[discord.Guild] = None) -> bool:
    user_id = getattr(user_or_member, 'id', user_or_member)
    return user_id in WHITELISTED_USERS

async def get_audit_log_actor(guild: discord.Guild, action: discord.AuditLogAction, target_id: int) -> Optional[discord.User]:
    try:
        async for entry in guild.audit_logs(limit=10, action=action):
            if entry.target and entry.target.id == target_id:
                return entry.user
    except (discord.Forbidden, discord.HTTPException) as e:
        logger.warning(f"Failed to fetch audit log: {e}")
    return None

def check_rate_limit(user_id: int, tracker: dict, limit: int, window: int = 5) -> bool:
    now = time.time()
    tracker[user_id] = [t for t in tracker[user_id] if now - t <= window]
    tracker[user_id].append(now)
    return len(tracker[user_id]) >= limit

async def send_mod_log(
    guild: discord.Guild,
    action: str,
    actor: discord.abc.User,
    target: str,
    details: str,
    color: int = 0x2B2D31
):
    try:
        if LOG_CHANNEL_ID == 0:
            return
            
        log_channel = guild.get_channel(LOG_CHANNEL_ID)
        if not log_channel:
            return
        
        embed = discord.Embed(
            title=f"Security Trigger: {action}",
            description=details[:4096],
            color=color,
            timestamp=discord.utils.utcnow()
        )
        
        embed.add_field(
            name="Triggered By",
            value=f"{actor.mention}\nID: `{actor.id}`",
            inline=True
        )
        
        embed.add_field(
            name="Target",
            value=target[:1024],
            inline=True
        )
        
        current_time = int(time.time())
        embed.add_field(
            name="Time Occurred",
            value=f"<t:{current_time}:F>\n(<t:{current_time}:R>)",
            inline=False
        )
        
        embed.set_footer(text="Kinsec Security System")
        await log_channel.send(embed=embed)
    except Exception as e:
        logger.error(f"Failed to send mod log: {e}")

async def clean_trackers():
    now = time.time()
    trackers = [
        kick_tracker, ban_tracker, spam_tracker, poll_tracker,
        thread_tracker, role_delete_tracker, channel_delete_tracker,
        webhook_delete_tracker, emoji_delete_tracker, join_spam_tracker
    ]
    
    for tracker in trackers:
        for user_id in list(tracker.keys()):
            tracker[user_id] = [t for t in tracker[user_id] if now - t <= 300]
            if not tracker[user_id]:
                del tracker[user_id]

# --- BOT EVENTS ---

@bot.event
async def on_ready():
    logger.info(f"Bisou Active. Logged in as: {bot.user} (ID: {bot.user.id})")
    if not presence_loop.is_running():
        presence_loop.start()
    if not cleanup_loop.is_running():
        cleanup_loop.start()

@tasks.loop(seconds=15)
async def presence_loop():
    try:
        members = sum(g.member_count or 0 for g in bot.guilds)
        await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=f"{members} members"))
    except Exception as e:
        logger.error(f"Presence loop error: {e}")

@presence_loop.before_loop
async def before_presence_loop():
    await bot.wait_until_ready()

@tasks.loop(minutes=5)
async def cleanup_loop():
    try:
        await clean_trackers()
    except Exception as e:
        logger.error(f"Cleanup loop error: {e}")

@cleanup_loop.before_loop
async def before_cleanup_loop():
    await bot.wait_until_ready()

# --- MEMBER EVENTS ---

@bot.event
async def on_member_join(member: discord.Member):
    try:
        join_history.append(datetime.datetime.now(datetime.timezone.utc))
        uid = member.id
        if check_rate_limit(uid, join_spam_tracker, RATE_LIMITS['join_spam']['limit'], RATE_LIMITS['join_spam']['window']):
            await member.ban(reason="Join spam detected", delete_message_days=0)
    except Exception as e:
        logger.error(f"Error in on_member_join: {e}")

# --- MESSAGE EVENT (INVITE FILTERING REMOVED) ---

@bot.event
async def on_message(message: discord.Message):
    """Handle messages with spam detection only (No link/invite filtering)."""
    try:
        if message.author.bot or message.guild is None:
            return
        
        if await is_whitelisted(message.author, message.guild):
            return
        
        uid = message.author.id
        
        # POLL SPAM
        if getattr(message, "poll", None):
            if check_rate_limit(uid, poll_tracker, RATE_LIMITS['poll']['limit'], RATE_LIMITS['poll']['window']):
                poll_tracker[uid].clear()
                try:
                    await asyncio.gather(
                        message.channel.purge(limit=10, check=lambda m: getattr(m, "poll", None) and m.author == message.author),
                        message.author.timeout(datetime.timedelta(minutes=1), reason="Mass Poll Spam"),
                        message.channel.send(f"stfu {message.author.mention}.")
                    )
                except discord.HTTPException:
                    pass
            return
        
        # TEXT SPAM
        if check_rate_limit(uid, spam_tracker, RATE_LIMITS['spam']['limit'], RATE_LIMITS['spam']['window']):
            spam_tracker[uid].clear()
            try:
                await asyncio.gather(
                    message.channel.purge(limit=10, check=lambda m: m.author == message.author),
                    message.author.timeout(datetime.timedelta(minutes=1), reason="Mass Spam"),
                    message.channel.send(f"stfu {message.author.mention}.")
                )
            except discord.HTTPException:
                pass
            return
        
    except Exception as e:
        logger.error(f"Error in on_message: {e}")

# --- START BOT ---

if __name__ == "__main__":
    try:
        bot.run(BOT_TOKEN)
    except Exception as e:
        logger.critical(f"Failed to start bot: {e}\n{traceback.format_exc()}")


