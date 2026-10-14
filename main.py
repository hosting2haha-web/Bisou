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
import re
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Bisou')

# --- RAILWAY HEALTH CHECK SERVER ---
# Railway requires web services to bind to a port. This prevents H10/health check crashes.
class HealthCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Bot is active and running!")
    
    def log_message(self, format, *args):
        # Suppress routine HTTP log spam in console
        pass

def run_health_check_server():
    port = int(os.getenv("PORT", 8080))
    server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
    logger.info(f"Health check server running on port {port}")
    server.serve_forever()

# Start the health check server in a background daemon thread
threading.Thread(target=run_health_check_server, daemon=True).start()

# --- CONFIGURATION ---
BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN or BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
    logger.critical("BOT_TOKEN is missing or not set in environment variables.")
    raise ValueError("Please provide a valid BOT_TOKEN in Railway variables.")

# Hardcoded configuration
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID", "1559214858048766022"))

# Hardcoded whitelisted users (these users are immune to all security features)
WHITELISTED_USERS: Set[int] = {
    1394753272492851322,  # User 1
    133844298306172120, 
    1524254377001357332   # User 2
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
    """Check if user is whitelisted (global whitelist only)."""
    user_id = getattr(user_or_member, 'id', user_or_member)
    return user_id in WHITELISTED_USERS

async def get_audit_log_actor(guild: discord.Guild, action: discord.AuditLogAction, target_id: int) -> Optional[discord.User]:
    """Safely fetch audit log actor with fallback."""
    try:
        async for entry in guild.audit_logs(limit=10, action=action):
            if entry.target and entry.target.id == target_id:
                return entry.user
    except (discord.Forbidden, discord.HTTPException) as e:
        logger.warning(f"Failed to fetch audit log: {e}")
    return None

def check_rate_limit(user_id: int, tracker: dict, limit: int, window: int = 5) -> bool:
    """Check if user exceeds rate limit."""
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
    """Safely send moderation log with error handling."""
    try:
        if LOG_CHANNEL_ID == 0:
            return
            
        log_channel = guild.get_channel(LOG_CHANNEL_ID)
        if not log_channel:
            logger.warning(f"Log channel {LOG_CHANNEL_ID} not found in guild {guild.id}")
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
        logger.info(f"Mod log sent: {action} by {actor.id} in {guild.id}")
        
    except discord.Forbidden:
        logger.error(f"Missing permissions to send log in guild {guild.id}")
    except discord.HTTPException as e:
        logger.error(f"Failed to send mod log: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in send_mod_log: {e}")

async def clean_trackers():
    """Periodically clean up old tracker entries to prevent memory leaks."""
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
    """Bot startup with security checks."""
    logger.info(f"Bisou Active. Logged in as: {bot.user} (ID: {bot.user.id})")
    logger.info(f"Whitelisted Users: {WHITELISTED_USERS}")
    logger.info(f"Log Channel ID: {LOG_CHANNEL_ID}")
    
    for guild in bot.guilds:
        me = guild.get_member(bot.user.id)
        if me:
            perms = me.guild_permissions
            missing = []
            if not perms.ban_members: missing.append("Ban Members")
            if not perms.kick_members: missing.append("Kick Members")
            if not perms.manage_roles: missing.append("Manage Roles")
            if not perms.manage_channels: missing.append("Manage Channels")
            if not perms.view_audit_log: missing.append("View Audit Log")
            if not perms.manage_messages: missing.append("Manage Messages")
            
            if missing:
                logger.warning(f"Missing permissions in {guild.name}: {', '.join(missing)}")
    
    if not presence_loop.is_running():
        presence_loop.start()
    
    if not cleanup_loop.is_running():
        cleanup_loop.start()

# --- BACKGROUND TASKS ---

@tasks.loop(seconds=15)
async def presence_loop():
    """Update bot presence with error handling."""
    try:
        members = sum(g.member_count or 0 for g in bot.guilds)
        vc_members = sum(
            len(vc.members)
            for g in bot.guilds
            for vc in g.voice_channels
        )
        
        activities = [
            discord.Streaming(name="/bisou", url="https://www.twitch.tv/discord"),
            discord.Activity(type=discord.ActivityType.watching, name=f"{vc_members} in vc"),
            discord.Activity(type=discord.ActivityType.watching, name=f"{members} members"),
            discord.Activity(type=discord.ActivityType.competing, name="Security")
        ]
        
        presence_loop.idx = getattr(presence_loop, "idx", 0)
        await bot.change_presence(activity=activities[presence_loop.idx % len(activities)])
        presence_loop.idx += 1
        
    except Exception as e:
        logger.error(f"Presence loop error: {e}")

@presence_loop.before_loop
async def before_presence_loop():
    await bot.wait_until_ready()

@tasks.loop(minutes=5)
async def cleanup_loop():
    """Periodically clean up old tracker data."""
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
    """Track member joins with raid detection and join spam prevention."""
    try:
        join_history.append(datetime.datetime.now(datetime.timezone.utc))
        
        now = time.time()
        recent_joins = [t for t in join_history if now - t.timestamp() <= 60]
        if len(recent_joins) >= 10:
            logger.warning(f"Potential raid detected in {member.guild.name}: {len(recent_joins)} joins in 60s")
            
            if LOG_CHANNEL_ID != 0:
                log_channel = member.guild.get_channel(LOG_CHANNEL_ID)
                if log_channel:
                    embed = discord.Embed(
                        title="Potential Raid Detected",
                        description=f"**{len(recent_joins)}** members joined in the last 60 seconds.",
                        color=0xFF0000,
                        timestamp=discord.utils.utcnow()
                    )
                    embed.set_footer(text="Kinsec Security System")
                    await log_channel.send(embed=embed)
        
        uid = member.id
        if check_rate_limit(uid, join_spam_tracker, RATE_LIMITS['join_spam']['limit'], RATE_LIMITS['join_spam']['window']):
            try:
                await member.ban(
                    reason=f"Join spam detected: {RATE_LIMITS['join_spam']['limit']}+ joins in {RATE_LIMITS['join_spam']['window']}s",
                    delete_message_days=0
                )
                await send_mod_log(
                    member.guild,
                    "Join Spam Detection",
                    bot.user,
                    member.mention,
                    f"User banned for join spamming. {RATE_LIMITS['join_spam']['limit']}+ joins in {RATE_LIMITS['join_spam']['window']}s.",
                    color=0xFF0000
                )
                logger.warning(f"Join spam detected: {member} banned from {member.guild.name}")
            except discord.Forbidden:
                logger.error(f"Missing permissions to ban {member} from {member.guild.name}")
            except discord.HTTPException as e:
                logger.error(f"Failed to ban {member}: {e}")
            
    except Exception as e:
        logger.error(f"Error in on_member_join: {e}")

@bot.event
async def on_member_remove(member: discord.Member):
    """Track member leaves."""
    try:
        leave_history.append(datetime.datetime.now(datetime.timezone.utc))
    except Exception as e:
        logger.error(f"Error in on_member_remove: {e}")

# --- ANTI-LEND ADMIN EVENTS ---

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Detect unauthorized admin grants."""
    try:
        before_admin = any(role.permissions.administrator for role in before.roles)
        after_admin = any(role.permissions.administrator for role in after.roles)
        
        if before_admin or not after_admin:
            return
        
        guild = after.guild
        actor = await get_audit_log_actor(guild, discord.AuditLogAction.member_role_update, after.id)
        
        if not actor or actor.id == bot.user.id or await is_whitelisted(actor, guild):
            return
        
        admin_roles_added = [
            role for role in after.roles 
            if role.permissions.administrator and role not in before.roles
        ]
        
        if admin_roles_added:
            await after.remove_roles(*admin_roles_added, reason="Security: Anti-Lend Admin")
            
            try:
                await guild.ban(
                    actor, 
                    reason="Security: Anti-Lend Admin (Unauthorized Admin Assignment)",
                    delete_message_days=1
                )
            except discord.Forbidden:
                logger.error(f"Missing permissions to ban {actor} from {guild.name}")
            
            await send_mod_log(
                guild,
                "Anti-Lend Admin (Role Assigned)",
                actor,
                after.mention,
                f"User attempted to assign admin role(s): {', '.join(r.name for r in admin_roles_added)}",
                color=0xFF0000
            )
            logger.warning(f"Anti-Lend Admin triggered: {actor} banned from {guild.name}")
            
    except discord.Forbidden:
        logger.error(f"Missing permissions in guild update")
    except Exception as e:
        logger.error(f"Error in on_member_update: {e}")

@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    """Detect unauthorized admin role edits."""
    try:
        if before.permissions.administrator or not after.permissions.administrator:
            return
            
        guild = after.guild
        actor = await get_audit_log_actor(guild, discord.AuditLogAction.role_update, after.id)
        
        if not actor or actor.id == bot.user.id or await is_whitelisted(actor, guild):
            return
        
        await after.edit(
            permissions=before.permissions,
            reason="Security: Anti-Lend Admin Revert"
        )
        
        try:
            await guild.ban(
                actor,
                reason="Security: Anti-Lend Admin (Unauthorized Role Edit)",
                delete_message_days=1
            )
        except discord.Forbidden:
            logger.error(f"Missing permissions to ban {actor} from {guild.name}")
        
        await send_mod_log(
            guild,
            "Anti-Lend Admin (Role Edit)",
            actor,
            f"Role: {after.name}",
            f"User attempted to add Administrator to role {after.name}",
            color=0xFF0000
        )
        logger.warning(f"Anti-Lend Admin role edit triggered: {actor} banned from {guild.name}")
        
    except Exception as e:
        logger.error(f"Error in on_guild_role_update: {e}")

# --- AUDIT LOG EVENTS ---

@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    """Monitor audit logs for malicious activity with threshold-based banning."""
    try:
        guild = entry.guild
        actor = entry.user
        
        if not actor or actor.id == bot.user.id or await is_whitelisted(actor, guild):
            return
        
        if entry.action == discord.AuditLogAction.kick:
            if check_rate_limit(actor.id, kick_tracker, RATE_LIMITS['kick']['limit'], RATE_LIMITS['kick']['window']):
                try:
                    await guild.ban(actor, reason="Security: Mass Kick Detection", delete_message_days=1)
                except discord.Forbidden:
                    pass
                await send_mod_log(guild, "Mass Kick Detected", actor, "Multiple Members", "User banned for mass kicking.", color=0xFF0000)
        
        elif entry.action == discord.AuditLogAction.ban:
            if check_rate_limit(actor.id, ban_tracker, RATE_LIMITS['ban']['limit'], RATE_LIMITS['ban']['window']):
                try:
                    await guild.ban(actor, reason="Security: Mass Ban Detection", delete_message_days=1)
                except discord.Forbidden:
                    pass
                await send_mod_log(guild, "Mass Ban Detected", actor, "Multiple Members", "User banned for mass banning.", color=0xFF0000)
        
        elif entry.action == discord.AuditLogAction.role_delete:
            if check_rate_limit(actor.id, role_delete_tracker, RATE_LIMITS['role_delete']['limit'], RATE_LIMITS['role_delete']['window']):
                role_delete_tracker[actor.id].clear()
                try:
                    await guild.ban(actor, reason="Anti-Nuke: Mass Role Deletion", delete_message_days=1)
                except discord.Forbidden:
                    pass
                await send_mod_log(guild, "Anti-Nuke: Mass Role Deletion", actor, "Role", "User banned for mass role deletion.", color=0xFF0000)
        
        elif entry.action == discord.AuditLogAction.channel_delete:
            if check_rate_limit(actor.id, channel_delete_tracker, RATE_LIMITS['channel_delete']['limit'], RATE_LIMITS['channel_delete']['window']):
                channel_delete_tracker[actor.id].clear()
                try:
                    await guild.ban(actor, reason="Anti-Nuke: Mass Channel Deletion", delete_message_days=1)
                except discord.Forbidden:
                    pass
                await send_mod_log(guild, "Anti-Nuke: Mass Channel Deletion", actor, "Channel", "User banned for mass channel deletion.", color=0xFF0000)
        
        elif entry.action == discord.AuditLogAction.webhook_delete:
            if check_rate_limit(actor.id, webhook_delete_tracker, RATE_LIMITS['webhook_delete']['limit'], RATE_LIMITS['webhook_delete']['window']):
                webhook_delete_tracker[actor.id].clear()
                try:
                    await guild.ban(actor, reason="Anti-Nuke: Mass Webhook Deletion", delete_message_days=1)
                except discord.Forbidden:
                    pass
                await send_mod_log(guild, "Anti-Nuke: Mass Webhook Deletion", actor, "Webhook", "User banned for mass webhook deletion.", color=0xFF0000)
        
        elif entry.action == discord.AuditLogAction.emoji_delete:
            if check_rate_limit(actor.id, emoji_delete_tracker, RATE_LIMITS['emoji_delete']['limit'], RATE_LIMITS['emoji_delete']['window']):
                emoji_delete_tracker[actor.id].clear()
                try:
                    await guild.ban(actor, reason="Anti-Nuke: Mass Emoji Deletion", delete_message_days=1)
                except discord.Forbidden:
                    pass
                await send_mod_log(guild, "Anti-Nuke: Mass Emoji Deletion", actor, "Emoji", "User banned for mass emoji deletion.", color=0xFF0000)
        
        elif entry.action == discord.AuditLogAction.bot_add:
            unauthorized_bot = entry.target
            if not unauthorized_bot or not getattr(unauthorized_bot, "bot", False):
                return
            
            if await is_whitelisted(actor, guild):
                return
            
            try:
                await actor.send("You are not authorized to add bots.")
            except discord.HTTPException:
                pass
            
            try:
                await guild.kick(unauthorized_bot, reason="Unauthorized Bot")
                await guild.ban(actor, reason="Unauthorized Bot Added", delete_message_days=1)
            except discord.Forbidden:
                pass
            
            await send_mod_log(guild, "Unauthorized Bot", actor, f"<@{unauthorized_bot.id}>", "Bot inviter banned and bot kicked.", color=0xFF0000)
                    
    except Exception as e:
        logger.error(f"Error in on_audit_log_entry_create: {e}")

# --- MESSAGE EVENT ---

@bot.event
async def on_message(message: discord.Message):
    """Handle messages with spam detection."""
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

# --- THREAD SPAM ---

@bot.event
async def on_thread_create(thread: discord.Thread):
    """Detect and prevent thread spam."""
    try:
        guild = thread.guild
        owner = thread.owner
        
        if not owner or owner.bot or await is_whitelisted(owner, guild):
            return
        
        uid = owner.id
        if check_rate_limit(uid, thread_tracker, RATE_LIMITS['thread']['limit'], RATE_LIMITS['thread']['window']):
            thread_tracker[uid].clear()
            try:
                await asyncio.gather(
                    thread.delete(),
                    owner.timeout(datetime.timedelta(minutes=1), reason="Mass Thread Spam"),
                    thread.parent.send(f"stfu {owner.mention}.")
                )
            except discord.HTTPException:
                pass
    except Exception as e:
        logger.error(f"Error in on_thread_create: {e}")

# --- START BOT ---

if __name__ == "__main__":
    try:
        bot.run(BOT_TOKEN)
    except Exception as e:
        logger.critical(f"Failed to start bot: {e}\n{traceback.format_exc()}")

