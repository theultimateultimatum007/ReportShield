import asyncio
import io
import json
import os
import re
import unicodedata
from datetime import datetime, timezone

import aiohttp
import discord
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

# Characters that visually resemble Latin letters but come from other
# scripts (Cyrillic, Greek, etc.) -- these are commonly used to bypass
# keyword filters. Map them to their ASCII lookalike.
CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "с": "c", "е": "e", "м": "m", "н": "h", "о": "o",
    "р": "p", "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j",
    "ѕ": "s", "қ": "q", "ԁ": "d", "ԥ": "q", "ң": "n", "р": "p", "ғ": "f",
    "к": "k", "н": "h", "п": "n", "у": "y", "ф": "f", "ы": "y", "э": "e",
    "ю": "io", "я": "ya", "з": "3", "ч": "4", "д": "d", "л": "l", "р": "p",
    # Greek
    "α": "a", "β": "b", "γ": "g", "δ": "d", "ε": "e", "ζ": "z", "η": "n",
    "θ": "th", "ι": "i", "κ": "k", "λ": "l", "μ": "m", "ν": "v", "ξ": "x",
    "ο": "o", "π": "p", "ρ": "p", "σ": "s", "τ": "t", "υ": "u", "φ": "f",
    "χ": "x", "ψ": "ps", "ω": "o",
    # Other lookalikes
    "ƒ": "f", "ⅼ": "l", "ⅿ": "m", "∣": "l", "ǀ": "l", "∧": "v", "∪": "u",
    "⊂": "c", "ѕ": "s", "о": "o", "а": "a", "е": "e", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j",
}

# Leet-speak / symbol substitutions (also catches "l33tsp3ak" evasion).
LEET = {
    "@": "a", "4": "a", "8": "b", "(": "c", "¢": "c", "{": "c", "[": "c",
    "<": "c", "3": "e", "€": "e", "6": "g", "9": "g", "1": "i", "|": "i",
    "!": "i", "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "2": "z",
    "8": "b", "vv": "w", "#": "h", "91": "g", "|3": "b", "|>": "p",
    "/\\": "a", "><": "x", "?": "q", "&": "g", "²": "2",
}


def normalize(text: str) -> str:
    """Aggressively normalize text so filter-bypass tricks don't work.

    - lowercase
    - strip accents / combining marks (NFKD)
    - strip zero-width and control characters
    - map confusable non-Latin letters to their ASCII lookalike
    - map leet-speak symbols / digits to letters
    - drop remaining punctuation
    - collapse all whitespace so spaced-out evasion ("n i g g e r") matches
    - collapse 3+ repeated chars to 2 so "niiiiiger" still matches "nigger"
    """
    # Fold accents and split combining marks from base letters.
    text = unicodedata.normalize("NFKD", text)
    # Drop combining marks (Mn) and all control/format (zero-width) chars.
    text = "".join(
        ch for ch in text
        if unicodedata.category(ch) != "Mn"
        and not (unicodedata.category(ch).startswith("C") and ch not in " \t\n")
    )
    text = text.lower()

    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        # Try two-char leet sequences first (e.g. "|3", "/>", "vv", "><").
        two = text[i:i + 2]
        if two in LEET:
            out.append(LEET[two])
            i += 2
            continue
        if ch in CONFUSABLES:
            out.append(CONFUSABLES[ch])
        elif ch in LEET:
            out.append(LEET[ch])
        elif ch.isascii() and ch.isalpha():
            out.append(ch)
        elif ch.isspace():
            out.append(" ")  # collapse all whitespace to a single space
        # else: drop other punctuation/symbols (they're already handled by LEET
        # if they're common bypass chars, otherwise they're just noise).
        i += 1

    result = "".join(out)
    # Collapse runs of whitespace.
    result = re.sub(r"\s+", " ", result).strip()
    # Collapse 3+ identical chars to 2 (e.g. "niiiiiger" -> "niiger").
    # We keep 2 so genuine doubled letters ("gg" in "nigger") survive.
    result = re.sub(r"(.)\1{2,}", r"\1\1", result)
    return result

TRIGGER_PATTERNS = [
    re.compile(pattern)
    for pattern in os.getenv("TRIGGER_PATTERNS", "secret").split("||")
    if pattern.strip()
]
BOT_TOKEN = os.getenv("BOT_TOKEN")

# Cap on total attachment bytes forwarded in a single repost (Discord's
# webhook limit is 10 MiB per request; keep a safety margin). Oversized
# attachments are skipped and mentioned in the reposted text.
MAX_REPOST_TOTAL_BYTES = 8 * 1024 * 1024

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents)

# Guild-scoped protection state (persisted between restarts):
#   PROTECT_ALL_GUILDS        -> set of guild IDs where !protectall is enabled
#   PROTECTED_CHANNELS        -> guild ID -> set of individually-protected channel IDs
#   KEYWORD_DETECTION_OFF     -> set of guild IDs where keyword detection is disabled
#                                (detection is ON by default for every guild)
PROTECT_ALL_GUILDS: set[int] = set()
PROTECTED_CHANNELS: dict[int, set[int]] = {}
KEYWORD_DETECTION_OFF: set[int] = set()

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
PROTECT_STATE_FILE = os.path.join(DATA_DIR, "protect_state.json")


def _load_protect_state():
    """Load persisted protection state from disk into the containers above."""
    try:
        with open(PROTECT_STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        PROTECT_ALL_GUILDS.clear()
        PROTECTED_CHANNELS.clear()
        KEYWORD_DETECTION_OFF.clear()
        PROTECT_ALL_GUILDS.update(int(g) for g in data.get("protect_all", []))
        for gid, channels in data.get("protected_channels", {}).items():
            PROTECTED_CHANNELS[int(gid)] = {int(c) for c in channels}
        KEYWORD_DETECTION_OFF.update(int(g) for g in data.get("keyword_detection_off", []))
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Warning: could not load protect state: {e}")


def _save_protect_state():
    """Persist the current protection state to disk."""
    os.makedirs(DATA_DIR, exist_ok=True)
    data = {
        "protect_all": sorted(PROTECT_ALL_GUILDS),
        "protected_channels": {
            gid: sorted(channels) for gid, channels in PROTECTED_CHANNELS.items()
        },
        "keyword_detection_off": sorted(KEYWORD_DETECTION_OFF),
    }
    with open(PROTECT_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


_load_protect_state()

ARCHIVES_DIR = os.path.join(DATA_DIR, "archives")

# Supported "what to archive" options for !archive create.
ARCHIVE_OPTIONS = ["all", "messages", "emojis", "stickers", "roles", "channels", "members"]

# Hard cap per channel so archiving a huge server can't run forever.
MAX_MESSAGES_PER_CHANNEL = 100_000


def _iter_guild_channels(guild: discord.Guild):
    """All channels in a guild, including active threads."""
    for channel in guild.channels:
        yield channel
    for thread in guild.threads:
        yield thread


def _serialize_message(msg: discord.Message) -> dict | None:
    """JSON-serializable representation of a message (None = skip)."""
    if msg.type not in (discord.MessageType.default, discord.MessageType.reply):
        return None
    return {
        "id": msg.id,
        "channel_id": msg.channel.id,
        "author_id": msg.author.id,
        "author_name": str(msg.author),
        "author_display": msg.author.display_name,
        "webhook_id": msg.webhook_id,
        "created_at": msg.created_at.isoformat(),
        "edited_at": msg.edited_at.isoformat() if msg.edited_at else None,
        "content": msg.content,
        "attachments": [
            {
                "id": a.id,
                "filename": a.filename,
                "size": a.size,
                "url": a.url,
                "content_type": a.content_type,
            }
            for a in msg.attachments
        ],
        "sticker_items": [
            {"id": s.id, "name": s.name, "format": str(s.format)}
            for s in msg.stickers
        ],
        "reply_to": msg.reference.message_id if msg.reference else None,
        "pinned": msg.pinned,
    }


def _serialize_emoji(e: discord.Emoji) -> dict:
    return {
        "id": e.id,
        "name": e.name,
        "animated": e.animated,
        "available": e.available,
        "managed": e.managed,
        "roles": [r.id for r in e.roles],
        "url": str(e.url),
        "created_at": e.created_at.isoformat() if e.created_at else None,
    }


def _serialize_sticker(s: discord.GuildSticker) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "tags": s.emoji,
        "available": s.available,
        "format": str(s.format),
        "url": str(s.url),
    }


def _serialize_role(r: discord.Role) -> dict:
    return {
        "id": r.id,
        "name": r.name,
        "color": r.color.value,
        "hoist": r.hoist,
        "mentionable": r.mentionable,
        "position": r.position,
        "permissions": r.permissions.value,
        "default": r.is_default(),
        "bot_id": r.tags.bot_id if r.is_bot_managed() else None,
    }


def _serialize_channel(ch) -> dict | None:
    """JSON-serializable representation of a channel (None = skip)."""
    if isinstance(ch, discord.CategoryChannel):
        return {
            "id": ch.id, "type": "category", "name": ch.name,
            "position": ch.position, "overwrites": _serialize_overwrites(ch),
        }
    if isinstance(ch, discord.TextChannel):
        data = {
            "id": ch.id, "type": "text", "name": ch.name, "topic": ch.topic,
            "position": ch.position, "nsfw": ch.nsfw, "slowmode": ch.slowmode_delay,
            "category_id": ch.category_id, "overwrites": _serialize_overwrites(ch),
        }
    elif isinstance(ch, discord.VoiceChannel):
        data = {
            "id": ch.id, "type": "voice", "name": ch.name, "position": ch.position,
            "nsfw": ch.nsfw, "bitrate": ch.bitrate, "user_limit": ch.user_limit,
            "category_id": ch.category_id, "overwrites": _serialize_overwrites(ch),
        }
    elif isinstance(ch, discord.ForumChannel):
        data = {
            "id": ch.id, "type": "forum", "name": ch.name, "topic": ch.topic,
            "position": ch.position, "nsfw": ch.nsfw, "category_id": ch.category_id,
            "overwrites": _serialize_overwrites(ch),
        }
    elif isinstance(ch, discord.Thread):
        data = {
            "id": ch.id, "type": "thread", "name": ch.name,
            "parent_id": ch.parent_id, "archived": ch.archived,
            "locked": ch.locked, "message_count": ch.message_count,
        }
    elif isinstance(ch, discord.StageChannel):
        data = {
            "id": ch.id, "type": "stage", "name": ch.name, "position": ch.position,
            "bitrate": ch.bitrate, "user_limit": ch.user_limit,
            "category_id": ch.category_id, "overwrites": _serialize_overwrites(ch),
        }
    else:
        return None
    return data


def _serialize_overwrites(channel) -> list[dict]:
    overwrites = []
    for target, perms in channel.overwrites.items():
        allow, deny = perms.pair()
        overwrite = {
            "target_id": target.id,
            "target_type": "role" if isinstance(target, discord.Role) else "member",
            "allow": allow.value,
            "deny": deny.value,
        }
        overwrites.append(overwrite)
    return overwrites


def _serialize_member_list(guild: discord.Guild) -> dict:
    """All members with nicknames, usernames, roles and bot status."""
    bots = 0
    members = []
    for m in guild.members:
        if m.bot:
            bots += 1
        members.append({
            "id": m.id,
            "username": m.name,
            "display_name": m.display_name,
            "nickname": m.nick,
            "bot": m.bot,
            "pending": m.pending,
            "roles": [r.id for r in m.roles if not r.is_default()],
            "top_role": {"id": m.top_role.id, "name": m.top_role.name},
            "joined_at": m.joined_at.isoformat() if m.joined_at else None,
            "avatar_url": m.display_avatar.url,
        })
    members.sort(key=lambda m: (m["bot"], m["display_name"].lower()))
    return {
        "total": len(members),
        "bots": bots,
        "humans": len(members) - bots,
        "members": members,
    }


def _member_list_text(archive: dict) -> str:
    """Plain-text member list from an archive dict."""
    meta = archive.get("members", {})
    lines = [
        f"Member list for guild {archive.get('guild', {}).get('name', '?')} "
        f"({meta.get('total', 0)} members, {meta.get('bots', 0)} bots)",
        "=" * 60,
    ]
    for m in meta.get("members", []):
        parts = [f"{m['username']}"]
        if m.get("nickname"):
            parts.append(f"nick: {m['nickname']}")
        parts.append("(bot)" if m.get("bot") else "(human)")
        lines.append(" | ".join(parts))
    return "\n".join(lines)


def _archive_filename(guild: discord.Guild) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"archive-{guild.id}-{stamp}.json"


async def _archive_messages(channel) -> list[dict]:
    """Fetch message history for a channel, newest first (silently skips
    channels we can't read)."""
    messages: list[dict] = []
    try:
        async for msg in channel.history(limit=MAX_MESSAGES_PER_CHANNEL):
            data = _serialize_message(msg)
            if data:
                messages.append(data)
    except (discord.Forbidden, discord.HTTPException) as e:
        print(f"Archive: could not read #{channel}: {e}")
    return messages


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")


async def get_or_create_webhook(channel) -> discord.Webhook:
    """Find an existing webhook owned by the bot, or create one.

    Works for text, voice, and forum channels (all support webhooks).
    """
    webhooks = await channel.webhooks()
    for wh in webhooks:
        if wh.user and wh.user.id == bot.user.id:
            return wh
    return await channel.create_webhook(name="Reposter")


def message_in_protected_channel(message: discord.Message) -> bool:
    """True if the message's channel is protected by !protectall or !protect."""
    if message.guild.id in PROTECT_ALL_GUILDS:
        return True
    protected = PROTECTED_CHANNELS.get(message.guild.id, set())
    if message.channel.id in protected:
        return True
    # Threads/forums: protection applies if the parent channel is protected.
    parent_id = getattr(message.channel, "parent_id", None)
    return parent_id in protected


@bot.event
async def on_message(message: discord.Message):
    # Ignore bot messages, webhook messages (prevents infinite repost loops
    # in protected channels), and DMs
    if message.author.bot or message.webhook_id or not message.guild:
        return

    normalized = normalize(message.content)
    should_repost = message_in_protected_channel(message)
    triggered_patterns = (
        [] if message.guild.id in KEYWORD_DETECTION_OFF
        else [
            pattern.pattern for pattern in TRIGGER_PATTERNS if pattern.search(normalized)
        ]
    )

    if should_repost or triggered_patterns:
        try:
            # Threads have no webhooks; use the parent channel's webhook
            # and target the thread via the `thread` kwarg.
            webhook_channel = message.channel
            if isinstance(message.channel, discord.Thread):
                parent = message.channel.parent
                if parent is None:
                    raise RuntimeError("thread has no accessible parent channel")
                webhook_channel = parent
            webhook = await get_or_create_webhook(webhook_channel)

            # Fetch the member so we can use guild display name/avatar
            member = message.guild.get_member(message.author.id)
            display_name = member.display_name if member else message.author.display_name
            avatar_url = message.author.display_avatar.url

            files: list[discord.File] = []
            attachments_too_big: list[str] = []
            total_size = 0
            for attachment in message.attachments:
                try:
                    if total_size + attachment.size > MAX_REPOST_TOTAL_BYTES:
                        attachments_too_big.append(attachment.filename)
                        continue
                    file = await attachment.to_file()
                    total_size += attachment.size
                    files.append(file)
                except Exception:
                    attachments_too_big.append(attachment.filename)

            content = message.content
            if attachments_too_big:
                skipped = ", ".join(attachments_too_big)
                content += f"\n[attachment(s) skipped: too large: {skipped}]" if content else f"[attachment(s) skipped: too large: {skipped}]"

            # In threads, webhook messages must be sent to the parent channel
            # with a thread reference, not directly to the thread.
            await webhook.send(
                content=content,
                files=files,
                thread=message.channel if isinstance(message.channel, discord.Thread) else discord.utils.MISSING,
                username=display_name,
                avatar_url=avatar_url,
                allowed_mentions=discord.AllowedMentions.none(),
            )

            await message.delete()
            if triggered_patterns:
                print(
                    f"Reposted message from {message.author} "
                    f"in #{message.channel} (patterns: {triggered_patterns})"
                )
        except discord.Forbidden:
            print(f"Missing permissions in #{message.channel}")
        except Exception as e:
            print(f"Error: {e}")

    # Process commands too
    await bot.process_commands(message)


ANTISPYWARE_TARGETS = [
    643945264868098049, # Discord
    669627189624307712, # Community Updates
    1081004946872352958, # Clyde
]


@bot.command(name="antispyware")
@commands.has_permissions(administrator=True)
@commands.bot_has_permissions(ban_members=True)
async def antispyware(ctx: commands.Context):
    """Ban the 3 hardcoded spyware user IDs."""
    banned = 0
    failed = []
    for uid in ANTISPYWARE_TARGETS:
        try:
            await ctx.guild.ban(
                discord.Object(id=uid),
                reason="antispyware: hardcoded target",
            )
            banned += 1
        except discord.NotFound:
            failed.append((uid, "not found"))
        except discord.Forbidden:
            failed.append((uid, "missing permissions"))
        except Exception as e:
            failed.append((uid, str(e)))

    msg = f"Banned {banned}/{len(ANTISPYWARE_TARGETS)} spyware targets."
    if failed:
        msg += "\nFailures: " + ", ".join(f"{uid} ({why})" for uid, why in failed)
    await ctx.send(msg)


@antispyware.error
async def antispyware_error(ctx: commands.Context, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You lack the Administrator permission.")
    elif isinstance(error, commands.BotMissingPermissions):
        await ctx.send("I lack the Ban Members permission.")
    else:
        raise error


def _validate_flag(flag: str) -> bool | None:
    """Return True for on, False for off, None for invalid input."""
    normalized = flag.strip().lower()
    if normalized in ("on", "true", "yes", "1", "enable", "enabled"):
        return True
    if normalized in ("off", "false", "no", "0", "disable", "disabled"):
        return False
    return None


@bot.command(name="protectall")
@commands.has_permissions(administrator=True)
@commands.bot_has_permissions(manage_webhooks=True, manage_messages=True)
async def protectall(ctx: commands.Context, flag: str):
    """Enable/disable reposting ALL messages via webhook (!protectall on/off)."""
    value = _validate_flag(flag)
    if value is None:
        await ctx.send("Usage: `!protectall on|off`")
        return

    if value:
        PROTECT_ALL_GUILDS.add(ctx.guild.id)
        await ctx.send(
            "Protecting ALL channels. "
            "Every message will be deleted and reposted via webhook."
        )
    else:
        PROTECT_ALL_GUILDS.discard(ctx.guild.id)
        await ctx.send("Stopped protecting all channels.")
    _save_protect_state()


@protectall.error
async def protectall_error(ctx: commands.Context, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You lack the Administrator permission.")
    elif isinstance(error, commands.BotMissingPermissions):
        await ctx.send("I lack the Manage Webhooks and/or Manage Messages permission.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Usage: `!protectall on|off`")
    else:
        raise error


@bot.command(name="protect")
@commands.has_permissions(administrator=True)
@commands.bot_has_permissions(manage_webhooks=True, manage_messages=True)
async def protect(ctx: commands.Context, channel: str, flag: str | None = None):
    """!protect on|off  -> toggle keyword detection for this server.
    !protect #channel on|off -> repost all messages in a specific channel.
    """
    value = _validate_flag(channel)
    # Form 1: "!protect on/off" (channel argument is actually the flag)
    if value is not None:
        if value:
            KEYWORD_DETECTION_OFF.discard(ctx.guild.id)
            await ctx.send("Keyword detection enabled.")
        else:
            KEYWORD_DETECTION_OFF.add(ctx.guild.id)
            await ctx.send("Keyword detection disabled.")
        _save_protect_state()
        return

    if flag is None:
        await ctx.send("Usage: `!protect on|off` or `!protect #channel on|off`")
        return

    # Form 2: "!protect #channel on/off"
    converter = commands.TextChannelConverter()
    target = await converter.convert(ctx, channel)
    if target.guild.id != ctx.guild.id:
        await ctx.send("That channel is not in this server.")
        return

    value = _validate_flag(flag)
    if value is None:
        await ctx.send(f"Usage: `!protect #{target.name} on|off`")
        return

    if value:
        PROTECTED_CHANNELS.setdefault(ctx.guild.id, set()).add(target.id)
        await ctx.send(f"Now protecting {target.mention}. All messages there will be reposted.")
    else:
        protected = PROTECTED_CHANNELS.get(ctx.guild.id, set())
        if target.id in protected:
            PROTECTED_CHANNELS[ctx.guild.id].discard(target.id)
            await ctx.send(f"Stopped protecting {target.mention}.")
        else:
            await ctx.send(f"{target.mention} was not protected.")
    _save_protect_state()


@protect.error
async def protect_error(ctx: commands.Context, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You lack the Administrator permission.")
    elif isinstance(error, commands.BotMissingPermissions):
        await ctx.send("I lack the Manage Webhooks and/or Manage Messages permission.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("Usage: `!protect on|off` or `!protect #channel on|off`")
    elif isinstance(error, (commands.ChannelNotFound, commands.BadArgument)):
        await ctx.send("Channel not found. Usage: `!protect on|off` or `!protect #channel on|off`")
    else:
        raise error


@bot.group(name="archive", invoke_without_command=True)
@commands.has_permissions(administrator=True)
async def archive(ctx: commands.Context):
    """Server archive tools: !archive create / !archive load."""
    await ctx.send(
        "Usage:\n"
        "- `!archive create [option...]` (default: all; options: "
        + ", ".join(ARCHIVE_OPTIONS) + "; `all` = everything)\n"
        "- `!archive load` (attach a .json archive file to this command)"
    )


@archive.command(name="create")
@commands.has_permissions(administrator=True)
@commands.bot_has_permissions(read_message_history=True, attach_files=True)
async def archive_create(ctx: commands.Context, *options: str):
    """Archive this server into a .json file (sent as an attachment)."""
    if options:
        wanted = {opt.lower() for opt in options}
        unknown = wanted - set(ARCHIVE_OPTIONS)
        if unknown:
            await ctx.send(
                "Unknown option(s): " + ", ".join(sorted(unknown))
                + "\nAvailable options: " + ", ".join(ARCHIVE_OPTIONS)
            )
            return
        if "all" in wanted:
            wanted = set(ARCHIVE_OPTIONS) - {"all"}
    else:
        wanted = set(ARCHIVE_OPTIONS) - {"all"}

    guild = ctx.guild
    status = await ctx.send(f"Archiving {guild.name}...")

    archive_data: dict = {
        "format": "reportshield-archive",
        "version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": ctx.author.id,
        "guild": {
            "id": guild.id,
            "name": guild.name,
            "description": guild.description,
            "vanity_url": str(guild.vanity_url) if guild.vanity_url else None,
            "premium_tier": guild.premium_tier,
            "owner_id": guild.owner_id,
            "created_at": guild.created_at.isoformat() if guild.created_at else None,
            "features": guild.features,
            "member_count": guild.member_count,
        },
    }

    try:
        if "roles" in wanted:
            archive_data["roles"] = [
                _serialize_role(r) for r in sorted(guild.roles, key=lambda r: r.position)
            ]

        if "channels" in wanted:
            archive_data["channels"] = [
                d
                for d in (_serialize_channel(c) for c in guild.channels)
                if d is not None
            ]

        if "members" in wanted:
            async with ctx.typing():
                try:
                    await guild.chunk()
                except Exception:
                    pass
            archive_data["members"] = _serialize_member_list(guild)

        if "emojis" in wanted or "stickers" in wanted:
            session: aiohttp.ClientSession | None = None
            try:
                if "emojis" in wanted:
                    if session is None:
                        session = aiohttp.ClientSession()
                    archive_data["emojis"] = []
                    for emoji in guild.emojis:
                        data = _serialize_emoji(emoji)
                        try:
                            async with session.get(str(emoji.url)) as resp:
                                if resp.status == 200:
                                    raw = await resp.read()
                                    import base64
                                    mime = "image/gif" if emoji.animated else "image/png"
                                    data["data"] = f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"
                        except Exception:
                            pass
                        archive_data["emojis"].append(data)

                if "stickers" in wanted:
                    archive_data["stickers"] = [
                        _serialize_sticker(s) for s in guild.stickers
                    ]
            finally:
                if session is not None:
                    await session.close()

        if "messages" in wanted:
            archive_data["messages"] = {}
            total_msgs = 0
            for channel in _iter_guild_channels(guild):
                if not isinstance(channel, (discord.TextChannel, discord.Thread)):
                    continue
                perms = channel.permissions_for(guild.me)
                if not perms.read_messages or not perms.read_message_history:
                    continue
                msgs = await _archive_messages(channel)
                if msgs:
                    archive_data["messages"][str(channel.id)] = msgs
                    total_msgs += len(msgs)
                await asyncio.sleep(0.5)

            archive_data["message_count"] = total_msgs

        # Save to data/archives/ and also send the file to the user.
        os.makedirs(ARCHIVES_DIR, exist_ok=True)
        filename = _archive_filename(guild)
        local_path = os.path.join(ARCHIVES_DIR, filename)
        payload = json.dumps(archive_data, ensure_ascii=False, indent=1)
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(payload)

        file = discord.File(
            io.BytesIO(payload.encode("utf-8")),
            filename=filename,
        )
        await status.delete()
        await ctx.send(
            f"Archive complete: {archive_data.get('message_count', 0)} messages, "
            f"{len(guild.emojis)} emojis, {len(guild.stickers)} stickers. "
            f"File: `{filename}`",
            file=file,
        )
    except Exception as e:
        await status.edit(content=f"Archive failed: {e}")


@archive_create.error
async def archive_create_error(ctx: commands.Context, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You lack the Administrator permission.")
    elif isinstance(error, commands.BotMissingPermissions):
        await ctx.send("I lack the Read Message History and/or Attach Files permission.")
    else:
        raise error


@archive.command(name="load")
@commands.has_permissions(administrator=True)
async def archive_load(ctx: commands.Context):
    """Load a server archive from an attached .json file (reports contents)."""
    if not ctx.message.attachments:
        await ctx.send("Attach a `.json` archive file to this command: `!archive load`")
        return
    attachment = ctx.message.attachments[0]
    if not attachment.filename.lower().endswith(".json"):
        await ctx.send("That file is not a `.json` archive.")
        return

    try:
        raw = await attachment.read()
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        await ctx.send(f"Could not parse archive: {e}")
        return

    if data.get("format") != "reportshield-archive":
        await ctx.send("That file is not a ReportShield archive (missing format marker).")
        return

    guild_info = data.get("guild", {})
    lines = [
        f"Archive for guild **{guild_info.get('name', '?')}** "
        f"(created {data.get('created_at', '?')})",
        f"- Messages: {data.get('message_count', 0)} across "
        f"{len(data.get('messages', {}))} channels",
        f"- Emojis: {len(data.get('emojis', []))}, Stickers: {len(data.get('stickers', []))}",
        f"- Roles: {len(data.get('roles', []))}, Channels: {len(data.get('channels', []))}",
        f"- Members: {data.get('members', {}).get('total', 0)} "
        f"({data.get('members', {}).get('bots', 0)} bots)",
    ]
    await ctx.send("\n".join(lines))

    members_data = data.get("members")
    if members_data and members_data.get("members"):
        text = _member_list_text(data)
        await ctx.send(
            "Member list preview:",
            file=discord.File(
                io.BytesIO(text.encode("utf-8")),
                filename=f"members-{guild_info.get('id', 'unknown')}.txt",
            ),
        )
    os.makedirs(ARCHIVES_DIR, exist_ok=True)
    filename = _archive_filename(guild_info.get("id", ctx.guild.id))
    with open(os.path.join(ARCHIVES_DIR, filename), "wb") as f:
        f.write(raw)
    await ctx.send(f"Saved archive as `{filename}` in data/archives.")


@archive_load.error
async def archive_load_error(ctx: commands.Context, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("You lack the Administrator permission.")
    else:
        raise error


bot.run(BOT_TOKEN)