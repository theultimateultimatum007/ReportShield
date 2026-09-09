import discord
from discord.ext import commands
from dotenv import load_dotenv
import json
import os
import re
import unicodedata

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


bot.run(BOT_TOKEN)