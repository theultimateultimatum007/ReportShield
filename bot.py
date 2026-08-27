import discord
from discord.ext import commands
from dotenv import load_dotenv
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

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")


async def get_or_create_webhook(channel: discord.TextChannel) -> discord.Webhook:
    """Find an existing webhook owned by the bot, or create one."""
    webhooks = await channel.webhooks()
    for wh in webhooks:
        if wh.user and wh.user.id == bot.user.id:
            return wh
    return await channel.create_webhook(name="Reposter")


@bot.event
async def on_message(message: discord.Message):
    # Ignore bot messages and DMs
    if message.author.bot or not message.guild:
        return

    normalized = normalize(message.content)
    if any(pattern.search(normalized) for pattern in TRIGGER_PATTERNS):
        try:
            webhook = await get_or_create_webhook(message.channel)

            # Fetch the member so we can use guild display name/avatar
            member = message.guild.get_member(message.author.id)
            display_name = member.display_name if member else message.author.display_name
            avatar_url = message.author.display_avatar.url

            await webhook.send(
                content=message.content,
                username=display_name,
                avatar_url=avatar_url,
                allowed_mentions=discord.AllowedMentions.none(),
            )

            await message.delete()
            print(
                f"Reposted message from {message.author} "
                f"in #{message.channel} (patterns: {[p.pattern for p in TRIGGER_PATTERNS]})"
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
@commands.has_permissions(ban_members=True)
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
        await ctx.send("You lack permission to ban members.")
    elif isinstance(error, commands.BotMissingPermissions):
        await ctx.send("I lack the Ban Members permission.")
    else:
        raise error


bot.run(BOT_TOKEN)