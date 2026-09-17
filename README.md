# ReportShield

A Python Discord bot to protect users from being reported and limited. Also contains commands to ban official Discord spyware from your server.

## How it works?

When an user types a detected slur. their message gets deleted and reposted as a webhook.

## Commands
!antispyware - Bans Discord, Community Updates and Clyde from your server.

!protectall on|off - Repost ALL messages in the server as webhooks.

!protect on|off - Enable/disable keyword detection for this server (on by default.

!protect #channel on|off - Repost all messages in a specific channel as webhooks.

!archive create [option...] - Archive the whole server into a .json file. With no
options everything is archived; pass one or more of `messages`, `emojis`,
`stickers`, `roles`, `channels`, `members` to choose what to include. Emojis are
embedded as base64 data. A plain-text member list (`username`, `nickname`,
bot/human) is included when `members` is selected. The file is also saved in
`data/archives/`. !archive create all to archive everything.

!archive load - Attach the archived `.json` to this command to import it. The bot
reports the archive's contents and saves it in `data/archives/`.

Protection settings are saved in `data/protect_state.json` and survive restarts.

## DISCLAIMER
This bot is for educational purposes only! Deploy at your own risk!