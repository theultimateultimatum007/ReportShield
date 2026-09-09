# ReportShield

A Python Discord bot to protect users from being reported and limited. Also contains commands to ban official Discord spyware from your server.

## How it works?

When an user types a detected slur. their message gets deleted and reposted as a webhook.

## Commands
!antispyware - Bans Discord, Community Updates and Clyde from your server.

!protectall on|off - Repost ALL messages in the server as webhooks.

!protect on|off - Enable/disable keyword detection for this server (on by default.

!protect #channel on|off - Repost all messages in a specific channel as webhooks.

Protection settings are saved in `data/protect_state.json` and survive restarts.

## DISCLAIMER
This bot is for educational purposes only! Deploy at your own risk!