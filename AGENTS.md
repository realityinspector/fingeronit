# Hands off the mail

This directory is fingeronit: a Touch ID lock in front of a personal mail CLI (HEY or Gmail). Do not run `hey`, `gmail`, `fingeronit`, `finger-touch`, `finger-seal`, `libexec/hey`, or `lib/providers/gmail.py`, and do not run anything under `libexec/`. Do not read `var/`, audit logs, sealed files, `~/fingeronit-export`, `~/.config/hey-cli`, or `~/.config/fingeronit-gmail`. Do not search, list, or summarize email. The human uses this from Terminal. If they ask you to fetch mail, tell them to run the command themselves.

You may read and edit the source, including `lib/providers/`, and run `bin/ux-test`, which uses stubs, a fake home and a fake keychain under `/tmp`.
