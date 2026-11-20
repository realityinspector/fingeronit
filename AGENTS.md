# Agents and the mail

This directory is fingeronit: a Touch ID lock in front of a personal mail CLI (HEY or Gmail).

## Using it

- **Get mail only through `bin/fingeronit ask`.** Each request names a purpose and up to 3 narrow lookups: one full address, a few topic words, a time window, a few threads. Your human approves it at `fingeronit desk` with Touch ID and sees the results before you do. Run `bin/fingeronit ask --help` for the rules, and `--check` to test a request without asking.
- **Ask for what the task needs, nothing more.** A refusal, a "no", or kept results are answers. Do not retry with a broader or reworded request to get around them.
- **Exit code 75 means no desk is open.** Tell your human to run `./fingeronit desk` in their own Terminal.
- **Setup you may run:** `bin/build`, `bin/fingeronit doctor`, `status`, `version`, `help`. Your human signs in (`./fingeronit`) and runs `sudo bin/install-keeper` themselves.

## Never

- **Commands:** do not run any other `fingeronit` command, or `hey`, `gmail`, `finger-touch`, `finger-seal`, `libexec/hey`, `lib/providers/gmail.py`, or anything under `libexec/`.
- **Files:** do not read `var/`, the desk queue under `/tmp/fingeronit-desk.*`, audit logs, sealed files, `~/fingeronit-export`, `~/.config/hey-cli`, or `~/.config/fingeronit-gmail`.
- **Approval:** do not approve anything on your human's behalf, type into their Terminal, or raise Touch ID prompts.
- **Code:** do not edit fingeronit's files in a checkout your human uses for real mail.

## Developing it

Work in a separate clone. You may read and edit the source, including `lib/providers/` and `lib/job.py`, and run `bin/ux-test`. It uses stubs, a fake home and a fake keychain under `/tmp`, and ends with `ux-test ok`.
