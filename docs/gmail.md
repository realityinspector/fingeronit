# Gmail provider

`lib/providers/gmail.py` is a read-only Gmail client (Python 3, standard
library only). Google does not let apps share one login, so you create your
own small OAuth client. It takes about five minutes and is free.

## 1. Create your own OAuth client

1. Go to <https://console.cloud.google.com/> and create a project (any name).
2. APIs & Services > Library > search "Gmail API" > Enable.
3. APIs & Services > OAuth consent screen: choose External, fill in the
   app name and your own address, and leave Publishing status as **Testing**.
4. On the same screen, under Test users, add your own Gmail address.
5. APIs & Services > Credentials > Create credentials > OAuth client ID >
   Application type **Desktop app**. Click Download JSON.

In Testing mode Google expires the login after 7 days; just sign in again.

## 2. Sign in

    fingeronit login --provider gmail

You will be asked for the downloaded client JSON file. It is copied to
`$XDG_CONFIG_HOME/fingeronit-gmail/client.json` (mode 600). A browser opens
for Google's consent screen (you may see an "unverified app" warning; that is
your own app, choose Advanced > continue). The login completes on a local
`127.0.0.1` page and the tokens are stored in `credentials.json` in the same
folder (mode 600). Nothing else is written to disk.

## What the scope means

The only scope requested is `gmail.readonly`. It lets the client read
messages, threads, attachments and drafts. It cannot send, edit, label,
archive or delete anything. Message text is printed to stdout only and is
never cached.

## Revoke

Open <https://myaccount.google.com/permissions>, pick your app, and choose
Delete all connections. You can also delete the
`fingeronit-gmail` folder to forget the local login.
