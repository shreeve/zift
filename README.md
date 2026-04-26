# zift
Zero Insanity File Transfer

Zift is a single-binary SFTP-compatible server with virtual users, per-user
roots, explicit file policy, and one reloadable config file. No web UI. No
database. No OS users. No chroot games.

## Build

Requires Zig 0.16.0 and libssh.

```sh
brew install libssh
zig build
```

## Run

Generate a host key and a password hash:

```sh
ssh-keygen -t ed25519 -f /tmp/zift_host_ed25519 -N ""
printf 'secret\n' | zig build run -- hash-password
```

Create roots and edit `example.zift`, then start the server:

```sh
mkdir -p /tmp/zift/ally/pending /tmp/zift/ally/archive
zig build run -- serve example.zift
```

Connect with any stock SFTP client:

```sh
sftp -P 2222 ally@127.0.0.1
```

## Config

Zift reloads the config for new sessions when the config file mtime changes.
Adding a user should be copy/paste/edit/save, then ask the user to sign in.

```text
server
  listen 127.0.0.1:2222
  host-key /tmp/zift_host_ed25519
  reload-interval 2s
  log stderr

user ally
  password $argon2id$v=19$m=65536,t=3,p=1$...
  root /tmp/zift/ally
  allow /pending* read write list mkdir remove rename
  allow /archive* read list
  allow / read list
  deny *.exe .ssh/*
```

Permissions are default-deny. `deny` rules override `allow` rules.
