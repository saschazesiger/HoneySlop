<div align="center">

# 🍯 HoneySlop

**An AI honeypot that fights back. Breaking in is a real challenge. You watch every move live.**

[![Build](https://github.com/saschazesiger/HoneySlop/actions/workflows/docker.yml/badge.svg)](https://github.com/saschazesiger/HoneySlop/actions/workflows/docker.yml)
[![Image](https://img.shields.io/badge/ghcr.io-honeyslop-3ddc97?logo=docker&logoColor=white)](https://github.com/saschazesiger/HoneySlop/pkgs/container/honeyslop)
![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-555)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<img src="docs/screenshots/dashboard.png" alt="Dashboard" width="900">

</div>

## ✨ What makes it different

Most honeypots either answer everything with a canned page, or let an LLM pretend every attack just works. HoneySlop does neither. On first start it generates a whole fictional company and a whole server: Unix accounts, MySQL users, a Laravel portal, a WordPress blog, SSH keys, API tokens, a full customer database. All of it with **real, consistent credentials**. The attacker has to actually find them and chain them together.

- 🔐 **Only real credentials work.** `su`, `sudo`, the `mysql` client and every web login are checked in Go against the generated world, not by the model. A guessed password is rejected with the exact error the real software would print. To get into the database you first have to read it out of a file, and only that one password opens it.
- 🗂️ **Secrets are consistent everywhere.** The `DB_PASSWORD` you pull from `/.env` over an LFI is the same one that logs you into MySQL and phpMyAdmin. The deploy password hidden in a world readable backup script is the one that actually lets you `su deploy`. Hashes in a dumped `users` table really are the bcrypt of the real password.
- 🖥️ **A shell that enforces permissions.** A deterministic engine answers `cat`, `ls`, `id`, `su`, `sudo`, the `mysql` monitor and more, with a real file system and Unix permission model. `cat /etc/shadow` as `www-data` is denied; the LLM fills in the rest and is handed the hard facts so it can never contradict them.
- 🗄️ **A working MySQL.** `mysql` and `mysqldump` log in, run real SQL against the generated database (information_schema, SHOW, DESCRIBE, grants, MySQL error codes) and print proper result tables.
- 🧗 **A kill chain to climb.** creds → db → login → user → root. Each attacker IP is scored on how far it got, live.
- 🤖 **The LLM only adds flavour.** Everything security relevant is decided by code; the model renders the pages and output around it.
- 💾 **Each path hits the AI once.** Generated pages are cached to disk (`<data>/cache`), so repeat probes of the same URL are free and always identical.

## 🛰️ Live dashboard

The operator console on `/pot` shows every IP with geo and ASN, every request and response, the fake shell sessions (password prompts, the `mysql>` monitor, root in red), and a kill-chain strip per IP. A **World** tab lays out the whole attack surface: the intended chain and every planted credential with where it leaks from. Built with a crafted pixel-type look (Tiny5 Duo + Departure Mono), not another stock dashboard.

| Timeline & terminal | Attack surface |
|---|---|
| <img src="docs/screenshots/event.png"> | <img src="docs/screenshots/settings.png"> |
| **Fake shell (attacker view)** | **First run** |
| <img src="docs/screenshots/terminal.png"> | <img src="docs/screenshots/setup.png"> |

## 🚀 Quick start

```bash
docker run -d --name honeyslop --restart unless-stopped \
  -p 80:80 -p 443:443 -v "$PWD/honeyslop:/data" \
  ghcr.io/saschazesiger/honeyslop pot.example.com
```

1. Open `https://pot.example.com/pot` and set a password
2. Add your [OpenRouter](https://openrouter.ai) key in ⚙️ Settings
3. Done 🍯

No domain? Omit it, a self-signed cert is used.

## 🧩 The challenge, by design

The generated world is reproducible across restarts and re-rolled from the dashboard. One intended path:

1. **creds** Pull a secret: `GET /.env` (also via LFI, `php://filter`, traversal), `/blog/wp-config.php.bak`, or `cat /opt/scripts/db-backup.sh` in the shell. Only the real values found here work.
2. **db** Use them: `mysql -h db-prod-01... -u connect_app -p<found>` or log into `/phpmyadmin`. Wrong passwords are denied.
3. **login** Sign into a web app: the Laravel portal, WordPress (one weak account is crackable), or phpMyAdmin.
4. **user** The backup script reuses the deploy password, so `su deploy` succeeds. deploy is in the `docker` group.
5. **root** Escalate from there.

## ⚙️ Config

| | Default | |
|---|---|---|
| `DOMAIN` or argument | | Let's Encrypt hostname |
| `ADMIN_PASSWORD` | | preset admin password |
| `ACME_EMAIL` | | Let's Encrypt contact |
| `OPENROUTER_BASE_URL` | OpenRouter | any OpenAI compatible API |
| `limits` | 10 / 60 / 100 | per IP AI calls (min / h / day) |
| `limits.global_hour` | 600 | AI calls per hour, all IPs |
| `retention_days` / `max_events` | 90 / 200000 | auto cleanup |

Everything lives in `/data`: `config.json`, `world.json` (the generated credentials), `honeyslop.db`, `cache/` (one answer per path), `certs/`.

## ⚠️ Notes

- Set the password right after start, or use `ADMIN_PASSWORD`
- Run it on a dedicated box
- All generated data is fictional

<div align="center"><sub>MIT · made with 🍯</sub></div>
