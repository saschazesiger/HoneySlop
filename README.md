<div align="center">

# 🍯 HoneySlop

**The honeypot that lies back.**
Every request gets a convincing, LLM‑generated *“yes, you hacked me”* response. You watch it all live.

[![Build](https://github.com/saschazesiger/HoneySlop/actions/workflows/docker.yml/badge.svg)](https://github.com/saschazesiger/HoneySlop/actions/workflows/docker.yml)
[![Image](https://img.shields.io/badge/ghcr.io-saschazesiger%2Fhoneyslop-3ddc97?logo=docker&logoColor=white)](https://github.com/saschazesiger/HoneySlop/pkgs/container/honeyslop)
![Go](https://img.shields.io/badge/go-single%20binary-00ADD8?logo=go&logoColor=white)
![Arch](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-555)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<img src="docs/screenshots/dashboard.png" alt="HoneySlop dashboard" width="900">

</div>

---

## ✨ What it does

Scanners and attackers hit your box. Instead of a boring 404, **every path looks vulnerable**:

| They try… | They get… |
|---|---|
| `GET /.env` | a full Laravel `.env` with DB passwords, AWS keys, SMTP creds |
| `?id=1' UNION SELECT …` | the page *with leaked user rows* and bcrypt hashes |
| `../../etc/passwd` | a believable `/etc/passwd` of the fake host |
| `/.git/config`, `/phpmyadmin`, `/wp-login.php`, `/actuator/env` … | exactly what they hoped for |
| `/` | an “exposed” **root web terminal** – a fake bash that remembers everything they typed |

All of it is generated on the fly by an LLM (via [OpenRouter](https://openrouter.ai)) impersonating a fictional mid‑size company – **realistic names, IBANs, hashes, keys in the right vendor formats**. No `admin123`, no `example.com`.

Meanwhile you sit in **`/pot`** and watch every request and every response, live. 🍿

## 🚀 Quick start

```bash
docker run -d --name honeyslop --restart unless-stopped \
  -p 80:80 -p 443:443 \
  -v "$PWD/honeyslop:/data" \
  ghcr.io/saschazesiger/honeyslop pot.example.com
```

1. 🌐 Point `pot.example.com` at your server – a **Let's Encrypt** certificate is issued automatically.
2. 🔑 Open **`https://pot.example.com/pot`** and set your admin password.
3. 🤖 Paste your **OpenRouter API key** in ⚙️ Settings and hit *Test connection*.
4. 🍯 Done. The trap is live on **ports 80 + 443, for every hostname and the bare IP**.

> No domain? Just drop the last argument – HoneySlop serves a self‑signed certificate and works on the IP.

<details>
<summary>🐙 docker compose</summary>

```yaml
services:
  honeyslop:
    image: ghcr.io/saschazesiger/honeyslop
    command: pot.example.com
    restart: unless-stopped
    ports: ["80:80", "443:443"]
    volumes: ["./honeyslop:/data"]
```
</details>

## 📸 Screenshots

<table>
<tr>
<td width="50%"><img src="docs/screenshots/event.png" alt="Request timeline"><br><sub>🔍 Every request & response, raw, in a timeline per IP</sub></td>
<td width="50%"><img src="docs/screenshots/terminal.png" alt="Fake terminal"><br><sub>🖥️ The bait on <code>/</code>: an LLM‑driven bash with full session memory</sub></td>
</tr>
<tr>
<td width="50%"><img src="docs/screenshots/settings.png" alt="Settings"><br><sub>⚙️ OpenRouter key, model & the fake company persona</sub></td>
<td width="50%"><img src="docs/screenshots/setup.png" alt="First run"><br><sub>🔐 First visit of <code>/pot</code>: create your password</sub></td>
</tr>
</table>

## 🧩 Features

- 🤖 **AI responses for every path** except `/` and `/pot` – full request context (method, URL, headers, body) plus the attacker's previous responses for consistency
- 🖥️ **Fake web terminal** on `/` – complete command history goes to the LLM, `cd`, users and created files stay consistent; sessions survive reloads
- 📡 **Live dashboard** – attacker IPs stream in via SSE, with 🌍 country, city, ISP and ASN
- 🧾 **Forensic timeline** – click an IP to see each raw request and raw response, in order
- 🚦 **Per‑IP AI budget** – 10 / minute, 60 / hour, 100 / day; beyond that attackers get plain nginx 404s
- 🎚️ **AI on/off switch** and 🧹 **clear all** in the dashboard
- 🔒 **Automatic TLS** via Let's Encrypt (HTTP‑01 & TLS‑ALPN‑01), self‑signed fallback for IP/other hosts
- 🧱 **Sandboxed bait** – generated pages are served with `CSP: sandbox`, so reflected “XSS” pops for the attacker but can never touch `/pot`
- 📦 **One static Go binary**, `linux/amd64` + `linux/arm64`, SQLite inside – no external DB

## 📁 Data folder

Everything lives in the mounted folder:

```
honeyslop/
├── config.json      # password hash, OpenRouter key, model, persona, AI toggle
├── honeyslop.db     # SQLite: every request, response, IP + geo info
└── certs/           # Let's Encrypt account & certificates, self-signed fallback
```

Back it up, copy it, `sqlite3` into it – it's yours.

## ⚙️ Configuration

Most things are set in the dashboard. For the rest:

| Option | Default | |
|---|---|---|
| `[domain]` (argument) or `DOMAIN` | – | hostname for the Let's Encrypt certificate |
| `ACME_EMAIL` | – | optional contact for Let's Encrypt |
| `ADMIN_PASSWORD` | – | pre‑set the admin password instead of creating it on first visit |
| `OPENROUTER_BASE_URL` | `https://openrouter.ai/api/v1` | any OpenAI‑compatible endpoint |
| `HTTP_ADDR` / `HTTPS_ADDR` | `:80` / `:443` | listen addresses |
| `config.json → trust_proxy` | `false` | use `X-Forwarded-For` (only behind your own proxy) |
| `config.json → limits` | `10 / 60 / 100` | per‑IP AI responses per minute / hour / day (IPv6 counted per /64) |
| `config.json → limits.global_hour` | `600` | AI responses per hour across all attackers – wallet protection |
| `config.json → retention_days` / `max_events` | `90` / `200000` | oldest events are pruned automatically |

## 🧠 How it works

```
attacker ──► :80 / :443 ──► /pot ........ your dashboard (password)
                        ├─► /  .......... fake bash ──► OpenRouter (full session history)
                        └─► /* .......... any path  ──► rate limit ──► OpenRouter ──► fake but plausible response
                                     every hit ──► SQLite ──► live SSE ──► /pot
```

## ⚠️ Good to know

- 🔑 **Set your password right after starting** – until then, whoever opens `/pot` first gets to set it (or use `ADMIN_PASSWORD`).
- 💸 The LLM costs money. Per‑IP limits, a global hourly cap and a concurrency cap keep it small; the default model is a cheap, fast one.
- 🧪 Run it on a **dedicated box / IP** – it exists to attract attacks.
- 🎭 All generated data is fictional. The default persona is the made‑up *Veltrona Logistics AG*; change it in Settings.

## 🛠️ Development

```bash
go run . --data ./data --http :8080 --https :8443   # then open http://localhost:8080/pot
go test ./...
```

<div align="center"><sub>Made with 🍯 and a healthy dose of slop.</sub></div>
