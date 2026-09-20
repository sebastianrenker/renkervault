# Hosting the RenkerVault relay — guide

So that people outside your machine can chat with each other, they
need a **mutually reachable relay server** (the relay still only sees
ciphertext — see [SECURITY.md](../SECURITY.md)). There are
two paths: a **rented server (recommended)** or your **own PC**.

---

## Path 1: Rented server (recommended)

A small VPS (1 vCPU, 1 GB RAM is easily enough; costs 3–6 € a month at most
providers) runs 24/7, has a fixed IP address, and no
risk to your own home network.

### Prerequisites

- A VPS with Ubuntu or Debian (Hetzner, IONOS, Contabo, DigitalOcean, …)
- A (sub)domain whose **A record points to the server IP** (e.g.
  `chat.yourdomain.com` → `203.0.113.42`) — needed for a real,
  browser-trusted TLS certificate.

### Step by step

**1) Secure the server (once)**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

The relay itself listens **only on localhost** (`127.0.0.1`) — it is not
directly reachable from the internet, only via the reverse proxy (Caddy).
This reduces the attack surface: a bug in the Node process cannot
be exploited directly from outside without passing the hardened proxy.

**2) Install Node.js**

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

**3) Upload and set up the RenkerVault relay**

```bash
sudo mkdir -p /opt/renkervault
sudo chown $USER:$USER /opt/renkervault
# copy the server/ folder from this repo here (e.g. via scp/rsync/git)
cd /opt/renkervault/server
npm install --omit=dev
cp ../deploy/.env.example .env
# adjust .env: HOST=127.0.0.1 (default), PORT=8787, TRUST_PROXY=1
nano .env
```

**4) Set up as a systemd service (runs continuously, restarts after reboot)**

```bash
sudo useradd --system --no-create-home renkervault
sudo chown -R renkervault:renkervault /opt/renkervault
sudo cp ../deploy/renkervault-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now renkervault-relay
sudo systemctl status renkervault-relay   # should show "active (running)"
```

**5) Install Caddy (an automatic, self-renewing TLS certificate)**

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

Copy `deploy/Caddyfile` to `/etc/caddy/Caddyfile`, set the domain in it to
your own, then:

```bash
sudo systemctl reload caddy
```

Caddy now automatically obtains a valid Let's Encrypt certificate for
the domain and forwards WebSocket traffic transparently to the relay.

**6) Enter it in RenkerVault**

In the app under **Settings → Relay server**, enter the address:

```
wss://chat.yourdomain.com
```

All users who want to chat with each other enter **the same address**.
Done — the relay now runs continuously and reachable for everyone.

### Operation & maintenance

- View logs: `sudo journalctl -u renkervault-relay -f`
- Restart after code changes: `sudo systemctl restart renkervault-relay`
- The relay holds state only in memory (a prototype, see
  SECURITY.md) — a restart resets the device/queue state,
  but **no** user data is "lost" in the process, since nothing is
  permanently stored on the server anyway.
- Automatic security updates recommended: `sudo apt install unattended-upgrades`

---

## Path 2: Hosting from your own PC

Possible, but with noticeable limitations — recommended only for tests or a very
small, informal circle of users:

- **Port forwarding needed:** in the router, port 443 (and possibly 80 for
  TLS certificate issuance) must be forwarded to the PC. That makes
  the PC directly reachable from the internet — a real security risk
  for the rest of the home network if the router/firewall is not
  cleanly configured.
- **No fixed IP address:** most private internet connections have
  a changing IP. Without a **DynDNS service** (e.g. DuckDNS, No-IP)
  the relay would no longer be reachable after every reassignment of the IP.
- **No 24/7 operation:** as soon as the PC turns off or goes to sleep,
  the relay is unreachable and nobody can chat anymore.
- **Privacy:** the public IP address of your own internet connection
  becomes visible to anyone who resolves the domain.

If desired anyway:

1. Set up a DynDNS client (e.g. the DuckDNS script as a cron job), point your own
   domain e.g. `myname.duckdns.org` at it.
2. Install Node.js locally, set up `server/` as under step 3 above
   (no systemd needed on Windows — instead start it e.g. as a scheduled
   task or simply manually in a terminal window).
3. Install Caddy locally, use the same `Caddyfile` principle with the
   DynDNS domain instead of your own domain.
4. In the router: set up port forwarding 443 → PC-IP:443 (and 80 → PC-IP:80 for
   certificate issuance).
5. In RenkerVault under Settings → Relay server: `wss://myname.duckdns.org`.

**Clear recommendation:** for anything beyond brief experimentation,
a rented VPS (path 1) is the significantly safer and more reliable
choice — and really costs only a few euros a month.

---

## Path 3: Maximum anonymity via a Tor hidden service

Paths 1 and 2 hide the *content* of the communication (end-to-end
encryption), but not **who is connected to the relay** — the
server operator (and an attacker on the same network) still sees the
IP address of every connected client, and a network observer sees
that a connection to this server exists at all. Anyone who additionally
wants to hide **that** runs the relay instead as a
**Tor hidden service** (`.onion` address):

1. On the server: `sudo apt install tor`, then append the content of
   [`torrc.snippet`](torrc.snippet) to `/etc/tor/torrc` and
   `sudo systemctl restart tor`.
2. Your own `.onion` address is then in
   `/var/lib/tor/renkervault/hostname`.
3. No TLS certificate, no domain, no open firewall port needed —
   the relay listens only on `127.0.0.1`, Tor handles the transport encryption
   and authentication of the entire connection.
4. Clients can connect only via Tor: in the **Tor Browser** (for the
   web client) or via a system-wide Tor service with a SOCKS5 proxy
   (for desktop/mobile apps — the browser WebSocket API itself cannot force a
   proxy, that must happen at the OS/browser level).
   The address in the settings: `ws://youraddress.onion` (no `wss://`
   needed — Tor already encrypts).

**Result:** neither the relay operator nor a network observer
learns which real IP addresses are conversing — and conversely,
clients also do not know the server's real IP address. This is the strongest
available level against traffic/metadata analysis in this setup, with the
trade-off of noticeably higher latency (typical for Tor) and the
necessity that really all participants communicate over Tor.

---

## Alternative: native TLS without a reverse proxy

The relay can also terminate TLS **itself** (without Caddy/nginx in front),
via `TLS_CERT_FILE`/`TLS_KEY_FILE` in the `.env` (see `.env.example`).
This is simpler to set up but has a real drawback: Let's Encrypt
certificates are only valid for 90 days and must be renewed **manually**
(e.g. via `certbot certonly --standalone`, then update `.env` and restart the
service) — Caddy does this automatically. Therefore use this variant
only when a reverse proxy is out of the question for other reasons.

---

## DDoS protection (hardening roadmap point 9)

The relay already comes with app-side limits (30 messages/s per
socket, max. 20 simultaneous connections per IP, 15 s auth timeout, see
SECURITY.md section 4 point 12) — that protects against a single
attacker/a single IP, but **not** against a distributed flood from
many IPs simultaneously (a real DDoS). Three additional layers, from simple
to effective:

**1) Limit the `ufw`/kernel-side connection rate (usable immediately, no extra package):**

```bash
# Limit new connections on 443 to max. 20/minute per source IP —
# holds off simple SYN floods from a single source.
sudo ufw limit 443/tcp
```

**2) `fail2ban` against repeated auth failures:** the relay already logs
lockouts to stdout (`[GUARD] Lockout for <userId> ...`), viewable via
`journalctl -u renkervault-relay`. A simple fail2ban jail
can additionally block IPs with conspicuously many lockouts at the firewall level:

```ini
# /etc/fail2ban/jail.d/renkervault.conf
[renkervault-relay]
enabled  = true
backend  = systemd
journalmatch = _SYSTEMD_UNIT=renkervault-relay.service
filter   = renkervault-relay
maxretry = 3
findtime = 600
bantime  = 3600
```

```ini
# /etc/fail2ban/filter.d/renkervault-relay.conf
[Definition]
failregex = ^.*\[GUARD\] Lockout for .* <HOST>?.*$
```

Note: the relay currently logs no IP address in the lockout line
(only the account ID) — for an effective IP-based fail2ban jail,
`server/src/index.js` would have to log the IP (`meta.ip`, already
present in the code, see `clientIp()`). Deliberately not added in this update, since
logging IP addresses in a log file creates a new, permanent
metadata artifact on the server — to be weighed against the
DDoS benefit, see SECURITY.md.

**3) An upstream CDN/anti-DDoS service (the only way against real
distributed attacks):** neither `ufw` nor `fail2ban` help against thousands of
simultaneous IPs. For that, place Cloudflare (or comparable) in "proxied" mode
in front of the domain — WebSocket is supported by Cloudflare's default proxy,
no special configuration needed. Trade-off: Cloudflare then sees
the connection metadata (not the ciphertext content) before your
own relay — to be weighed against the availability gain.

---

## Security quick-check before going live

- [ ] `HOST=127.0.0.1` in the `.env` when a reverse proxy runs (not `0.0.0.0`)
- [ ] `wss://`, not `ws://`, for anything other than `localhost`
- [ ] The firewall allows only 80/443 (+ SSH) from outside
- [ ] `TRUST_PROXY=1` set only when a reverse proxy really runs in front
- [ ] Automatic system updates active
- [ ] The server user without unnecessary rights (the systemd unit already runs as
      its own, unprivileged `renkervault` user)
