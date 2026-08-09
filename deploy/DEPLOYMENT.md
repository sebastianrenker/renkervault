# RenkerVault Relay hosten — Anleitung

Damit Personen außerhalb deines Rechners miteinander chatten können,
brauchen sie einen **gemeinsam erreichbaren Relay-Server** (der Relay sieht
dabei weiterhin nur Chiffretext — siehe [SECURITY.md](../SECURITY.md)). Es
gibt zwei Wege: ein **gemieteter Server (empfohlen)** oder der **eigene PC**.

---

## Weg 1: Gemieteter Server (empfohlen)

Ein kleiner VPS (1 vCPU, 1 GB RAM reichen locker; kostet bei den meisten
Anbietern 3–6 € im Monat) läuft 24/7, hat eine feste IP-Adresse und kein
Risiko fürs eigene Heimnetz.

### Voraussetzungen

- Ein VPS mit Ubuntu oder Debian (Hetzner, IONOS, Contabo, DigitalOcean, …)
- Eine (Sub-)Domain, deren **A-Record auf die Server-IP zeigt** (z. B.
  `chat.deinedomain.de` → `203.0.113.42`) — nötig für ein echtes,
  Browser-vertrauenswürdiges TLS-Zertifikat.

### Schritt für Schritt

**1) Server absichern (einmalig)**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y ufw
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

Der Relay selbst lauscht **nur auf localhost** (`127.0.0.1`) — er ist vom
Internet aus nicht direkt erreichbar, nur über den Reverse-Proxy (Caddy).
Das reduziert die Angriffsfläche: Ein Fehler im Node-Prozess kann nicht
direkt von außen ausgenutzt werden, ohne den gehärteten Proxy zu passieren.

**2) Node.js installieren**

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

**3) RenkerVault-Relay hochladen und einrichten**

```bash
sudo mkdir -p /opt/renkervault
sudo chown $USER:$USER /opt/renkervault
# server/-Ordner aus diesem Repo hierher kopieren (z. B. per scp/rsync/git)
cd /opt/renkervault/server
npm install --omit=dev
cp ../deploy/.env.example .env
# .env anpassen: HOST=127.0.0.1 (Standard), PORT=8787, TRUST_PROXY=1
nano .env
```

**4) Als systemd-Dienst einrichten (läuft dauerhaft, startet nach Reboot neu)**

```bash
sudo useradd --system --no-create-home renkervault
sudo chown -R renkervault:renkervault /opt/renkervault
sudo cp ../deploy/renkervault-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now renkervault-relay
sudo systemctl status renkervault-relay   # sollte "active (running)" zeigen
```

**5) Caddy installieren (automatisches, sich selbst erneuerndes TLS-Zertifikat)**

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

`deploy/Caddyfile` nach `/etc/caddy/Caddyfile` kopieren, die Domain darin auf
die eigene setzen, dann:

```bash
sudo systemctl reload caddy
```

Caddy holt sich jetzt automatisch ein gültiges Let's-Encrypt-Zertifikat für
die Domain und leitet WebSocket-Verkehr transparent an den Relay weiter.

**6) In RenkerVault eintragen**

In der App unter **Einstellungen → Relay-Server** die Adresse eintragen:

```
wss://chat.deinedomain.de
```

Alle Nutzer, die miteinander chatten wollen, tragen **dieselbe Adresse**
ein. Fertig — der Relay läuft jetzt dauerhaft und erreichbar für alle.

### Betrieb & Wartung

- Logs ansehen: `sudo journalctl -u renkervault-relay -f`
- Neustart nach Codeänderungen: `sudo systemctl restart renkervault-relay`
- Der Relay hält Zustand nur im Arbeitsspeicher (Prototyp, siehe
  SECURITY.md) — ein Neustart setzt Geräte-/Warteschlangen-Zustand zurück,
  aber **keine** Nutzerdaten gehen dabei "verloren", da ohnehin nichts
  dauerhaft auf dem Server gespeichert wird.
- Automatische Sicherheitsupdates empfohlen: `sudo apt install unattended-upgrades`

---

## Weg 2: Vom eigenen PC hosten

Möglich, aber mit spürbaren Einschränkungen — nur für Tests oder einen sehr
kleinen, informellen Nutzerkreis empfohlen:

- **Portweiterleitung nötig:** Im Router muss Port 443 (und ggf. 80 für die
  TLS-Zertifikatsausstellung) auf den PC weitergeleitet werden. Das macht
  den PC direkt aus dem Internet erreichbar — ein echtes Sicherheitsrisiko
  fürs restliche Heimnetz, falls der Router/die Firewall nicht sauber
  konfiguriert ist.
- **Keine feste IP-Adresse:** Die meisten privaten Internetanschlüsse haben
  eine wechselnde IP. Ohne einen **DynDNS-Dienst** (z. B. DuckDNS, No-IP)
  wäre der Relay nach jeder Neuvergabe der IP nicht mehr erreichbar.
- **Kein 24/7-Betrieb:** Sobald der PC aus- oder in den Ruhezustand geht,
  ist der Relay nicht erreichbar und niemand kann mehr chatten.
- **Datenschutz:** Die öffentliche IP-Adresse des eigenen Internetanschlusses
  wird für jeden sichtbar, der die Domain auflöst.

Falls trotzdem gewünscht:

1. DynDNS-Client einrichten (z. B. DuckDNS-Skript als Cronjob), eigene
   Domain z. B. `meinname.duckdns.org` darauf zeigen lassen.
2. Node.js lokal installieren, `server/` wie oben unter Schritt 3 einrichten
   (kein systemd nötig unter Windows — stattdessen z. B. als geplante
   Aufgabe oder einfach manuell in einem Terminal-Fenster starten).
3. Caddy lokal installieren, gleiches `Caddyfile`-Prinzip mit der
   DynDNS-Domain statt einer eigenen Domain verwenden.
4. Im Router: Portweiterleitung 443 → PC-IP:443 (und 80 → PC-IP:80 für die
   Zertifikatsausstellung) einrichten.
5. In RenkerVault unter Einstellungen → Relay-Server: `wss://meinname.duckdns.org`.

**Klare Empfehlung:** Für alles, was über kurzes Ausprobieren hinausgeht,
ist ein gemieteter VPS (Weg 1) die deutlich sicherere und zuverlässigere
Wahl — und kostet real nur wenige Euro im Monat.

---

## Weg 3: Maximale Anonymität über einen Tor Hidden Service

Weg 1 und 2 verstecken den *Inhalt* der Kommunikation (Ende-zu-Ende-
Verschlüsselung), aber nicht, **wer mit dem Relay verbunden ist** — der
Server-Betreiber (und ein Angreifer im selben Netz) sieht weiterhin die
IP-Adresse jedes verbundenen Clients, und ein Netzwerk-Beobachter sieht,
dass überhaupt eine Verbindung zu diesem Server besteht. Wer zusätzlich
**das** verstecken will, betreibt den Relay stattdessen als
**Tor Hidden Service** (`.onion`-Adresse):

1. Auf dem Server: `sudo apt install tor`, dann den Inhalt von
   [`torrc.snippet`](torrc.snippet) an `/etc/tor/torrc` anhängen und
   `sudo systemctl restart tor`.
2. Die eigene `.onion`-Adresse steht danach in
   `/var/lib/tor/renkervault/hostname`.
3. Kein TLS-Zertifikat, keine Domain, keine offene Firewall-Pforte nötig —
   der Relay lauscht nur auf `127.0.0.1`, Tor übernimmt Transportverschlüsselung
   und Authentifizierung der gesamten Verbindung.
4. Verbinden lassen sich Clients nur über Tor: im **Tor Browser** (für den
   Web-Client) oder über einen system-weiten Tor-Dienst mit SOCKS5-Proxy
   (für Desktop-/Mobile-Apps — die Browser-WebSocket-API selbst kann keinen
   Proxy erzwingen, das muss auf Betriebssystem-/Browser-Ebene passieren).
   Adresse in den Einstellungen: `ws://deinadresse.onion` (kein `wss://`
   nötig — Tor verschlüsselt bereits).

**Ergebnis:** Weder der Relay-Betreiber noch ein Netzwerk-Beobachter
erfahren, welche echten IP-Adressen sich unterhalten — und umgekehrt kennen
Clients auch nicht die echte IP-Adresse des Servers. Das ist die stärkste
verfügbare Stufe gegen Traffic-/Metadaten-Analyse in diesem Setup, mit dem
Kompromiss einer spürbar höheren Latenz (typisch für Tor) und der
Notwendigkeit, dass wirklich alle Beteiligten über Tor kommunizieren.

---

## Alternative: Natives TLS ohne Reverse-Proxy

Der Relay kann TLS auch **selbst** terminieren (ohne Caddy/nginx davor),
über `TLS_CERT_FILE`/`TLS_KEY_FILE` in der `.env` (siehe `.env.example`).
Das ist einfacher aufzusetzen, hat aber einen echten Nachteil: Let's-Encrypt-
Zertifikate sind nur 90 Tage gültig und müssen **manuell** erneuert werden
(z. B. per `certbot certonly --standalone`, dann `.env` aktualisieren und den
Dienst neu starten) — Caddy erledigt das automatisch. Diese Variante daher
nur nutzen, wenn ein Reverse-Proxy aus anderen Gründen nicht infrage kommt.

---

## DDoS-Schutz (Härtungs-Roadmap Punkt 9)

Der Relay bringt bereits App-seitige Grenzen mit (30 Nachrichten/s pro
Socket, max. 20 gleichzeitige Verbindungen pro IP, 15 s Auth-Timeout, siehe
SECURITY.md Abschnitt 4 Punkt 12) — das schützt vor einem einzelnen
Angreifer/einer einzelnen IP, aber **nicht** vor einer verteilten Flut aus
vielen IPs gleichzeitig (echtes DDoS). Drei zusätzliche Ebenen, von einfach
nach wirksam:

**1) `ufw`/Kernel-seitige Verbindungsrate begrenzen (sofort einsetzbar, kein Zusatzpaket):**

```bash
# Neue Verbindungen auf 443 auf max. 20/Minute pro Quell-IP begrenzen —
# haelt simple SYN-Fluten von einer einzelnen Quelle ab.
sudo ufw limit 443/tcp
```

**2) `fail2ban` gegen wiederholte Auth-Fehlversuche:** Der Relay protokolliert
Lockouts bereits nach stdout (`[GUARD] Lockout fuer <userId> ...`), das via
`journalctl -u renkervault-relay` einsehbar ist. Ein einfacher fail2ban-Jail
kann IPs mit auffällig vielen Lockouts zusätzlich auf Firewall-Ebene sperren:

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
failregex = ^.*\[GUARD\] Lockout fuer .* <HOST>?.*$
```

Hinweis: Der Relay loggt aktuell keine IP-Adresse in der Lockout-Zeile
(nur die Konto-ID) — für einen wirksamen IP-basierten fail2ban-Jail müsste
`server/src/index.js` die IP mitloggen (`meta.ip`, bereits im Code
vorhanden, siehe `clientIp()`). Bewusst nicht in diesem Update ergänzt, da
das Mitloggen von IP-Adressen in einer Logdatei ein neues, dauerhaftes
Metadaten-Artefakt auf dem Server schafft — abzuwägen gegen den
DDoS-Nutzen, siehe SECURITY.md.

**3) Vorgelagerter CDN-/Anti-DDoS-Dienst (der einzige Weg gegen echte
verteilte Angriffe):** Weder `ufw` noch `fail2ban` helfen gegen tausende
gleichzeitige IPs. Dafür Cloudflare (oder vergleichbar) im „Proxied"-Modus
vor die Domain schalten — WebSocket wird von Cloudflares Standard-Proxy
unterstützt, keine Sonderkonfiguration nötig. Kompromiss: Cloudflare sieht
dann die Verbindungsmetadaten (nicht den Chiffretext-Inhalt) vor dem
eigenen Relay — abzuwägen gegen den Verfügbarkeitsgewinn.

---

## Sicherheits-Kurzcheck vor dem Livegang

- [ ] `HOST=127.0.0.1` in der `.env`, wenn ein Reverse-Proxy läuft (nicht `0.0.0.0`)
- [ ] `wss://`, nicht `ws://`, für alles außer `localhost`
- [ ] Firewall lässt nur 80/443 (+ SSH) von außen zu
- [ ] `TRUST_PROXY=1` nur gesetzt, wenn wirklich ein Reverse-Proxy davor läuft
- [ ] Automatische System-Updates aktiv
- [ ] Server-Nutzer ohne unnötige Rechte (systemd-Unit läuft bereits als
      eigener, unprivilegierter `renkervault`-Nutzer)
