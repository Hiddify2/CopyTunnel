<div align="center">

# 📦 CopyTunnel

**An encrypted tunnel that copies every TCP/UDP packet from the client, encrypts it, and relays it through a server to its real destination — and back. Two forwarding methods (TUN and transparent proxy) and six ciphers, driven by an interactive installer.**

<p>
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square" alt="Linux">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/methods-TUN%20%7C%20Proxy-purple?style=flat-square" alt="Methods">
  <img src="https://img.shields.io/badge/ciphers-6-green?style=flat-square" alt="Ciphers">
</p>

<p>
  <a href="#-quick-install">Quick Install</a> ·
  <a href="#-two-forwarding-methods">Methods</a> ·
  <a href="#-how-it-works">How It Works</a> ·
  <a href="#-encryption-methods">Encryption</a> ·
  <a href="#-configuration-reference">Configuration</a>
</p>

</div>

---

> **⚠️ Educational, research, and authorized use only.**
> CopyTunnel forwards network traffic between two hosts you control. You are solely
> responsible for using it lawfully and only on networks and systems you are
> authorized to operate. The authors assume no liability for misuse.

---

## What it does

CopyTunnel is a **point-to-point encrypted tunnel** built in Rust. The client
captures your traffic, **encrypts every packet/stream**, and relays it to the
server; the server **decrypts** it and lets the kernel route it to the real
destination — and replies come back the same way. To the application it is
transparent; to anyone watching the client↔server link it is opaque,
authenticated traffic.

It offers **two ways to capture traffic**, so you can pick what survives your
network and matches your use case:

| Method | Layer | Transport | Captures | Best for |
|---|---|---|---|---|
| **TUN** | L3 (IP packets) | UDP | all IPv4 TCP **and UDP** | full tunnelling, UDP apps, lowest overhead |
| **Transparent Proxy** | L4 (streams) | TCP | TCP connections (via sing-box tproxy) | reliable relaying, works where UDP is blocked, no TUN needed |

Both methods use the **same CopyTunnel server, the same pre-shared key, and the
same ciphers** — the server can serve TUN clients and proxy clients at the same
time. An **interactive installer** (à la Hiddify Relay Builder) sets up either
one for you, including sing-box and the iptables rules for the proxy method.

The TUN handling, point-to-point addressing, port-forward filtering, and TOML
config layout follow the model of
[CandyTunnel](https://github.com/AmiRCandy/CandyTunnel).

---

## 🚀 Quick Install

One command bootstraps everything (detects your distro, installs dependencies,
fetches the binary, and launches the manager):

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hiddify2/CopyTunnel/main/scripts/install.sh)"
```

Re-open the manager anytime with `copytunnel-menu` (or the short alias `ct`).

The manager is a `whiptail` menu. You pick a **method**, then **Install /
Status / Add / Remove / Uninstall** within it:

```
CopyTunnel — choose method
  ┌────────────────────────────────────────────────┐
  │  TUN       Layer-3 encrypted tunnel (TUN + UDP) │
  │  Proxy     Transparent proxy (sing-box + iptbl) │
  │  Options   DNS · update · keygen · test · rm    │
  │  Quit                                           │
  └────────────────────────────────────────────────┘
```

| Menu | What it does |
|---|---|
| **TUN → Install** | Wizard for role (client/server), key (auto-generate or type), cipher, obfuscation, addresses, ports, NIC/NAT. Writes the config + a systemd unit and starts it. |
| **Proxy → Install** | Same wizard; for a client it **also** downloads sing-box, writes its tproxy config, installs the iptables TPROXY rules (with a managed bypass list), and wires up three systemd units in the right order. |
| **Proxy → Add / Remove** | Manage the direct-route **bypass list** (IPs/CIDRs sent outside the tunnel). |
| **Status** | `systemctl` state + listening sockets + (proxy) active mangle rules. |
| **Options** | Set DNS, update the binary + restart services, generate a random key, run a connectivity/tunnel test, or uninstall everything. |

> Everything the installer does by hand is also documented below for manual setups.

---

## ⚙️ How It Works

```text
          CLIENT HOST                                 SERVER HOST                 INTERNET
 ┌──────────────────────────┐              ┌──────────────────────────┐        ┌──────────┐
 │ application (any TCP/UDP) │              │                          │        │          │
 │            │             │              │                          │        │  real    │
 │            ▼             │              │                          │        │  dest    │
 │   kernel routing table   │              │                          │        │          │
 │            │             │              │                          │        └────▲─────┘
 │            ▼             │              │                          │             │
 │   TUN  "copy0"           │              │   TUN  "copy0"           │  kernel     │
 │            │ read        │              │        write │           │  routes +   │
 │            ▼             │              │             ▼            │  NAT        │
 │   inspect (tcp/udp?      │              │   decrypt (AEAD auth)    │─────────────┘
 │   port filter?)          │              │             ▲            │
 │            │             │              │             │            │
 │   encrypt (chosen cipher)│   UDP data   │        recv_from         │
 │            │ ───────────────────────────────────────▶│            │
 │   send ─────────────────▶│   channel    │                          │
 │                          │              │   ── reply path ──       │
 │   TUN write ◀─ decrypt ◀─── UDP ◀───────── encrypt ◀─ TUN read ◀───│
 └──────────────────────────┘              └──────────────────────────┘
```

**On the wire**, every datagram is one frame:

```
 AEAD ciphers:   [ nonce ][ ciphertext(type-byte ‖ ip-packet) ‖ auth-tag ]
 xor cipher:     [ salt  ][ keystream-xored(type-byte ‖ ip-packet)       ]
 none:           [ type-byte ‖ ip-packet ]
```

The `type-byte` distinguishes a forwarded IP packet (`0x01`) from a keepalive
(`0x02`). AEAD authentication doubles as a cheap filter: any datagram that
doesn't decrypt under the shared key — random scans, spoofed packets, a peer with
the wrong key — is dropped before it can ever touch the TUN device.

---

## 🚦 Two Forwarding Methods

### Method 1 — TUN (layer 3)

The diagram above. A TUN device captures **all IPv4 TCP and UDP** packets; each
is encrypted and relayed over **UDP**. The inner protocols handle their own
reliability, so the tunnel is a dumb, fast pipe. Best when you want to forward
everything (including UDP: DNS, QUIC, games, VoIP) and have `CAP_NET_ADMIN`.

### Method 2 — Transparent Proxy (layer 4)

Here **sing-box** provides the transparent *ingress*: iptables `TPROXY` rules
redirect outbound connections into sing-box's `tproxy` inbound, which forwards
each one to a **local SOCKS5 server that CopyTunnel runs**. CopyTunnel applies
the **same AEAD encryption** and relays the stream to the server over **TCP**;
the server opens the real connection. sing-box only captures traffic —
**CopyTunnel does all the crypto.**

```text
          CLIENT HOST                                          SERVER HOST          INTERNET
 ┌───────────────────────────────────────────┐        ┌────────────────────┐      ┌────────┐
 │ app ─▶ iptables TPROXY (mangle/fwmark)     │        │                    │      │ real   │
 │             │                              │        │                    │      │ dest   │
 │             ▼                              │        │                    │      └───▲────┘
 │   sing-box  tproxy inbound  ──▶  socks out │        │                    │          │
 │                                   │        │        │                    │          │
 │   127.0.0.1:socks_listen ◀────────┘        │        │                    │          │
 │             │                              │        │                    │          │
 │   CopyTunnel SOCKS5 server                 │        │                    │          │
 │   ── encrypt (AEAD, length-framed) ──┐     │  TCP   │  decrypt ─▶ connect│──────────┘
 │                                      └───────────────▶│  relay bytes ⇄   │
 │   deliver ◀── decrypt ◀───────────────── TCP ◀────────┘                  │
 └───────────────────────────────────────────┘        └────────────────────┘
```

Per relayed connection (one TCP connection to the server), every message is
`[u16 length][ sealed-frame ]`:

```
 1. client → server : sealed  [atyp][addr][port]     (the destination)
 2. server → client : sealed  [status]               (0 = connected)
 3. both ways       : sealed  [raw bytes] …          until a half closes
```

The first frame failing authentication → the connection is dropped, so internet
scanners hitting the proxy port get nothing. **Loop prevention:** the iptables
rules bypass loopback, private ranges, and the server IP, so the
CopyTunnel→server socket is never re-captured. A managed **bypass list**
(`Proxy → Add/Remove`, stored at `/etc/copytunnel/bypass.list`) lets you send
specific IPs/CIDRs outside the tunnel.

> **TCP vs UDP:** proxy mode relays **TCP** (covers all HTTP/HTTPS/TLS traffic).
> For UDP (DNS, QUIC, …) use **TUN** mode, which tunnels UDP natively. A server
> can run both listeners at once, so clients can mix methods.

---

## 🔐 Encryption Methods

CopyTunnel ships six selectable wire ciphers. Set the same one on both sides via
`encryption = "..."`. Here is exactly what each gives you and when to pick it.

| `encryption` value   | Type              | Key  | Nonce  | Authenticated? | Relative speed | Choose it when… |
|----------------------|-------------------|------|--------|----------------|----------------|-----------------|
| `chacha20poly1305`   | AEAD stream       | 256b | 96-bit | ✅ Poly1305    | Very fast on **any** CPU | **Default.** No AES hardware (ARM boards, routers, VPS without AES-NI), or you just want a safe, fast, constant-time cipher everywhere. |
| `xchacha20poly1305`  | AEAD stream       | 256b | 192-bit| ✅ Poly1305    | Very fast | Extremely high packet rates / long-lived keys. The 192-bit random nonce makes accidental nonce reuse statistically impossible, so random nonces stay safe far beyond what a 96-bit nonce allows. |
| `aes256gcm`          | AEAD block (CTR)  | 256b | 96-bit | ✅ GCM         | Fastest **with** AES-NI | Modern x86-64 or ARMv8 with hardware AES. Often the throughput winner on a capable server. |
| `aes128gcm`          | AEAD block (CTR)  | 128b | 96-bit | ✅ GCM         | Fastest, slightly > 256 | Same as above but you prefer a 128-bit key (marginally faster, still considered strong). |
| `xor`                | keystream obfusc. | 256b | 64-bit salt | ❌ none    | Near memcpy | **Not confidential.** Lightweight obfuscation / DPI shape-breaking only, or measuring tunnel throughput without crypto cost. Do **not** use where secrecy matters. |
| `none`               | plaintext         | —    | —      | ❌ none        | memcpy         | Debugging and development only. Packets travel in the clear. |

### How to read this table

- **AEAD** (Authenticated Encryption with Associated Data) means the cipher
  provides **confidentiality *and* integrity** in one pass. A tampered or
  forged frame fails the authentication tag and is silently discarded. All four
  AEAD options (`chacha20poly1305`, `xchacha20poly1305`, `aes256gcm`,
  `aes128gcm`) are suitable for real use. **Prefer these.**
- **ChaCha20 vs AES.** ChaCha20-Poly1305 is a software stream cipher that runs
  fast and in constant time on *every* CPU, with no special instructions. AES-GCM
  is faster *when* the CPU has AES-NI (most modern x86-64/ARMv8) but can be slower
  and more side-channel-sensitive in pure software. Rule of thumb: pick
  `aes256gcm` on a beefy server with AES-NI, pick `chacha20poly1305` on small
  ARM/edge devices or when unsure.
- **Nonce width matters.** CopyTunnel uses a fresh **random** nonce per frame.
  With a 96-bit nonce (ChaCha20-Poly1305, AES-GCM) random nonces are safe into
  the billions of frames per key, which is plenty for normal use. If you push
  enormous sustained packet rates and want an extra safety margin against the
  birthday bound, `xchacha20poly1305`'s 192-bit nonce removes the concern
  entirely.
- **`xor` and `none` are obfuscation/debug tools, not security.** `xor` applies
  a SHA-256-derived keystream so identical packets look different on the wire,
  but it provides **no authentication and no real confidentiality** — treat it as
  camouflage. `none` sends plaintext.

### Key derivation

- By default the 32-byte symmetric key is `SHA-256("copytunnel-kdf-v1" ‖ pre_shared_key)`.
- Set `key_hex` (64 hex chars = 32 bytes) to supply the key directly instead.
- `aes128gcm` uses the first 16 bytes of that key.
- Both sides **must** end up with the same key, cipher, and `obfuscate` setting,
  or every frame will fail to authenticate and the tunnel will appear silent.

### Optional obfuscation layer

`obfuscate = true` runs a deterministic, PSK-derived XOR mask over the **entire**
sealed frame (including the nonce). It adds no cryptographic strength — the AEAD
already provides that — but it removes the fixed structure a trivial classifier
might key on. Must match on both sides.

---

## 📥 Install & Build

### Requirements

| Requirement | Details |
|---|---|
| **OS**        | Linux (TUN + iptables). The data path is Linux-only. |
| **Privileges**| `CAP_NET_ADMIN` (+ `CAP_NET_RAW` not required). Run as root, or `setcap`. |
| **Rust**      | 1.74+ (edition 2021). |
| **Runtime deps** | `ip` (iproute2) and, for `auto_nat`, `iptables`. |

### Build from source

```bash
git clone https://github.com/Hiddify2/CopyTunnel
cd CopyTunnel

# Standard release build
cargo build --release

# Maximum performance (enables AES-NI / AVX2 / NEON on the build host;
# the resulting binary is not portable to older CPUs):
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The binary is `target/release/copytunnel`.

### Grant capabilities instead of running as root (optional)

```bash
sudo setcap cap_net_admin+ep ./target/release/copytunnel
```

---

## ▶️ Quick Start

Two hosts: a **server** with a public IP (say `203.0.113.10`) and a **client**.

### 1. Set a shared secret on both sides

Edit `config/server.toml` and `config/client.toml` and set the **same**
`pre_shared_key` and the **same** `encryption`. Point the client's
`server_addr` at the server.

### 2. Start the server

```bash
sudo ./target/release/copytunnel --config config/server.toml
```

With `auto_nat = true` it enables IP forwarding and installs the MASQUERADE rule
automatically (and removes them on Ctrl-C).

### 3. Start the client

```bash
sudo ./target/release/copytunnel --config config/client.toml
```

The client brings up `copy0` as a point-to-point link to the server's TUN IP.

### 4. Route the traffic you want to tunnel

CopyTunnel only moves packets that the kernel routes **into** `copy0`. You decide
what that is. Two common choices:

**a) Tunnel a specific destination** (safe, surgical):

```bash
# send traffic for 93.184.216.34 through the tunnel
sudo ip route add 93.184.216.34/32 dev copy0
```

**b) Tunnel everything** (full VPN-style default route). Keep a host route to the
server over your real gateway first so the tunnel itself doesn't loop:

```bash
sudo ip route add 203.0.113.10/32 via "$(ip route show default | awk '{print $3; exit}')"
sudo ip route add 0.0.0.0/1 dev copy0
sudo ip route add 128.0.0.0/1 dev copy0
```

Now test:

```bash
curl --interface copy0 https://example.com      # or just curl, with the default route in place
```

To restrict which ports are tunnelled at all, set `forward_ports` (e.g.
`[80, 443]`) in the client config; leave it empty to forward every port.

---

## 📋 Configuration Reference

Both configs share one schema; `role` selects the half that runs.

### Role & mode

| Field | Side | Default | Description |
|---|---|---|---|
| `role` | both | — | `"client"` or `"server"`. |
| `mode` | client | `tun` | `"tun"` (TUN method) or `"proxy"` (transparent-proxy method). Ignored on the server. |

### Transport — TUN method (UDP)

| Field | Side | Default | Description |
|---|---|---|---|
| `server_addr` | client | — | `IP:PORT` of the server's UDP listener. |
| `listen_addr` | server | `0.0.0.0:51822` | Local `IP:PORT` for the UDP (TUN) listener. Empty `""` disables it. |

### Transport — Proxy method (TCP)

| Field | Side | Default | Description |
|---|---|---|---|
| `proxy_server` | client | — | `IP:PORT` of the server's TCP proxy listener. |
| `proxy_listen` | server | `0.0.0.0:51823` | Local `IP:PORT` for the TCP proxy listener. Empty `""` disables it. |
| `socks_listen` | client | `127.0.0.1:1080` | Local SOCKS5 bind (sing-box's socks outbound dials this). |

> A server may enable **both** `listen_addr` and `proxy_listen` to serve TUN and
> proxy clients simultaneously with one key/cipher.

### Security

| Field | Side | Default | Description |
|---|---|---|---|
| `pre_shared_key` | both | — | Shared secret (≥16 chars). Derives the key. **Must match.** |
| `key_hex` | both | *(none)* | Optional explicit 32-byte key (64 hex chars). Overrides derivation. |
| `encryption` | both | `chacha20poly1305` | Wire cipher — see [Encryption Methods](#-encryption-methods). **Must match.** |
| `obfuscate` | both | `false` | Whole-frame XOR obfuscation layer. **Must match.** |

### Packet selection

| Field | Side | Default | Description |
|---|---|---|---|
| `forward_protocols` | both | `["tcp","udp"]` | IP protocols to tunnel; others dropped. |
| `forward_ports` | both | `[]` | Port allowlist (src OR dst). Empty = all ports. |

### TUN interface

| Field | Side | Default | Description |
|---|---|---|---|
| `tun_name` | both | `copy0` | TUN interface name. |
| `tun_ip` | both | — | This side's TUN address (**swap** between client/server). |
| `tun_peer_ip` | both | — | The other side's TUN address. |
| `tun_netmask` | both | `255.255.255.252` | `/30` point-to-point mask. |
| `mtu` | both | `1380` | Tunnel MTU (576–9000). Keep below path MTU minus overhead. |

### Networking & runtime

| Field | Side | Default | Description |
|---|---|---|---|
| `interface` | server | `eth0` | Physical NIC for the MASQUERADE rule. |
| `auto_nat` | server | `true` | Enable IP forwarding + install/remove NAT automatically. |
| `keepalive_secs` | client | `15` | Keepalive interval so the server knows the client's address. 0 = off. |
| `worker_threads` | both | `0` | Tokio worker threads. 0 = one per core. |
| `log_level` | both | `info` | `trace` · `debug` · `info` · `warn` · `error`. |

---

## 🧠 Operational Notes

| Rule | Detail |
|---|---|
| **Match both sides** | `pre_shared_key`/`key_hex`, `encryption`, and `obfuscate` must be identical, or all frames fail to authenticate. |
| **Swap TUN IPs** | The client's `tun_ip` is the server's `tun_peer_ip` and vice-versa. |
| **IPv4 only** | The tunnel forwards IPv4 TCP/UDP. IPv6 and other protocols are dropped at the TUN. |
| **MTU** | If you see stalls on large transfers, lower `mtu` (e.g. 1280). The tunnel adds nonce+tag overhead on top of your packet. |
| **NAT** | With `auto_nat = false`, set up `net.ipv4.ip_forward` and MASQUERADE yourself. |
| **Routing (TUN)** | CopyTunnel never changes your default route automatically. Nothing is tunnelled until you route it into `copy0`. |
| **Proxy = TCP** | The transparent-proxy method relays TCP. Tunnel UDP via the TUN method (a server can run both). |
| **Proxy bypass** | iptables rules auto-bypass loopback, private ranges, and the server IP. Add more via `Proxy → Add` (`/etc/copytunnel/bypass.list`). |
| **sing-box** | The installer downloads sing-box for proxy clients. It is only the transparent *ingress*; CopyTunnel does the encryption. |

---

## 🔒 Security Model (honest summary)

- **Confidentiality & integrity:** provided by the AEAD ciphers
  (`chacha20poly1305`, `xchacha20poly1305`, `aes256gcm`, `aes128gcm`). A static
  pre-shared key is used; there is **no forward secrecy** and no key rotation —
  compromise of the PSK compromises captured traffic. This is a simple,
  WireGuard-shaped data plane, not a full key-agreement protocol.
- **Authentication:** symmetric, via the shared key. Unauthenticated datagrams
  are dropped before reaching the TUN, which also shields the server from random
  internet scan traffic on the data port.
- **Replay:** not tracked. For most relay use this is acceptable; if you need
  anti-replay, terminate TLS/SSH *inside* the tunnel as usual.
- **`xor`/`none`:** obfuscation and debugging only — no security. Pick an AEAD
  cipher for anything real.

Use strong, random secrets:

```bash
# a good pre_shared_key
openssl rand -base64 48

# or a raw 32-byte key for key_hex
openssl rand -hex 32
```

---

## 🛠️ Manager & Files

The interactive manager (`scripts/menu.sh`, launched by `scripts/install.sh`)
is the recommended way to run everything — see [Quick Install](#-quick-install).
It installs to a predictable layout:

```
/usr/local/bin/copytunnel            ← the binary
/usr/local/bin/copytunnel-menu, ct   ← launch the manager
/opt/copytunnel/                     ← source + scripts
/etc/copytunnel/tun.toml             ← TUN method config
/etc/copytunnel/proxy.toml           ← Proxy method config
/etc/copytunnel/singbox.json         ← sing-box (proxy client) config
/etc/copytunnel/tproxy-up.sh / -down.sh  ← iptables TPROXY rules
/etc/copytunnel/bypass.list          ← direct-route bypass entries
/etc/systemd/system/copytunnel-tun.service
/etc/systemd/system/copytunnel-proxy.service
/etc/systemd/system/sing-box.service
/etc/systemd/system/copytunnel-tproxy.service
```

Manage services directly if you prefer:

```bash
systemctl status copytunnel-tun       # or copytunnel-proxy / sing-box / copytunnel-tproxy
journalctl -u copytunnel-proxy -f
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).

<div align="center">
<sub>Built in Rust · published by <a href="https://github.com/Hiddify2">Hiddify2</a></sub>
</div>
