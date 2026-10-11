<div align="center">

# 📦 CopyTunnel

**An encrypted layer-3 tunnel that copies every TCP/UDP packet from the client, encrypts it, and relays it through a server to its real destination — and back.**

<p>
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square" alt="Linux">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/ciphers-6-green?style=flat-square" alt="Ciphers">
</p>

<p>
  <a href="#-how-it-works">How It Works</a> ·
  <a href="#-encryption-methods">Encryption Methods</a> ·
  <a href="#-install--build">Install</a> ·
  <a href="#-quick-start">Quick Start</a> ·
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

CopyTunnel is a **point-to-point encrypted tunnel** built in Rust. It is a
layer-3 (IP) tunnel in the same family as WireGuard or a classic IPsec road-warrior
setup, with a deliberately simple design:

1. On the **client**, a virtual `TUN` interface captures the IP packets your
   applications send. CopyTunnel reads each packet, keeps only TCP and UDP
   (configurable), and **encrypts the whole packet** with the cipher you chose.
2. The encrypted frame is sent to the **server** over a single UDP data channel.
3. The server **decrypts** it and writes the original packet into its own TUN
   interface. The Linux kernel then **routes and NATs** it to the real
   destination on the internet.
4. Replies walk the same path in reverse: the server captures them, encrypts
   them, and relays them back to the client, which decrypts and delivers them to
   the application.

To the application it is transparent. To anyone watching the link between client
and server, it is a stream of opaque, authenticated UDP datagrams.

The TUN handling, point-to-point addressing, port-forward filtering, and the
TOML configuration layout follow the model of
[CandyTunnel](https://github.com/AmiRCandy/CandyTunnel); CopyTunnel keeps that
operational shape but replaces the transport with a straightforward
**encrypt → relay → decrypt → deliver** copy path and a menu of modern ciphers.

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

### Transport

| Field | Side | Default | Description |
|---|---|---|---|
| `role` | both | — | `"client"` or `"server"`. |
| `server_addr` | client | — | `IP:PORT` of the server's UDP listener. |
| `listen_addr` | server | `0.0.0.0:51822` | Local `IP:PORT` to receive client datagrams. |

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
| **Routing is yours** | CopyTunnel never changes your default route automatically. Nothing is tunnelled until you route it into `copy0`. |

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

## 🛠️ Manager Script

`scripts/copytunnel.sh` wraps build, config generation, and `systemd` service
management:

```bash
sudo bash scripts/copytunnel.sh install        # build + install binary
sudo bash scripts/copytunnel.sh service server # create & start a systemd unit
sudo bash scripts/copytunnel.sh status
sudo bash scripts/copytunnel.sh logs
```

See the script header for all subcommands.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

<div align="center">
<sub>Built in Rust · published by <a href="https://github.com/Hiddify2">Hiddify2</a></sub>
</div>
