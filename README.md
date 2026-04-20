# Custom-Security-esp32Router

## 🔐 Security Purpose (OPSEC Focus)

This project is designed to address emerging wireless privacy threats related to Wi-Fi signal exploitation, including techniques often referred to as **Wi-Fi sensing**, **RF imaging**, or attacks like **Wi-Peep**.

### 🧠 The Threat

Modern research has shown that Wi-Fi signals can be used for more than just communication. By analyzing how wireless signals interact with physical environments and devices, an attacker may be able to:

- Detect **presence and movement** through walls
- Infer **device locations** without joining a network
- Perform **low-resolution environmental sensing**, similar to a “radio-based camera”
- Exploit **802.11 protocol behaviors** to trigger responses from devices

These attacks do not require traditional network access and can operate passively or semi-passively, making them difficult to detect with conventional security tools.

---

### 🛡️ Project Goal

This ESP32-based router project aims to provide a **lightweight, deployable defense layer** against these threats by:

- Monitoring wireless and network behavior
- Detecting unusual or suspicious traffic patterns
- Reducing unnecessary signal leakage and response behavior
- Acting as a **privacy-aware gateway** between devices and external networks

---

### ⚙️ Core Security Concepts

- **Minimize signal exposure**  
  Reduce unnecessary responses that can be used for device fingerprinting or localization.

- **Detect probing and scanning behavior**  
  Identify abnormal traffic patterns that may indicate reconnaissance or sensing attempts.

- **Segment and control traffic flow**  
  Use NAT, firewall rules, and isolation to limit visibility into internal devices.

- **Optional VPN tunneling (WireGuard)**  
  Prevent external observers from correlating traffic with physical presence.

---

## The goal:
To create a **plug-and-play OPSEC router** that helps protect users from emerging side-channel and RF-based privacy attacks—turning inexpensive hardware into a proactive privacy defense system.

---


# ESP32Router

**ESP32-C3 Super Mini + W5500** — Full NAT Router with WireGuard VPN, DHCP, Firewall, and a modern Web UI.

---

## File Structure

```
ESP32C3Router/
├── ESP32C3Router.ino       ← Main sketch
├── config.h / .cpp         ← LittleFS JSON config
├── wan_eth.h / .cpp        ← W5500 WAN driver
├── nat.h / .cpp            ← NAT/PAT engine (512 sessions)
├── firewall.h / .cpp       ← Stateful firewall + CT + DoS protection
├── dhcp_server.h / .cpp    ← Full RFC 2131 DHCP server
├── vpn_wireguard.h / .cpp  ← WireGuard VPN client
├── web_ui.h / .cpp         ← ESPAsyncWebServer REST API
├── utils.h                 ← Logging macros
└── data/
    └── www/
        └── index.html      ← SPA dashboard (upload to LittleFS)
```

---

## Hardware Wiring

### W5500 ↔ ESP32-C3 Super Mini

| W5500 Pin | C3 Mini GPIO | Notes              |
|-----------|--------------|--------------------|
| MISO      | GPIO5        | SPI                |
| MOSI      | GPIO6        | SPI                |
| SCK       | GPIO4        | SPI                |
| CS        | GPIO7        | SPI CS             |
| RST       | GPIO8        | Optional but recommended |
| INT       | GPIO9        | Optional            |
| VCC       | 3.3V         |                    |
| GND       | GND          |                    |

---

## Arduino IDE Setup

### 1. Board

- **Board**: `ESP32C3 Dev Module`  
  *(or "ESP32-C3 SuperMini" if you have that package)*
- **CPU Frequency**: 160 MHz
- **Flash Size**: 4MB (32Mb)
- **Partition Scheme**: `Default 4MB with spiffs` ← **important for LittleFS**
- **Upload Speed**: 921600

### 2. Required Libraries (Sketch → Manage Libraries)

| Library | Author | Purpose |
|---------|--------|---------|
| `Ethernet` | Arduino | W5500 driver |
| `ESPAsyncWebServer` | ESP Async | Web server |
| `AsyncTCP` | dvarrel / ESP Async | Required by AsyncWebServer |
| `ArduinoJson` v6 | Benoit Blanchon | JSON config |
| `WireGuard-ESP32` | ciniml | WireGuard VPN |

> `LittleFS` is built into the Arduino-ESP32 core (v2.0+), no install needed.

### 3. Upload Filesystem (Web UI + Config)

The `data/www/index.html` must be uploaded to LittleFS:

1. Install **ESP32 LittleFS Data Upload** plugin:  
   - Arduino IDE 1.x: [arduino-esp32fs-plugin](https://github.com/lorol/arduino-esp32fs-plugin)  
   - Arduino IDE 2.x: Use [Arduino IDE 2 LittleFS uploader](https://github.com/earlephilhower/arduino-littlefs-upload)
2. Place your `data/` folder inside the sketch folder.
3. In Arduino IDE: **Tools → ESP32 LittleFS Data Upload**

### 4. Compile & Flash

```
Tools → Board    → ESP32C3 Dev Module
Tools → Partition → Default 4MB with spiffs
Sketch → Upload
```

---

## Defaults (all configurable via Web UI or `/config.json`)

| Parameter     | Default          |
|---------------|------------------|
| WiFi SSID     | `ESP32Router`    |
| WiFi Password | `router1234`     |
| LAN IP        | `192.168.4.1`    |
| DHCP Pool     | `192.168.4.10–50`|
| Web UI Port   | `80`             |
| Web Username  | `admin`          |
| Web Password  | `admin`          |
| WAN           | DHCP             |

---

## Web UI

Access at `http://192.168.4.1` from a WiFi client:

| Page      | Description                                |
|-----------|--------------------------------------------|
| Overview  | Live stats: WAN IP, clients, NAT, heap     |
| WAN       | DHCP/static WAN settings                  |
| LAN/WiFi  | AP SSID, password, channel, client limit  |
| DHCP      | Pool, lease time, active lease table       |
| Firewall  | Rule management, connection log            |
| NAT Table | Live session table + stats, flush button  |
| Port Fwd  | DNAT / port forwarding rules               |
| WireGuard | VPN config, connect/disconnect, kill switch|
| System    | Chip info, reboot, factory reset           |

---

## REST API

All routes under `/api/*` — HTTP Basic Auth required.

```
GET  /api/status
GET  /api/wan        POST /api/wan
GET  /api/lan        POST /api/lan
GET  /api/dhcp/leases
GET  /api/dhcp/config POST /api/dhcp/config
GET  /api/fw/rules   POST /api/fw/add
DELETE /api/fw/rule?id=N
GET  /api/fw/log
GET  /api/nat/table  GET /api/nat/stats  POST /api/nat/flush
GET  /api/vpn/status POST /api/vpn/config
POST /api/vpn/connect   POST /api/vpn/disconnect
GET  /api/portfwd    POST /api/portfwd
GET  /api/sysinfo
POST /api/reboot     POST /api/factory
```

---

## Memory Budget (ESP32-C3, 400KB SRAM)

| Component          | ~Heap   |
|--------------------|---------|
| NAT table (512)    | ~14 KB  |
| CT table (256)     | ~8 KB   |
| DHCP leases (50)   | ~3 KB   |
| Config struct      | ~1 KB   |
| FW rules (20)      | ~1 KB   |
| WiFi + lwIP stack  | ~90 KB  |
| AsyncWebServer     | ~30 KB  |
| WireGuard          | ~40 KB  |
| **Available free** | **~220 KB** |

---

## WireGuard Key Generation

Generate keys with the `wg` CLI tool:

```bash
wg genkey | tee private.key | wg pubkey > public.key
cat private.key   # paste into "Private Key" field
cat public.key    # share with VPN server as peer public key
```

Or use [WireGuard app](https://www.wireguard.com/) to generate a tunnel config, then copy the keys.

---

## Known Limitations

- **TCP NAT** uses application-layer socket pairs; full kernel-level IP forwarding would require lwIP netif hooks with esp-netif internals.  
- **UDP throughput** bottlenecked by W5500 SPI at ~10 MHz (target ~30–50 Mbps for small packets, less for large).  
- **WireGuard** performance ~10–15 Mbps on C3 at 160 MHz (no hardware AES, but Zinc crypto is fast).  
- **Web UI** auth is HTTP Basic — add HTTPS if exposing to WAN.

---

## Clearing Config

To wipe config and revert to defaults, POST to `/api/factory` or delete `/config.json` from LittleFS.


### Note

This project is intended for **defensive security, research, and privacy protection**.  
It does not perform or promote offensive RF sensing or surveillance techniques.
Customize your privacy from attackers and your ISP with ESP-Router. Consumer Wi-Fi can leak occupancy, motion, and device-location information through protocol behavior and radio reflections, enabling a low-resolution form of environmental sensing even without a conventional camera. Monitor, Manage, and prevent suspicious activity on your network .
