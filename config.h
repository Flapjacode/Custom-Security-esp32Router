/*
 * config.h
 * Router configuration stored as JSON in LittleFS at /config.json
 * Falls back to compiled-in defaults on first boot or corrupt config.
 */

#pragma once
#include <Arduino.h>
#include <IPAddress.h>
#include <ArduinoJson.h>
#include <LittleFS.h>
#include "utils.h"

#define CONFIG_PATH       "/config.json"
#define CONFIG_JSON_SIZE  2048

// ── Firewall rule (up to MAX_FW_RULES) ────────────────────────────────────────
#define MAX_FW_RULES  20

#define FW_ACTION_ALLOW  0
#define FW_ACTION_DENY   1
#define FW_ACTION_REJECT 2

#define FW_DIR_IN      0
#define FW_DIR_OUT     1
#define FW_DIR_FORWARD 2

#define FW_PROTO_ANY   0
#define FW_PROTO_TCP   6
#define FW_PROTO_UDP   17
#define FW_PROTO_ICMP  1

struct FWRule {
  bool     enabled       = true;
  uint8_t  action        = FW_ACTION_ALLOW;
  uint8_t  direction     = FW_DIR_FORWARD;
  uint8_t  protocol      = FW_PROTO_ANY;
  uint32_t src_ip        = 0;       // 0 = any
  uint32_t src_mask      = 0;
  uint32_t dst_ip        = 0;       // 0 = any
  uint32_t dst_mask      = 0;
  uint16_t dst_port_min  = 0;       // 0 = any
  uint16_t dst_port_max  = 0;
  bool     log_match     = false;
};

// ── Port forwarding rule ──────────────────────────────────────────────────────
#define MAX_PORT_FWD_RULES 10

struct PortFwdRule {
  bool     enabled      = false;
  uint8_t  protocol     = FW_PROTO_TCP;
  uint16_t ext_port     = 0;
  uint32_t int_ip       = 0;
  uint16_t int_port     = 0;
};

// ── Main config struct ────────────────────────────────────────────────────────
struct RouterConfig {
  // ── WAN ───────────────────────────────────────────────────────────────────
  bool      wan_dhcp        = true;
  IPAddress wan_ip          = IPAddress(192, 168, 1, 2);
  IPAddress wan_mask        = IPAddress(255, 255, 255, 0);
  IPAddress wan_gw          = IPAddress(192, 168, 1, 1);
  IPAddress wan_dns1        = IPAddress(8, 8, 8, 8);
  IPAddress wan_dns2        = IPAddress(8, 8, 4, 4);
  uint8_t   wan_mac[6]      = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};

  // ── LAN / WiFi AP ─────────────────────────────────────────────────────────
  IPAddress lan_ip          = IPAddress(192, 168, 4, 1);
  IPAddress lan_mask        = IPAddress(255, 255, 255, 0);
  char      wifi_ssid[33]   = "ESP32Router";
  char      wifi_pass[65]   = "router1234";
  uint8_t   wifi_channel    = 6;
  uint8_t   wifi_max_clients = 8;

  // ── DHCP ──────────────────────────────────────────────────────────────────
  bool      dhcp_enabled    = true;
  IPAddress dhcp_start      = IPAddress(192, 168, 4, 10);
  IPAddress dhcp_end        = IPAddress(192, 168, 4, 50);
  uint32_t  dhcp_lease_sec  = 3600;
  char      dhcp_domain[32] = "lan";

  // ── Firewall ──────────────────────────────────────────────────────────────
  uint8_t   fw_default_policy = FW_ACTION_ALLOW;
  bool      fw_dos_protect    = true;
  bool      fw_wan_admin      = false;   // allow Web UI from WAN
  FWRule    fw_rules[MAX_FW_RULES];
  uint8_t   fw_rule_count     = 0;

  // ── Port forwarding ───────────────────────────────────────────────────────
  PortFwdRule port_fwd[MAX_PORT_FWD_RULES];
  uint8_t     port_fwd_count = 0;

  // ── WireGuard VPN ─────────────────────────────────────────────────────────
  bool      vpn_enabled         = false;
  char      vpn_server[64]      = "";
  uint16_t  vpn_port            = 51820;
  char      vpn_privkey[48]     = "";   // base64 private key
  char      vpn_pubkey[48]      = "";   // peer public key
  char      vpn_psk[48]         = "";   // preshared key (optional)
  char      vpn_tunnel_ip[20]   = "";   // e.g. "10.0.0.2/24"
  char      vpn_dns[16]         = "";   // VPN DNS override
  bool      vpn_kill_switch     = false;
  bool      vpn_split_tunnel    = false;
  char      vpn_allowed_ips[64] = "0.0.0.0/0";  // full tunnel default

  // ── Web UI ────────────────────────────────────────────────────────────────
  uint16_t  web_port    = 80;
  char      web_user[32] = "admin";
  char      web_pass[32] = "admin";
  bool      web_https   = false;

  // ── Methods ───────────────────────────────────────────────────────────────
  void load();
  void save();
  void defaults();

  // Serialization helpers
  String wan_ip_str()    const { return wan_ip.toString(); }
  String lan_ip_str()    const { return lan_ip.toString(); }
  String dhcp_start_str()const { return dhcp_start.toString(); }
  String dhcp_end_str()  const { return dhcp_end.toString(); }
};
