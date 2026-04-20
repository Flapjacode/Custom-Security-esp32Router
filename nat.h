/*
 * nat.h
 * Full NAT/PAT engine for ESP32-C3.
 * Uses lwIP hooks + WiFi AP + W5500 for packet bridging.
 *
 * Strategy:
 *   LAN (WiFi AP) clients send packets through the ESP32-C3 WiFi stack.
 *   lwIP netif input/output hooks intercept packets on the AP interface.
 *   NAT rewrites src IP:port -> WAN IP:mapped_port before forwarding to W5500.
 *   Inbound WAN replies are reverse-mapped and injected back into the AP netif.
 *
 * NAT table: 512 entries, 28 bytes each = ~14KB heap (well within 400KB budget)
 * Port range: 10000-10511 (one per slot)
 *
 * Port forwarding: up to MAX_PORT_FWD_RULES static DNAT rules.
 */

#pragma once
#include <Arduino.h>
#include <IPAddress.h>
#include <WiFi.h>
#include <Ethernet.h>
#include "config.h"
#include "firewall.h"
#include "wan_eth.h"
#include "utils.h"

// lwIP raw API
extern "C" {
  #include "lwip/netif.h"
  #include "lwip/pbuf.h"
  #include "lwip/ip4.h"
  #include "lwip/tcp.h"
  #include "lwip/udp.h"
}

#define NAT_TABLE_SIZE    512
#define NAT_PORT_BASE     10000
#define NAT_TCP_TTL_SEC   120
#define NAT_UDP_TTL_SEC   30
#define NAT_ICMP_TTL_SEC  10

// Packet buffer for WAN->LAN forwarding
#define NAT_PKT_BUF_SIZE  1500

struct NATEntry {
  uint32_t lan_ip;
  uint16_t lan_port;
  uint16_t wan_port;       // mapped external port
  uint32_t dst_ip;
  uint16_t dst_port;
  uint8_t  protocol;       // FW_PROTO_TCP / UDP / ICMP
  uint32_t last_seen_ms;
  bool     active;
};

// Per-protocol counters for monitoring
struct NATStats {
  uint32_t pkts_lan_to_wan  = 0;
  uint32_t pkts_wan_to_lan  = 0;
  uint32_t pkts_dropped_fw  = 0;
  uint32_t pkts_dropped_nat = 0;
  uint32_t bytes_tx         = 0;
  uint32_t bytes_rx         = 0;
  uint32_t active_entries   = 0;
};

class NATEngine {
public:
  NATStats stats;

  void begin(RouterConfig &cfg, WanEth &wan, Firewall &fw);
  void tick();   // expire entries, poll WAN inbound, update stats

  // Outbound: LAN client -> WAN. Returns mapped WAN port or 0 on fail.
  uint16_t map_outbound(uint32_t lan_ip, uint16_t lan_port,
                        uint32_t dst_ip, uint16_t dst_port,
                        uint8_t protocol);

  // Inbound: WAN reply -> LAN. Returns true + fills out_* if mapping found.
  bool reverse_lookup(uint16_t wan_port, uint8_t protocol,
                      uint32_t &out_lan_ip, uint16_t &out_lan_port);

  // DNAT port forward lookup: returns true + fills int_ip/int_port
  bool portfwd_lookup(uint16_t ext_port, uint8_t protocol,
                      uint32_t &int_ip, uint16_t &int_port);

  uint32_t active_count();
  void     flush();

  NATEntry entries[NAT_TABLE_SIZE];

private:
  RouterConfig *_cfg;
  WanEth       *_wan;
  Firewall     *_fw;

  NATEntry* find_existing(uint32_t lan_ip, uint16_t lan_port,
                           uint32_t dst_ip, uint16_t dst_port, uint8_t proto);
  NATEntry* find_free_slot(uint8_t &out_idx);
  uint32_t  ttl_for(uint8_t proto) const;
  void      expire_entries();
  void      poll_wan_inbound();
  void      forward_to_lan(uint32_t lan_ip, uint16_t lan_port,
                            const uint8_t *data, uint16_t len);
};
