/*
 * nat.cpp
 * NAT/PAT engine using lwIP netif hooks on the WiFi AP interface
 * and EthernetClient/UDP on the W5500 WAN interface.
 *
 * lwIP hook approach:
 *   esp_netif provides access to the underlying lwIP netif.
 *   We register a custom input function on the AP netif that
 *   intercepts outbound packets before they leave the AP interface,
 *   rewrites the src IP/port, and sends them via W5500.
 *
 *   For the inbound path we poll W5500 sockets and inject packets
 *   back into the AP netif via netif->input().
 */
#include "nat.h"

// ── begin ──────────────────────────────────────────────────────────────────────
void NATEngine::begin(RouterConfig &cfg, WanEth &wan, Firewall &fw) {
  _cfg = &cfg;
  _wan = &wan;
  _fw  = &fw;

  for (int i = 0; i < NAT_TABLE_SIZE; i++) entries[i].active = false;
  memset(&stats, 0, sizeof(stats));

  LOG_I("NAT engine ready. Table size: %d entries", NAT_TABLE_SIZE);
}

// ── tick ───────────────────────────────────────────────────────────────────────
void NATEngine::tick() {
  expire_entries();
  poll_wan_inbound();

  // Update active count for stats
  uint32_t cnt = 0;
  for (int i = 0; i < NAT_TABLE_SIZE; i++) if (entries[i].active) cnt++;
  stats.active_entries = cnt;
}

// ── map_outbound ───────────────────────────────────────────────────────────────
uint16_t NATEngine::map_outbound(uint32_t lan_ip, uint16_t lan_port,
                                  uint32_t dst_ip, uint16_t dst_port,
                                  uint8_t protocol) {
  // Check firewall (outbound)
  if (_fw->evaluate(FW_DIR_OUT, protocol, dst_ip, dst_port) != FW_ACTION_ALLOW) {
    stats.pkts_dropped_fw++;
    return 0;
  }

  // Check existing mapping
  NATEntry *existing = find_existing(lan_ip, lan_port, dst_ip, dst_port, protocol);
  if (existing) {
    existing->last_seen_ms = millis();
    return existing->wan_port;
  }

  // Allocate new slot
  uint8_t idx = 0;
  NATEntry *slot = find_free_slot(idx);
  if (!slot) {
    stats.pkts_dropped_nat++;
    LOG_W("NAT table full!");
    return 0;
  }

  slot->lan_ip       = lan_ip;
  slot->lan_port     = lan_port;
  slot->wan_port     = NAT_PORT_BASE + idx;
  slot->dst_ip       = dst_ip;
  slot->dst_port     = dst_port;
  slot->protocol     = protocol;
  slot->last_seen_ms = millis();
  slot->active       = true;

  stats.pkts_lan_to_wan++;
  return slot->wan_port;
}

// ── reverse_lookup ─────────────────────────────────────────────────────────────
bool NATEngine::reverse_lookup(uint16_t wan_port, uint8_t protocol,
                                uint32_t &out_lan_ip, uint16_t &out_lan_port) {
  for (int i = 0; i < NAT_TABLE_SIZE; i++) {
    NATEntry &e = entries[i];
    if (!e.active) continue;
    if (e.wan_port == wan_port && e.protocol == protocol) {
      e.last_seen_ms = millis();
      out_lan_ip     = e.lan_ip;
      out_lan_port   = e.lan_port;
      stats.pkts_wan_to_lan++;
      return true;
    }
  }
  return false;
}

// ── portfwd_lookup ─────────────────────────────────────────────────────────────
bool NATEngine::portfwd_lookup(uint16_t ext_port, uint8_t protocol,
                                uint32_t &int_ip, uint16_t &int_port) {
  for (uint8_t i = 0; i < _cfg->port_fwd_count; i++) {
    const PortFwdRule &r = _cfg->port_fwd[i];
    if (!r.enabled) continue;
    if (r.ext_port == ext_port && r.protocol == protocol) {
      int_ip   = r.int_ip;
      int_port = r.int_port;
      return true;
    }
  }
  return false;
}

// ── active_count ───────────────────────────────────────────────────────────────
uint32_t NATEngine::active_count() {
  return stats.active_entries;
}

// ── flush ─────────────────────────────────────────────────────────────────────
void NATEngine::flush() {
  for (int i = 0; i < NAT_TABLE_SIZE; i++) entries[i].active = false;
  memset(&stats, 0, sizeof(stats));
  LOG_I("NAT table flushed");
}

// ── find_existing ──────────────────────────────────────────────────────────────
NATEntry* NATEngine::find_existing(uint32_t lan_ip, uint16_t lan_port,
                                    uint32_t dst_ip, uint16_t dst_port,
                                    uint8_t proto) {
  for (int i = 0; i < NAT_TABLE_SIZE; i++) {
    NATEntry &e = entries[i];
    if (!e.active) continue;
    if (e.lan_ip   == lan_ip   && e.lan_port  == lan_port &&
        e.dst_ip   == dst_ip   && e.dst_port  == dst_port &&
        e.protocol == proto) return &e;
  }
  return nullptr;
}

// ── find_free_slot ─────────────────────────────────────────────────────────────
NATEntry* NATEngine::find_free_slot(uint8_t &out_idx) {
  // LRU eviction if all slots full
  uint32_t oldest_ms = UINT32_MAX;
  int oldest_i = -1;

  for (int i = 0; i < NAT_TABLE_SIZE; i++) {
    if (!entries[i].active) {
      out_idx = (uint8_t)(i % 256);
      return &entries[i];
    }
    if (entries[i].last_seen_ms < oldest_ms) {
      oldest_ms = entries[i].last_seen_ms;
      oldest_i  = i;
    }
  }

  // Evict oldest
  if (oldest_i >= 0) {
    entries[oldest_i].active = false;
    out_idx = (uint8_t)(oldest_i % 256);
    return &entries[oldest_i];
  }
  return nullptr;
}

// ── ttl_for ────────────────────────────────────────────────────────────────────
uint32_t NATEngine::ttl_for(uint8_t proto) const {
  switch (proto) {
    case FW_PROTO_TCP:  return NAT_TCP_TTL_SEC  * 1000UL;
    case FW_PROTO_UDP:  return NAT_UDP_TTL_SEC  * 1000UL;
    case FW_PROTO_ICMP: return NAT_ICMP_TTL_SEC * 1000UL;
    default:            return NAT_UDP_TTL_SEC  * 1000UL;
  }
}

// ── expire_entries ─────────────────────────────────────────────────────────────
void NATEngine::expire_entries() {
  uint32_t now = millis();
  for (int i = 0; i < NAT_TABLE_SIZE; i++) {
    NATEntry &e = entries[i];
    if (!e.active) continue;
    if ((now - e.last_seen_ms) > ttl_for(e.protocol)) {
      e.active = false;
    }
  }
}

// ── poll_wan_inbound ───────────────────────────────────────────────────────────
/*
 * Checks W5500 UDP socket for inbound packets on mapped ports.
 * For each packet: reverse-maps to LAN IP:port, checks firewall,
 * then injects into the WiFi AP client's TCP/UDP socket.
 *
 * Full kernel-level IP forwarding (lwIP netif hooks) requires esp-netif
 * internal access; this implementation uses the socket API approach
 * which works at the application layer for UDP. TCP requires persistent
 * EthernetClient + WiFiClient pair per NAT session.
 */
void NATEngine::poll_wan_inbound() {
  EthernetUDP &udp = _wan->udp_socket();

  int pkt_size = udp.parsePacket();
  if (pkt_size <= 0) return;

  // Which local port did it arrive on?
  uint16_t local_port = udp.localPort();
  uint8_t  proto      = FW_PROTO_UDP;

  // Check port forward first (DNAT)
  uint32_t int_ip; uint16_t int_port;
  if (portfwd_lookup(local_port, proto, int_ip, int_port)) {
    static uint8_t rx_buf[NAT_PKT_BUF_SIZE];
    uint16_t n = udp.read(rx_buf, sizeof(rx_buf));
    if (_fw->evaluate(FW_DIR_IN, proto, int_ip, int_port) == FW_ACTION_ALLOW) {
      forward_to_lan(int_ip, int_port, rx_buf, n);
      stats.bytes_rx += n;
    } else {
      stats.pkts_dropped_fw++;
    }
    return;
  }

  // Standard NAT reverse lookup
  uint32_t lan_ip; uint16_t lan_port;
  if (!reverse_lookup(local_port, proto, lan_ip, lan_port)) {
    // Unsolicited packet - check firewall default policy
    while (udp.available()) udp.read();
    stats.pkts_dropped_nat++;
    return;
  }

  if (_fw->evaluate(FW_DIR_IN, proto, lan_ip, lan_port) != FW_ACTION_ALLOW) {
    while (udp.available()) udp.read();
    stats.pkts_dropped_fw++;
    return;
  }

  static uint8_t rx_buf[NAT_PKT_BUF_SIZE];
  uint16_t n = udp.read(rx_buf, sizeof(rx_buf));
  forward_to_lan(lan_ip, lan_port, rx_buf, n);
  stats.bytes_rx += n;
}

// ── forward_to_lan ─────────────────────────────────────────────────────────────
void NATEngine::forward_to_lan(uint32_t lan_ip, uint16_t lan_port,
                                const uint8_t *data, uint16_t len) {
  WiFiUDP udp_lan;
  IPAddress dest(lan_ip >> 24, (lan_ip>>16)&0xFF, (lan_ip>>8)&0xFF, lan_ip&0xFF);
  if (udp_lan.beginPacket(dest, lan_port)) {
    udp_lan.write(data, len);
    udp_lan.endPacket();
  }
}
