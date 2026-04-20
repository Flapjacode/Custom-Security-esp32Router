/*
 * dhcp_server.cpp
 */
#include "dhcp_server.h"
#include <ArduinoJson.h>

// DHCP fixed-field offsets
#define OFF_OP      0
#define OFF_XID     4
#define OFF_FLAGS   10
#define OFF_CIADDR  12
#define OFF_YIADDR  16
#define OFF_SIADDR  20
#define OFF_GIADDR  24
#define OFF_CHADDR  28
#define OFF_SNAME   44
#define OFF_FILE    108
#define OFF_OPTIONS 236

static uint32_t ip_to_u32(IPAddress ip) {
  return ((uint32_t)ip[0]<<24)|((uint32_t)ip[1]<<16)|((uint32_t)ip[2]<<8)|ip[3];
}
static IPAddress u32_to_ip(uint32_t ip) {
  return IPAddress(ip>>24,(ip>>16)&0xFF,(ip>>8)&0xFF,ip&0xFF);
}

void DHCPServer::begin(RouterConfig &cfg) {
  _cfg = &cfg;
  leases.reserve(50);
  _udp.begin(DHCP_SERVER_PORT);
  LOG_I("DHCP server started on port %d", DHCP_SERVER_PORT);
}

void DHCPServer::tick() {
  expire_leases();

  int pkt_size = _udp.parsePacket();
  if (pkt_size <= 0) return;
  if (pkt_size > DHCP_PKT_SIZE) pkt_size = DHCP_PKT_SIZE;

  int n = _udp.read(_pkt, pkt_size);
  if (n > 0) handle_packet(_pkt, (uint16_t)n);
}

void DHCPServer::handle_packet(const uint8_t *pkt, uint16_t len) {
  if (len < OFF_OPTIONS + 4) return;
  if (pkt[OFF_OP] != 1) return; // BOOTREQUEST only

  // Verify magic cookie
  uint32_t cookie = ((uint32_t)pkt[OFF_OPTIONS]<<24)|((uint32_t)pkt[OFF_OPTIONS+1]<<16)
                   |((uint32_t)pkt[OFF_OPTIONS+2]<<8)|pkt[OFF_OPTIONS+3];
  if (cookie != DHCP_MAGIC_COOKIE) return;

  uint32_t xid = ((uint32_t)pkt[OFF_XID]<<24)|((uint32_t)pkt[OFF_XID+1]<<16)
                |((uint32_t)pkt[OFF_XID+2]<<8)|pkt[OFF_XID+3];
  const uint8_t *chaddr = pkt + OFF_CHADDR;

  const uint8_t *opts    = pkt + OFF_OPTIONS + 4;
  uint16_t       opts_len = len - OFF_OPTIONS - 4;

  uint8_t  msg_type   = get_msg_type(opts, opts_len);
  uint32_t req_ip     = get_requested_ip(opts, opts_len);
  char     hostname[32]; hostname[0] = '\0';
  get_hostname(opts, opts_len, hostname, sizeof(hostname));

  uint32_t server_ip = ip_to_u32(_cfg->lan_ip);

  switch (msg_type) {
    case DHCP_DISCOVER: {
      uint32_t offered = allocate_ip(chaddr, req_ip);
      if (offered) {
        LOG_I("DHCP OFFER %u.%u.%u.%u -> %02X:%02X:%02X:%02X:%02X:%02X",
              offered>>24,(offered>>16)&0xFF,(offered>>8)&0xFF,offered&0xFF,
              chaddr[0],chaddr[1],chaddr[2],chaddr[3],chaddr[4],chaddr[5]);
        send_offer(chaddr, xid, offered, server_ip);
      }
      break;
    }
    case DHCP_REQUEST: {
      uint32_t assigned = allocate_ip(chaddr, req_ip);
      if (assigned) {
        DHCPLease *l = find_by_mac(chaddr);
        if (!l) l = alloc_slot();
        if (l) {
          memcpy(l->mac, chaddr, 6);
          l->ip         = assigned;
          l->expires_ms = millis() + _cfg->dhcp_lease_sec * 1000UL;
          l->active     = true;
          strlcpy(l->hostname, hostname, sizeof(l->hostname));
        }
        send_ack(chaddr, xid, assigned, server_ip);
      } else {
        send_nak(xid);
      }
      break;
    }
    case DHCP_RELEASE: {
      DHCPLease *l = find_by_mac(chaddr);
      if (l && !l->is_static) l->active = false;
      break;
    }
    case DHCP_INFORM: {
      // ACK with no IP assignment
      uint32_t ci = ((uint32_t)pkt[OFF_CIADDR]<<24)|((uint32_t)pkt[OFF_CIADDR+1]<<16)
                   |((uint32_t)pkt[OFF_CIADDR+2]<<8)|pkt[OFF_CIADDR+3];
      send_ack(chaddr, xid, ci, server_ip);
      break;
    }
    default: break;
  }
}

void DHCPServer::send_offer(const uint8_t *chaddr, uint32_t xid, uint32_t offered_ip,
                             uint32_t server_ip) {
  static uint8_t reply[DHCP_PKT_SIZE];
  memset(reply, 0, sizeof(reply));

  reply[OFF_OP]   = 2; // BOOTREPLY
  reply[OFF_OP+1] = 1; // HTYPE ethernet
  reply[OFF_OP+2] = 6; // HLEN
  reply[OFF_XID]   = (xid>>24)&0xFF; reply[OFF_XID+1] = (xid>>16)&0xFF;
  reply[OFF_XID+2] = (xid>>8)&0xFF;  reply[OFF_XID+3] =  xid&0xFF;

  reply[OFF_YIADDR]   = (offered_ip>>24)&0xFF;
  reply[OFF_YIADDR+1] = (offered_ip>>16)&0xFF;
  reply[OFF_YIADDR+2] = (offered_ip>>8)&0xFF;
  reply[OFF_YIADDR+3] =  offered_ip&0xFF;

  reply[OFF_SIADDR]   = (server_ip>>24)&0xFF;
  reply[OFF_SIADDR+1] = (server_ip>>16)&0xFF;
  reply[OFF_SIADDR+2] = (server_ip>>8)&0xFF;
  reply[OFF_SIADDR+3] =  server_ip&0xFF;

  memcpy(reply + OFF_CHADDR, chaddr, 6);

  // Options
  uint8_t *p = reply + OFF_OPTIONS;
  *p++ = 0x63; *p++ = 0x82; *p++ = 0x53; *p++ = 0x63; // magic cookie

  write_option_u8 (p, 53, DHCP_OFFER);                   // message type
  write_option_ip (p, 54, server_ip);                     // server id
  write_option_u32(p, 51, _cfg->dhcp_lease_sec);          // lease time
  write_option_u32(p, 58, _cfg->dhcp_lease_sec / 2);      // renewal time
  write_option_u32(p, 59, _cfg->dhcp_lease_sec * 7 / 8);  // rebind time

  uint32_t mask = ip_to_u32(_cfg->lan_mask);
  write_option_ip(p, 1, mask);                            // subnet mask
  write_option_ip(p, 3, server_ip);                       // router
  uint32_t dns1 = ip_to_u32(_cfg->wan_dns1);
  uint32_t dns2 = ip_to_u32(_cfg->wan_dns2);
  uint8_t dns_data[8] = {
    (uint8_t)(dns1>>24),(uint8_t)((dns1>>16)&0xFF),(uint8_t)((dns1>>8)&0xFF),(uint8_t)(dns1&0xFF),
    (uint8_t)(dns2>>24),(uint8_t)((dns2>>16)&0xFF),(uint8_t)((dns2>>8)&0xFF),(uint8_t)(dns2&0xFF)
  };
  write_option(p, 6, 8, dns_data);                        // DNS
  if (_cfg->dhcp_domain[0]) {
    write_option(p, 15, strlen(_cfg->dhcp_domain), _cfg->dhcp_domain);
  }
  write_option_end(p);

  uint16_t reply_len = (uint16_t)(p - reply);
  send_reply(0xFFFFFFFF, DHCP_CLIENT_PORT, reply, reply_len);
}

void DHCPServer::send_ack(const uint8_t *chaddr, uint32_t xid, uint32_t assigned_ip,
                           uint32_t server_ip) {
  static uint8_t reply[DHCP_PKT_SIZE];
  memset(reply, 0, sizeof(reply));

  reply[OFF_OP]   = 2;
  reply[OFF_OP+1] = 1;
  reply[OFF_OP+2] = 6;
  reply[OFF_XID]   = (xid>>24)&0xFF; reply[OFF_XID+1] = (xid>>16)&0xFF;
  reply[OFF_XID+2] = (xid>>8)&0xFF;  reply[OFF_XID+3] =  xid&0xFF;
  reply[OFF_YIADDR]   = (assigned_ip>>24)&0xFF;
  reply[OFF_YIADDR+1] = (assigned_ip>>16)&0xFF;
  reply[OFF_YIADDR+2] = (assigned_ip>>8)&0xFF;
  reply[OFF_YIADDR+3] =  assigned_ip&0xFF;
  reply[OFF_SIADDR]   = (server_ip>>24)&0xFF;
  reply[OFF_SIADDR+1] = (server_ip>>16)&0xFF;
  reply[OFF_SIADDR+2] = (server_ip>>8)&0xFF;
  reply[OFF_SIADDR+3] =  server_ip&0xFF;
  memcpy(reply + OFF_CHADDR, chaddr, 6);

  uint8_t *p = reply + OFF_OPTIONS;
  *p++ = 0x63; *p++ = 0x82; *p++ = 0x53; *p++ = 0x63;

  write_option_u8 (p, 53, DHCP_ACK);
  write_option_ip (p, 54, server_ip);
  write_option_u32(p, 51, _cfg->dhcp_lease_sec);
  write_option_u32(p, 58, _cfg->dhcp_lease_sec / 2);
  write_option_u32(p, 59, _cfg->dhcp_lease_sec * 7 / 8);
  uint32_t mask = ip_to_u32(_cfg->lan_mask);
  write_option_ip(p, 1, mask);
  write_option_ip(p, 3, server_ip);
  uint32_t dns1 = ip_to_u32(_cfg->wan_dns1);
  uint8_t dns_data[4] = {(uint8_t)(dns1>>24),(uint8_t)((dns1>>16)&0xFF),(uint8_t)((dns1>>8)&0xFF),(uint8_t)(dns1&0xFF)};
  write_option(p, 6, 4, dns_data);
  if (_cfg->dhcp_domain[0]) write_option(p, 15, strlen(_cfg->dhcp_domain), _cfg->dhcp_domain);
  write_option_end(p);

  send_reply(0xFFFFFFFF, DHCP_CLIENT_PORT, reply, (uint16_t)(p - reply));
}

void DHCPServer::send_nak(uint32_t xid) {
  static uint8_t reply[300];
  memset(reply, 0, sizeof(reply));
  reply[OFF_OP] = 2;
  reply[OFF_XID]   = (xid>>24)&0xFF; reply[OFF_XID+1] = (xid>>16)&0xFF;
  reply[OFF_XID+2] = (xid>>8)&0xFF;  reply[OFF_XID+3] =  xid&0xFF;
  uint8_t *p = reply + OFF_OPTIONS;
  *p++ = 0x63; *p++ = 0x82; *p++ = 0x53; *p++ = 0x63;
  write_option_u8(p, 53, DHCP_NAK);
  write_option_end(p);
  send_reply(0xFFFFFFFF, DHCP_CLIENT_PORT, reply, (uint16_t)(p - reply));
}

void DHCPServer::send_reply(uint32_t dst_ip, uint16_t dst_port,
                             const uint8_t *pkt, uint16_t len) {
  IPAddress dest = (dst_ip == 0xFFFFFFFF) ? IPAddress(255,255,255,255) : u32_to_ip(dst_ip);
  _udp.beginPacket(dest, dst_port);
  _udp.write(pkt, len);
  _udp.endPacket();
}

uint32_t DHCPServer::allocate_ip(const uint8_t *mac, uint32_t requested_ip) {
  // Check static lease first
  for (auto &l : leases) {
    if (l.is_static && memcmp(l.mac, mac, 6) == 0) return l.ip;
  }
  // Check existing dynamic lease
  DHCPLease *existing = find_by_mac(mac);
  if (existing && existing->active) return existing->ip;

  // Try requested IP first
  uint32_t start = ip_to_u32(_cfg->dhcp_start);
  uint32_t end   = ip_to_u32(_cfg->dhcp_end);

  if (requested_ip && requested_ip >= start && requested_ip <= end) {
    if (!find_by_ip(requested_ip)) return requested_ip;
  }

  // Sequential allocation
  for (uint32_t candidate = start; candidate <= end; candidate++) {
    if (!find_by_ip(candidate)) return candidate;
  }
  LOG_W("DHCP pool exhausted");
  return 0;
}

DHCPLease* DHCPServer::find_by_mac(const uint8_t *mac) {
  for (auto &l : leases) if (l.active && memcmp(l.mac, mac, 6) == 0) return &l;
  return nullptr;
}
DHCPLease* DHCPServer::find_by_ip(uint32_t ip) {
  for (auto &l : leases) if (l.active && l.ip == ip) return &l;
  return nullptr;
}
DHCPLease* DHCPServer::alloc_slot() {
  for (auto &l : leases) if (!l.active) return &l;
  leases.push_back(DHCPLease{});
  return &leases.back();
}

void DHCPServer::expire_leases() {
  uint32_t now = millis();
  for (auto &l : leases) {
    if (l.active && !l.is_static && now > l.expires_ms) {
      l.active = false;
    }
  }
}

uint32_t DHCPServer::active_count() const {
  uint32_t n = 0;
  for (const auto &l : leases) if (l.active) n++;
  return n;
}

String DHCPServer::lease_table_json() const {
  String json = "[";
  bool first = true;
  for (const auto &l : leases) {
    if (!l.active) continue;
    if (!first) json += ",";
    first = false;
    char mac[18], ip[16];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             l.mac[0],l.mac[1],l.mac[2],l.mac[3],l.mac[4],l.mac[5]);
    snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
             l.ip>>24,(l.ip>>16)&0xFF,(l.ip>>8)&0xFF,l.ip&0xFF);
    uint32_t rem = (l.expires_ms > millis()) ? (l.expires_ms - millis()) / 1000 : 0;
    json += "{\"mac\":\""; json += mac;
    json += "\",\"ip\":\""; json += ip;
    json += "\",\"hostname\":\""; json += l.hostname;
    json += "\",\"ttl\":"; json += rem;
    json += ",\"static\":"; json += l.is_static ? "true" : "false";
    json += "}";
  }
  json += "]";
  return json;
}

void DHCPServer::add_static_lease(const uint8_t *mac, uint32_t ip, const char *hostname) {
  DHCPLease *l = alloc_slot();
  if (!l) return;
  memcpy(l->mac, mac, 6);
  l->ip        = ip;
  l->active    = true;
  l->is_static = true;
  l->expires_ms = 0;
  strlcpy(l->hostname, hostname ? hostname : "", sizeof(l->hostname));
}

// ── Option helpers ────────────────────────────────────────────────────────────
void DHCPServer::write_option(uint8_t *&ptr, uint8_t code, uint8_t len, const void *data) {
  *ptr++ = code; *ptr++ = len;
  memcpy(ptr, data, len); ptr += len;
}
void DHCPServer::write_option_u8(uint8_t *&ptr, uint8_t code, uint8_t val) {
  write_option(ptr, code, 1, &val);
}
void DHCPServer::write_option_u32(uint8_t *&ptr, uint8_t code, uint32_t val) {
  uint8_t b[4] = {(uint8_t)(val>>24),(uint8_t)((val>>16)&0xFF),(uint8_t)((val>>8)&0xFF),(uint8_t)(val&0xFF)};
  write_option(ptr, code, 4, b);
}
void DHCPServer::write_option_ip(uint8_t *&ptr, uint8_t code, uint32_t ip) {
  write_option_u32(ptr, code, ip);
}
void DHCPServer::write_option_end(uint8_t *&ptr) { *ptr++ = 255; }

// ── Options parser helpers ────────────────────────────────────────────────────
uint8_t DHCPServer::get_msg_type(const uint8_t *opts, uint16_t opts_len) {
  uint16_t i = 0;
  while (i < opts_len) {
    uint8_t code = opts[i++];
    if (code == 255) break;
    if (code == 0) continue;
    if (i >= opts_len) break;
    uint8_t len = opts[i++];
    if (code == 53 && len == 1) return opts[i];
    i += len;
  }
  return 0;
}
uint32_t DHCPServer::get_requested_ip(const uint8_t *opts, uint16_t opts_len) {
  uint16_t i = 0;
  while (i < opts_len) {
    uint8_t code = opts[i++];
    if (code == 255) break;
    if (code == 0) continue;
    if (i >= opts_len) break;
    uint8_t len = opts[i++];
    if (code == 50 && len == 4) {
      return ((uint32_t)opts[i]<<24)|((uint32_t)opts[i+1]<<16)|((uint32_t)opts[i+2]<<8)|opts[i+3];
    }
    i += len;
  }
  return 0;
}
void DHCPServer::get_hostname(const uint8_t *opts, uint16_t opts_len, char *out, uint8_t sz) {
  uint16_t i = 0;
  while (i < opts_len) {
    uint8_t code = opts[i++];
    if (code == 255) break;
    if (code == 0) continue;
    if (i >= opts_len) break;
    uint8_t len = opts[i++];
    if (code == 12) {
      uint8_t n = min(len, (uint8_t)(sz - 1));
      memcpy(out, opts + i, n);
      out[n] = '\0';
      return;
    }
    i += len;
  }
  out[0] = '\0';
}
