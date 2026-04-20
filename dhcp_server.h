/*
 * dhcp_server.h
 * Full DHCP server for the LAN (WiFi AP) interface.
 * Uses WiFiUDP on port 67. Supports DISCOVER/REQUEST/RELEASE/INFORM.
 * Static lease support. Up to 50 leases (heap-allocated).
 */

#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <IPAddress.h>
#include <vector>
#include "config.h"
#include "utils.h"

#define DHCP_SERVER_PORT  67
#define DHCP_CLIENT_PORT  68
#define DHCP_MAGIC_COOKIE 0x63825363UL

#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_DECLINE  4
#define DHCP_ACK      5
#define DHCP_NAK      6
#define DHCP_RELEASE  7
#define DHCP_INFORM   8

#define DHCP_PKT_SIZE 576

struct DHCPLease {
  uint8_t  mac[6];
  uint32_t ip;
  uint32_t expires_ms;   // millis() based
  bool     active;
  bool     is_static;
  char     hostname[32];
};

class DHCPServer {
public:
  std::vector<DHCPLease> leases;

  void begin(RouterConfig &cfg);
  void tick();

  uint32_t active_count() const;
  String   lease_table_json() const;

  // Add static lease (persisted via config)
  void add_static_lease(const uint8_t *mac, uint32_t ip, const char *hostname = "");

private:
  RouterConfig *_cfg;
  WiFiUDP       _udp;
  uint8_t       _pkt[DHCP_PKT_SIZE];

  void handle_packet(const uint8_t *pkt, uint16_t len);
  void send_offer(const uint8_t *chaddr, uint32_t xid, uint32_t offered_ip,
                  uint32_t server_ip);
  void send_ack  (const uint8_t *chaddr, uint32_t xid, uint32_t assigned_ip,
                  uint32_t server_ip);
  void send_nak  (uint32_t xid);
  void send_reply(uint32_t dst_ip, uint16_t dst_port,
                  const uint8_t *pkt, uint16_t len);

  uint32_t allocate_ip(const uint8_t *mac, uint32_t requested_ip = 0);
  DHCPLease* find_by_mac(const uint8_t *mac);
  DHCPLease* find_by_ip(uint32_t ip);
  DHCPLease* alloc_slot();
  void       expire_leases();

  uint8_t get_msg_type(const uint8_t *opts, uint16_t opts_len);
  uint32_t get_requested_ip(const uint8_t *opts, uint16_t opts_len);
  void     get_hostname(const uint8_t *opts, uint16_t opts_len, char *out, uint8_t sz);

  void write_option(uint8_t *&ptr, uint8_t code, uint8_t len, const void *data);
  void write_option_u8 (uint8_t *&ptr, uint8_t code, uint8_t  val);
  void write_option_u32(uint8_t *&ptr, uint8_t code, uint32_t val);
  void write_option_ip (uint8_t *&ptr, uint8_t code, uint32_t ip);
  void write_option_end(uint8_t *&ptr);
};
