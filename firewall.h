/*
 * firewall.h
 * Stateful-capable packet filter for ESP32-C3.
 * 20 configurable rules + connection tracking for TCP (SYN/SYN-ACK/RST).
 * DoS protection: SYN flood + ICMP flood rate limiting.
 */

#pragma once
#include <Arduino.h>
#include <IPAddress.h>
#include "config.h"
#include "utils.h"

// Connection tracking entry
#define CT_TABLE_SIZE   256

#define CT_STATE_NEW     0
#define CT_STATE_ESTAB   1
#define CT_STATE_CLOSING 2

struct CTEntry {
  uint32_t src_ip;
  uint16_t src_port;
  uint32_t dst_ip;
  uint16_t dst_port;
  uint8_t  protocol;
  uint8_t  state;
  uint32_t last_seen_ms;
  bool     active;
};

// DoS rate limit buckets
#define DOS_SYN_THRESHOLD   20   // SYNs/sec before blocking
#define DOS_ICMP_THRESHOLD  50   // ICMPs/sec before blocking
#define DOS_WINDOW_MS       1000

struct DoSBucket {
  uint32_t count;
  uint32_t window_start_ms;
};

class Firewall {
public:
  void begin(const RouterConfig &cfg);

  // Evaluate a packet. Returns FW_ACTION_ALLOW / DENY / REJECT
  uint8_t evaluate(uint8_t direction, uint8_t protocol,
                   uint32_t dst_ip, uint16_t dst_port);

  // Evaluate with full 5-tuple (enables connection tracking)
  uint8_t evaluate_full(uint8_t direction, uint8_t protocol,
                        uint32_t src_ip, uint16_t src_port,
                        uint32_t dst_ip, uint16_t dst_port,
                        uint8_t tcp_flags = 0);

  void     update_ct(uint8_t protocol,
                     uint32_t src_ip, uint16_t src_port,
                     uint32_t dst_ip, uint16_t dst_port,
                     uint8_t tcp_flags);

  uint8_t  get_default_policy() const { return _default_policy; }
  uint32_t ct_active_count() const;

  // Log ring buffer access
  String   get_log_entry(uint8_t idx) const;
  uint8_t  log_count() const { return _log_count; }

private:
  RouterConfig const *_cfg;
  uint8_t  _default_policy;
  bool     _dos_protect;

  // Connection tracking table
  CTEntry  _ct[CT_TABLE_SIZE];

  // DoS rate limiters
  DoSBucket _syn_bucket;
  DoSBucket _icmp_bucket;

  // Simple log ring (last 16 blocked packets)
  struct LogEntry {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  action;
    uint32_t ts_ms;
  };
  static const uint8_t LOG_SIZE = 16;
  LogEntry _log[LOG_SIZE];
  uint8_t  _log_head  = 0;
  uint8_t  _log_count = 0;

  bool     dos_check_syn();
  bool     dos_check_icmp();
  CTEntry* ct_find(uint32_t src_ip, uint16_t src_port,
                   uint32_t dst_ip, uint16_t dst_port, uint8_t proto);
  CTEntry* ct_alloc();
  void     expire_ct();
  void     log_drop(uint32_t src_ip, uint32_t dst_ip,
                    uint16_t dst_port, uint8_t proto, uint8_t action);
};
