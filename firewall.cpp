/*
 * firewall.cpp
 */
#include "firewall.h"

// TCP flags bitmask
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_FIN  0x01

void Firewall::begin(const RouterConfig &cfg) {
  _cfg            = &cfg;
  _default_policy = cfg.fw_default_policy;
  _dos_protect    = cfg.fw_dos_protect;

  for (int i = 0; i < CT_TABLE_SIZE; i++) _ct[i].active = false;
  _syn_bucket  = {0, 0};
  _icmp_bucket = {0, 0};
  _log_head    = 0;
  _log_count   = 0;

  LOG_I("Firewall ready. Rules: %d  Default: %s  DoS: %s",
        cfg.fw_rule_count,
        cfg.fw_default_policy == FW_ACTION_DENY ? "DENY" : "ALLOW",
        cfg.fw_dos_protect ? "ON" : "OFF");
}

// ── evaluate (simple 3-tuple) ──────────────────────────────────────────────────
uint8_t Firewall::evaluate(uint8_t direction, uint8_t protocol,
                            uint32_t dst_ip, uint16_t dst_port) {
  return evaluate_full(direction, protocol, 0, 0, dst_ip, dst_port, 0);
}

// ── evaluate_full (5-tuple with CT + DoS) ─────────────────────────────────────
uint8_t Firewall::evaluate_full(uint8_t direction, uint8_t protocol,
                                 uint32_t src_ip, uint16_t src_port,
                                 uint32_t dst_ip, uint16_t dst_port,
                                 uint8_t tcp_flags) {
  // DoS protection
  if (_dos_protect) {
    if (protocol == FW_PROTO_TCP && (tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
      if (!dos_check_syn()) {
        log_drop(src_ip, dst_ip, dst_port, protocol, FW_ACTION_DENY);
        return FW_ACTION_DENY;
      }
    }
    if (protocol == FW_PROTO_ICMP) {
      if (!dos_check_icmp()) {
        log_drop(src_ip, dst_ip, dst_port, protocol, FW_ACTION_DENY);
        return FW_ACTION_DENY;
      }
    }
  }

  // Connection tracking: ESTABLISHED traffic always passes
  if (src_ip && (protocol == FW_PROTO_TCP || protocol == FW_PROTO_UDP)) {
    CTEntry *ct = ct_find(src_ip, src_port, dst_ip, dst_port, protocol);
    if (ct && ct->state == CT_STATE_ESTAB) {
      ct->last_seen_ms = millis();
      return FW_ACTION_ALLOW;
    }
  }

  // Evaluate user rules
  for (uint8_t i = 0; i < _cfg->fw_rule_count; i++) {
    const FWRule &r = _cfg->fw_rules[i];
    if (!r.enabled) continue;
    if (r.direction != FW_DIR_FORWARD && r.direction != direction) continue;
    if (r.protocol  != FW_PROTO_ANY   && r.protocol  != protocol)  continue;

    // Source IP match
    if (r.src_ip && src_ip) {
      if ((src_ip & r.src_mask) != (r.src_ip & r.src_mask)) continue;
    }

    // Destination IP match
    if (r.dst_ip) {
      if ((dst_ip & r.dst_mask) != (r.dst_ip & r.dst_mask)) continue;
    }

    // Destination port range match
    if (r.dst_port_min) {
      uint16_t hi = r.dst_port_max ? r.dst_port_max : r.dst_port_min;
      if (dst_port < r.dst_port_min || dst_port > hi) continue;
    }

    // Match!
    if (r.log_match) log_drop(src_ip, dst_ip, dst_port, protocol, r.action);
    if (r.action != FW_ACTION_ALLOW) {
      log_drop(src_ip, dst_ip, dst_port, protocol, r.action);
    }
    return r.action;
  }

  if (_default_policy != FW_ACTION_ALLOW) {
    log_drop(src_ip, dst_ip, dst_port, protocol, _default_policy);
  }
  return _default_policy;
}

// ── update_ct ─────────────────────────────────────────────────────────────────
void Firewall::update_ct(uint8_t protocol,
                          uint32_t src_ip, uint16_t src_port,
                          uint32_t dst_ip, uint16_t dst_port,
                          uint8_t tcp_flags) {
  expire_ct();

  CTEntry *existing = ct_find(src_ip, src_port, dst_ip, dst_port, protocol);

  if (protocol == FW_PROTO_TCP) {
    if (tcp_flags & TCP_FLAG_RST) {
      if (existing) existing->active = false;
      return;
    }
    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
      // New connection
      if (!existing) existing = ct_alloc();
      if (!existing) return;
      existing->src_ip    = src_ip;
      existing->src_port  = src_port;
      existing->dst_ip    = dst_ip;
      existing->dst_port  = dst_port;
      existing->protocol  = protocol;
      existing->state     = CT_STATE_NEW;
      existing->last_seen_ms = millis();
      existing->active    = true;
      return;
    }
    if ((tcp_flags & TCP_FLAG_ACK) && existing && existing->state == CT_STATE_NEW) {
      existing->state = CT_STATE_ESTAB;
      existing->last_seen_ms = millis();
      return;
    }
    if ((tcp_flags & TCP_FLAG_FIN) && existing) {
      existing->state = CT_STATE_CLOSING;
      existing->last_seen_ms = millis();
      return;
    }
  } else if (protocol == FW_PROTO_UDP) {
    if (!existing) {
      existing = ct_alloc();
      if (!existing) return;
      existing->src_ip    = src_ip;
      existing->src_port  = src_port;
      existing->dst_ip    = dst_ip;
      existing->dst_port  = dst_port;
      existing->protocol  = protocol;
      existing->active    = true;
    }
    existing->state        = CT_STATE_ESTAB;
    existing->last_seen_ms = millis();
  }
}

// ── ct_active_count ───────────────────────────────────────────────────────────
uint32_t Firewall::ct_active_count() const {
  uint32_t n = 0;
  for (int i = 0; i < CT_TABLE_SIZE; i++) if (_ct[i].active) n++;
  return n;
}

// ── get_log_entry ─────────────────────────────────────────────────────────────
String Firewall::get_log_entry(uint8_t idx) const {
  if (idx >= _log_count) return "";
  const LogEntry &e = _log[idx];
  char buf[80];
  snprintf(buf, sizeof(buf), "[%lu] %s %u.%u.%u.%u -> %u.%u.%u.%u:%u proto=%u",
    (unsigned long)e.ts_ms,
    e.action == FW_ACTION_ALLOW ? "ALLOW" : "DROP",
    (unsigned)(e.src_ip>>24),(unsigned)((e.src_ip>>16)&0xFF),
    (unsigned)((e.src_ip>>8)&0xFF),(unsigned)(e.src_ip&0xFF),
    (unsigned)(e.dst_ip>>24),(unsigned)((e.dst_ip>>16)&0xFF),
    (unsigned)((e.dst_ip>>8)&0xFF),(unsigned)(e.dst_ip&0xFF),
    e.dst_port, e.protocol);
  return String(buf);
}

// ── DoS helpers ───────────────────────────────────────────────────────────────
bool Firewall::dos_check_syn() {
  uint32_t now = millis();
  if (now - _syn_bucket.window_start_ms > DOS_WINDOW_MS) {
    _syn_bucket.count = 0;
    _syn_bucket.window_start_ms = now;
  }
  _syn_bucket.count++;
  return (_syn_bucket.count <= DOS_SYN_THRESHOLD);
}

bool Firewall::dos_check_icmp() {
  uint32_t now = millis();
  if (now - _icmp_bucket.window_start_ms > DOS_WINDOW_MS) {
    _icmp_bucket.count = 0;
    _icmp_bucket.window_start_ms = now;
  }
  _icmp_bucket.count++;
  return (_icmp_bucket.count <= DOS_ICMP_THRESHOLD);
}

// ── CT helpers ────────────────────────────────────────────────────────────────
CTEntry* Firewall::ct_find(uint32_t src_ip, uint16_t src_port,
                            uint32_t dst_ip, uint16_t dst_port, uint8_t proto) {
  for (int i = 0; i < CT_TABLE_SIZE; i++) {
    CTEntry &e = _ct[i];
    if (!e.active) continue;
    if (e.src_ip   == src_ip   && e.src_port == src_port &&
        e.dst_ip   == dst_ip   && e.dst_port == dst_port &&
        e.protocol == proto) return &e;
    // Also match reverse direction
    if (e.src_ip   == dst_ip   && e.src_port == dst_port &&
        e.dst_ip   == src_ip   && e.dst_port == src_port &&
        e.protocol == proto) return &e;
  }
  return nullptr;
}

CTEntry* Firewall::ct_alloc() {
  // Find free or oldest entry
  uint32_t oldest_ms = UINT32_MAX;
  int oldest_i = -1;
  for (int i = 0; i < CT_TABLE_SIZE; i++) {
    if (!_ct[i].active) return &_ct[i];
    if (_ct[i].last_seen_ms < oldest_ms) {
      oldest_ms = _ct[i].last_seen_ms;
      oldest_i  = i;
    }
  }
  if (oldest_i >= 0) { _ct[oldest_i].active = false; return &_ct[oldest_i]; }
  return nullptr;
}

void Firewall::expire_ct() {
  static uint32_t last_expire = 0;
  if (millis() - last_expire < 5000) return;
  last_expire = millis();
  uint32_t now = millis();
  for (int i = 0; i < CT_TABLE_SIZE; i++) {
    if (!_ct[i].active) continue;
    uint32_t ttl = (_ct[i].protocol == FW_PROTO_TCP) ? 120000UL : 30000UL;
    if (now - _ct[i].last_seen_ms > ttl) _ct[i].active = false;
  }
}

void Firewall::log_drop(uint32_t src_ip, uint32_t dst_ip,
                         uint16_t dst_port, uint8_t proto, uint8_t action) {
  LogEntry &e = _log[_log_head % LOG_SIZE];
  e.src_ip   = src_ip;
  e.dst_ip   = dst_ip;
  e.dst_port = dst_port;
  e.protocol = proto;
  e.action   = action;
  e.ts_ms    = millis();
  _log_head  = (_log_head + 1) % LOG_SIZE;
  if (_log_count < LOG_SIZE) _log_count++;
}
