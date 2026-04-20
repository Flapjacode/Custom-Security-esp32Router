/*
 * vpn_wireguard.cpp
 */
#include "vpn_wireguard.h"

void VPNWireGuard::begin(RouterConfig &cfg) {
  _cfg     = &cfg;
  _started = false;
  connected = false;

  if (!cfg.vpn_enabled) return;
  if (cfg.vpn_server[0] == '\0' || cfg.vpn_privkey[0] == '\0') {
    LOG_W("VPN: missing server or private key, not starting");
    return;
  }

  LOG_I("VPN: Starting WireGuard tunnel to %s:%u", cfg.vpn_server, cfg.vpn_port);
  start_tunnel();
}

bool VPNWireGuard::start_tunnel() {
  _last_attempt  = millis();
  _attempt_count++;

  // Configure the WireGuard interface
  // WireGuard-ESP32 library API:
  //   wg.begin(local_ip, private_key, server_addr, server_pubkey, server_port)
  //   Optional: set PSK via wg.set_preshared_key()
  //   Optional: allowed IPs via wg.set_allowed_ip()

  // Parse tunnel IP (strip /prefix if present)
  char tunnel_ip_str[16] = "";
  strncpy(tunnel_ip_str, _cfg->vpn_tunnel_ip, sizeof(tunnel_ip_str));
  char *slash = strchr(tunnel_ip_str, '/');
  if (slash) *slash = '\0';

  IPAddress tunnel_ip;
  if (!tunnel_ip.fromString(tunnel_ip_str)) {
    LOG_E("VPN: Invalid tunnel IP: %s", _cfg->vpn_tunnel_ip);
    return false;
  }

  // The WireGuard-ESP32 library uses the C API under the hood.
  // begin() takes: (local_ip, private_key_b64, server_addr, public_key_b64, port)
  bool ok = _wg.begin(
    tunnel_ip,
    _cfg->vpn_privkey,
    _cfg->vpn_server,
    _cfg->vpn_pubkey,
    _cfg->vpn_port
  );

  if (ok) {
    _started  = true;
    connected = true;
    last_handshake_ms = millis();
    LOG_I("VPN: Tunnel UP  IP=%s", tunnel_ip_str);

    // Apply kill switch if configured
    if (_cfg->vpn_kill_switch) apply_kill_switch(true);
  } else {
    _started  = false;
    connected = false;
    LOG_E("VPN: Tunnel start failed (attempt %u)", _attempt_count);
  }

  return ok;
}

void VPNWireGuard::tick() {
  if (!_cfg->vpn_enabled) return;

  // Reconnect logic
  if (!connected) {
    if (millis() - _last_attempt > VPN_RECONNECT_INTERVAL_MS) {
      LOG_I("VPN: Reconnecting...");
      if (_started) { _wg.end(); _started = false; }
      start_tunnel();
    }

    // Kill switch: block WAN traffic while VPN is down
    if (_cfg->vpn_kill_switch && !kill_switch_active) {
      apply_kill_switch(true);
    }
    return;
  }

  // Check for handshake timeout (WireGuard re-handshakes every 180s)
  // If no handshake in VPN_HANDSHAKE_TIMEOUT_MS we consider the tunnel dead.
  if (millis() - last_handshake_ms > VPN_HANDSHAKE_TIMEOUT_MS * 6) {
    LOG_W("VPN: Handshake timeout, reconnecting");
    connected = false;
    if (_started) { _wg.end(); _started = false; }
    return;
  }

  // Update stats from WireGuard library (if available in library version)
  // _wg.get_stats(tx_bytes, rx_bytes);
  // last_handshake_ms updated by library callback
  last_handshake_ms = millis(); // placeholder; replace with real WG stat if available
}

void VPNWireGuard::stop() {
  if (_started) {
    _wg.end();
    _started  = false;
    connected = false;
  }
  if (kill_switch_active) apply_kill_switch(false);
  LOG_I("VPN: Stopped");
}

void VPNWireGuard::reconnect() {
  stop();
  delay(500);
  start_tunnel();
}

// ── Kill switch ────────────────────────────────────────────────────────────────
// Kill switch blocks all outbound traffic on the WAN interface
// when the VPN tunnel is down, preventing IP leaks.
// On ESP32 we achieve this by adding a firewall rule or by
// controlling the W5500 CS pin (hardware approach).
// Here we use a software flag that the Firewall module checks.
void VPNWireGuard::apply_kill_switch(bool enable) {
  kill_switch_active = enable;
  LOG_I("VPN kill switch: %s", enable ? "ACTIVE (blocking WAN)" : "RELEASED");
  // The NAT engine checks g_vpn.kill_switch_active before forwarding WAN packets.
}

// ── status_json ───────────────────────────────────────────────────────────────
String VPNWireGuard::status_json() const {
  char buf[256];
  snprintf(buf, sizeof(buf),
    "{\"enabled\":%s,\"connected\":%s,\"server\":\"%s\",\"port\":%u,"
    "\"tunnel_ip\":\"%s\",\"kill_switch\":%s,\"kill_switch_active\":%s,"
    "\"tx_bytes\":%lu,\"rx_bytes\":%lu,\"last_handshake_ms\":%lu}",
    _cfg->vpn_enabled ? "true" : "false",
    connected ? "true" : "false",
    _cfg->vpn_server,
    _cfg->vpn_port,
    _cfg->vpn_tunnel_ip,
    _cfg->vpn_kill_switch ? "true" : "false",
    kill_switch_active ? "true" : "false",
    (unsigned long)tx_bytes,
    (unsigned long)rx_bytes,
    (unsigned long)last_handshake_ms
  );
  return String(buf);
}
