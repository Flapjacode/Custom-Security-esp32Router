/*
 * vpn_wireguard.h
 * WireGuard VPN client wrapper using the WireGuard-ESP32 library by ciniml.
 * Library: https://github.com/ciniml/WireGuard-ESP32-Arduino
 * Install: Arduino Library Manager -> "WireGuard-ESP32"
 */

#pragma once
#include <Arduino.h>
#include <WireGuard-ESP32.h>
#include <WiFi.h>
#include "config.h"
#include "utils.h"

#define VPN_RECONNECT_INTERVAL_MS  30000
#define VPN_HANDSHAKE_TIMEOUT_MS   15000

class VPNWireGuard {
public:
  bool connected    = false;
  bool kill_switch_active = false;
  uint32_t tx_bytes = 0;
  uint32_t rx_bytes = 0;
  uint32_t last_handshake_ms = 0;

  void begin(RouterConfig &cfg);
  void tick();
  void stop();
  void reconnect();

  String status_json() const;

private:
  RouterConfig    *_cfg;
  WireGuard        _wg;
  bool             _started       = false;
  uint32_t         _last_attempt  = 0;
  uint32_t         _attempt_count = 0;

  bool start_tunnel();
  void apply_kill_switch(bool enable);
};
