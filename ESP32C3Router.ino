
/*
 * ESP32C3Router.ino
 * ESP32-C3 Super Mini + W5500 Full NAT Router
 *
 * Features: NAT, DHCP Server, Firewall, WireGuard VPN, AsyncWebServer UI
 *
 * W5500 SPI Pins (C3 Mini):
 *   MISO -> GPIO5
 *   MOSI -> GPIO6
 *   SCK  -> GPIO4
 *   CS   -> GPIO7
 *   RST  -> GPIO8   (optional but recommended)
 *   INT  -> GPIO9   (optional)
 *
 * WAN: W5500 Ethernet (connects to modem/switch)
 * LAN: ESP32-C3 internal WiFi AP (192.168.4.0/24 default)
 *
 * Framework: Arduino-ESP32 core v2.0+
 * Board:     ESP32C3 Dev Module (or "ESP32-C3 SuperMini")
 *
 * Required Libraries (Arduino Library Manager):
 *   - Ethernet (or EthernetLarge)        -> W5500 driver
 *   - ESPAsyncWebServer                  -> Web UI
 *   - AsyncTCP                           -> Required by ESPAsyncWebServer
 *   - ArduinoJson v6                     -> Config serialization
 *   - WireGuard-ESP32 by ciniml          -> WireGuard VPN
 *   - LittleFS (built into Arduino-ESP32 core)
 */

#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include <ETH.h>
#include <WireGuard-ESP32.h>
#include <Arduino.h>
#include <SPI.h>
#include <WiFi.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <ArduinoJson.hpp>


#include "config.h"
#include "wan_eth.h"
#include "nat.h"
#include "dhcp_server.h"
#include "firewall.h"
#include "vpn_wireguard.h"
#include "web_ui.h"
#include "utils.h"

// ── Global instances ──────────────────────────────────────────────────────────
RouterConfig  g_cfg;
WanEth        g_wan;
NATEngine     g_nat;
DHCPServer    g_dhcp;
Firewall      g_fw;
VPNWireGuard  g_vpn;
WebUI         g_webui;

// ── Setup ─────────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  delay(300);
  LOG_I("ESP32C3Router booting...");

  // Mount filesystem for config + web assets
  if (!LittleFS.begin(true)) {
    LOG_E("LittleFS mount failed");
  }

  // Load or create default config
  g_cfg.load();

  // Init W5500 WAN
  // g_wan.begin(g_cfg);

  // Init WiFi AP (LAN)
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(g_cfg.lan_ip, g_cfg.lan_ip, g_cfg.lan_mask);
  WiFi.softAP(g_cfg.wifi_ssid, g_cfg.wifi_pass, g_cfg.wifi_channel, 0, g_cfg.wifi_max_clients);
  LOG_I("WiFi AP: %s  IP: %s", g_cfg.wifi_ssid, g_cfg.lan_ip.toString().c_str());

  // Init subsystems
  g_dhcp.begin(g_cfg);
  g_fw.begin(g_cfg);
  // g_nat.begin(g_cfg, g_wan, g_fw);

  // VPN (only start if enabled in config)
  // if (g_cfg.vpn_enabled) {
  //   g_vpn.begin(g_cfg);
  // }

  // Web UI
  // g_webui.begin(g_cfg, g_wan, g_nat, g_dhcp, g_fw, g_vpn);

  LOG_I("Boot complete. Free heap: %u bytes", ESP.getFreeHeap());
}

// ── Loop ──────────────────────────────────────────────────────────────────────
void loop() {
  g_dhcp.tick();
  yield();


  // VPN keepalive / reconnect
  //if (g_cfg.vpn_enabled) g_vpn.tick();

  // WAN link monitoring
  //g_wan.tick();

}
