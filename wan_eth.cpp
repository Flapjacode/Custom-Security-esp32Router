/*
 * wan_eth.cpp
 */
#include "wan_eth.h"

void WanEth::begin(RouterConfig &cfg) {
  _cfg = &cfg;

  // Init SPI with explicit C3 Mini pins
  SPI.begin(W5500_SCK_PIN, W5500_MISO_PIN, W5500_MOSI_PIN, W5500_CS_PIN);

  // Hardware reset W5500
  hw_reset();

  Ethernet.init(W5500_CS_PIN);

  bool ok = false;
  if (cfg.wan_dhcp) {
    ok = init_dhcp();
    if (!ok) {
      LOG_W("WAN DHCP failed, falling back to static IP");
      init_static();
    }
  } else {
    init_static();
    ok = true;
  }

  current_ip  = Ethernet.localIP();
  current_gw  = Ethernet.gatewayIP();
  current_dns = Ethernet.dnsServerIP();
  link_up     = (current_ip != IPAddress(0,0,0,0));

  LOG_I("WAN IP: %s  GW: %s  DNS: %s",
        current_ip.toString().c_str(),
        current_gw.toString().c_str(),
        current_dns.toString().c_str());

  // Open UDP socket on a fixed port for NAT inbound
  _udp.begin(0); // port 0 = OS assigns; NAT will bind specific ports per session
}

void WanEth::tick() {
  uint32_t now = millis();
  if (now - _last_link_check < WAN_LINK_CHECK_INTERVAL_MS) return;
  _last_link_check = now;

  // Renew DHCP lease
  if (_cfg->wan_dhcp) {
    int res = Ethernet.maintain();
    if (res == 1 || res == 3) { // renewed or rebind
      current_ip  = Ethernet.localIP();
      current_gw  = Ethernet.gatewayIP();
      current_dns = Ethernet.dnsServerIP();
      LOG_I("DHCP renewed: %s", current_ip.toString().c_str());
    }
  }

  // Link detection via W5500 PHYCFGR register (chip-specific check)
  bool new_link = (Ethernet.localIP() != IPAddress(0,0,0,0));
  if (new_link != link_up) {
    link_up = new_link;
    LOG_I("WAN link %s", link_up ? "UP" : "DOWN");
  }
}

void WanEth::hw_reset() {
  if (W5500_RST_PIN < 0) return;
  pinMode(W5500_RST_PIN, OUTPUT);
  digitalWrite(W5500_RST_PIN, LOW);
  delay(50);
  digitalWrite(W5500_RST_PIN, HIGH);
  delay(200);
}

bool WanEth::init_dhcp() {
  LOG_I("WAN: Starting DHCP...");
  int result = Ethernet.begin(_cfg->wan_mac, 10000, 4000);
  _dhcp_active = (result == 1);
  return _dhcp_active;
}

void WanEth::init_static() {
  LOG_I("WAN: Static IP %s", _cfg->wan_ip.toString().c_str());
  Ethernet.begin(_cfg->wan_mac, _cfg->wan_ip, _cfg->wan_dns1,
                 _cfg->wan_gw, _cfg->wan_mask);
}
