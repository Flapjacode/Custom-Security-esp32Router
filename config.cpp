/*
 * config.cpp
 */
#include "config.h"

static IPAddress parse_ip(const char *s) {
  IPAddress ip;
  ip.fromString(s);
  return ip;
}

// ── defaults ──────────────────────────────────────────────────────────────────
void RouterConfig::defaults() {
  wan_dhcp   = true;
  wan_ip     = IPAddress(192, 168, 1, 2);
  wan_mask   = IPAddress(255, 255, 255, 0);
  wan_gw     = IPAddress(192, 168, 1, 1);
  wan_dns1   = IPAddress(8, 8, 8, 8);
  wan_dns2   = IPAddress(8, 8, 4, 4);
  uint8_t mac[] = {0xDE,0xAD,0xBE,0xEF,0x01,0x02};
  memcpy(wan_mac, mac, 6);

  lan_ip    = IPAddress(192, 168, 4, 1);
  lan_mask  = IPAddress(255, 255, 255, 0);
  strlcpy(wifi_ssid, "ESP32Router", sizeof(wifi_ssid));
  strlcpy(wifi_pass, "router1234",  sizeof(wifi_pass));
  wifi_channel    = 6;
  wifi_max_clients = 8;

  dhcp_enabled   = true;
  dhcp_start     = IPAddress(192, 168, 4, 10);
  dhcp_end       = IPAddress(192, 168, 4, 50);
  dhcp_lease_sec = 3600;
  strlcpy(dhcp_domain, "lan", sizeof(dhcp_domain));

  fw_default_policy = FW_ACTION_ALLOW;
  fw_dos_protect    = true;
  fw_wan_admin      = false;
  fw_rule_count     = 0;
  port_fwd_count    = 0;

fw_rules[0].enabled      = true;
fw_rules[0].action       = FW_ACTION_DENY;
fw_rules[0].direction    = FW_DIR_IN;
fw_rules[0].protocol     = FW_PROTO_TCP;
fw_rules[0].src_ip       = 0;
fw_rules[0].src_mask     = 0;
fw_rules[0].dst_ip       = 0;
fw_rules[0].dst_mask     = 0;
fw_rules[0].dst_port_min = 0;
fw_rules[0].dst_port_max = 0;
fw_rules[0].log_match    = false;

  vpn_enabled      = false;
  vpn_port         = 51820;
  vpn_kill_switch  = false;
  vpn_split_tunnel = false;
  strlcpy(vpn_allowed_ips, "0.0.0.0/0", sizeof(vpn_allowed_ips));
  vpn_server[0] = vpn_privkey[0] = vpn_pubkey[0] = vpn_psk[0] = '\0';
  vpn_tunnel_ip[0] = vpn_dns[0] = '\0';

  web_port  = 80;
  web_https = false;
  strlcpy(web_user, "admin", sizeof(web_user));
  strlcpy(web_pass, "admin", sizeof(web_pass));
}

// ── load ──────────────────────────────────────────────────────────────────────
void RouterConfig::load() {
  defaults();

  if (!LittleFS.exists(CONFIG_PATH)) {
    LOG_W("No config file, writing defaults");
    save();
    return;
  }

  File f = LittleFS.open(CONFIG_PATH, "r");
  if (!f) { LOG_E("Cannot open config"); return; }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, f);
  f.close();

  if (err) {
    LOG_E("Config JSON parse error: %s", err.c_str());
    save();
    return;
  }

  // WAN
  wan_dhcp = doc["wan"]["dhcp"] | true;
  if (doc["wan"]["ip"])   wan_ip   = parse_ip(doc["wan"]["ip"]);
  if (doc["wan"]["mask"]) wan_mask = parse_ip(doc["wan"]["mask"]);
  if (doc["wan"]["gw"])   wan_gw   = parse_ip(doc["wan"]["gw"]);
  if (doc["wan"]["dns1"]) wan_dns1 = parse_ip(doc["wan"]["dns1"]);
  if (doc["wan"]["dns2"]) wan_dns2 = parse_ip(doc["wan"]["dns2"]);
  JsonArray mac_arr = doc["wan"]["mac"].as<JsonArray>();
  if (mac_arr.size() == 6) for (int i=0;i<6;i++) wan_mac[i] = mac_arr[i];

  // LAN/WiFi
  if (doc["lan"]["ip"])   lan_ip   = parse_ip(doc["lan"]["ip"]);
  if (doc["lan"]["mask"]) lan_mask = parse_ip(doc["lan"]["mask"]);
  strlcpy(wifi_ssid, doc["lan"]["ssid"] | "ESP32Router", sizeof(wifi_ssid));
  strlcpy(wifi_pass, doc["lan"]["pass"] | "router1234",  sizeof(wifi_pass));
  wifi_channel     = doc["lan"]["channel"]     | 6;
  wifi_max_clients = doc["lan"]["max_clients"] | 8;

  // DHCP
  dhcp_enabled   = doc["dhcp"]["enabled"] | true;
  if (doc["dhcp"]["start"]) dhcp_start = parse_ip(doc["dhcp"]["start"]);
  if (doc["dhcp"]["end"])   dhcp_end   = parse_ip(doc["dhcp"]["end"]);
  dhcp_lease_sec = doc["dhcp"]["lease_sec"] | 3600;
  strlcpy(dhcp_domain, doc["dhcp"]["domain"] | "lan", sizeof(dhcp_domain));

  // Firewall
  fw_default_policy = doc["fw"]["default_policy"] | (int)FW_ACTION_ALLOW;
  fw_dos_protect    = doc["fw"]["dos_protect"]  | true;
  fw_wan_admin      = doc["fw"]["wan_admin"]    | false;
  fw_rule_count = 0;
  JsonArray rules = doc["fw"]["rules"].as<JsonArray>();
  for (JsonObject r : rules) {
    if (fw_rule_count >= MAX_FW_RULES) break;
    FWRule &fr = fw_rules[fw_rule_count++];
    fr.enabled      = r["en"]      | true;
    fr.action       = r["action"]  | 0;
    fr.direction    = r["dir"]     | 0;
    fr.protocol     = r["proto"]   | 0;
    fr.src_ip       = r["src_ip"]  | 0u;
    fr.src_mask     = r["src_mask"]| 0u;
    fr.dst_ip       = r["dst_ip"]  | 0u;
    fr.dst_mask     = r["dst_mask"]| 0u;
    fr.dst_port_min = r["dport_lo"]| 0;
    fr.dst_port_max = r["dport_hi"]| 0;
    fr.log_match    = r["log"]     | false;
  }

  // Port forwarding
  port_fwd_count = 0;
  JsonArray pfwds = doc["port_fwd"].as<JsonArray>();
  for (JsonObject p : pfwds) {
    if (port_fwd_count >= MAX_PORT_FWD_RULES) break;
    PortFwdRule &pf = port_fwd[port_fwd_count++];
    pf.enabled   = p["en"]       | false;
    pf.protocol  = p["proto"]    | (int)FW_PROTO_TCP;
    pf.ext_port  = p["ext_port"] | 0;
    pf.int_ip    = p["int_ip"]   | 0u;
    pf.int_port  = p["int_port"] | 0;
  }

  // VPN
  vpn_enabled      = doc["vpn"]["enabled"]      | false;
  vpn_port         = doc["vpn"]["port"]          | 51820;
  vpn_kill_switch  = doc["vpn"]["kill_switch"]   | false;
  vpn_split_tunnel = doc["vpn"]["split_tunnel"]  | false;
  strlcpy(vpn_server,      doc["vpn"]["server"]      | "", sizeof(vpn_server));
  strlcpy(vpn_privkey,     doc["vpn"]["privkey"]      | "", sizeof(vpn_privkey));
  strlcpy(vpn_pubkey,      doc["vpn"]["pubkey"]       | "", sizeof(vpn_pubkey));
  strlcpy(vpn_psk,         doc["vpn"]["psk"]          | "", sizeof(vpn_psk));
  strlcpy(vpn_tunnel_ip,   doc["vpn"]["tunnel_ip"]    | "", sizeof(vpn_tunnel_ip));
  strlcpy(vpn_dns,         doc["vpn"]["dns"]          | "", sizeof(vpn_dns));
  strlcpy(vpn_allowed_ips, doc["vpn"]["allowed_ips"]  | "0.0.0.0/0", sizeof(vpn_allowed_ips));

  // Web UI
  web_port  = doc["web"]["port"]  | 80;
  web_https = doc["web"]["https"] | false;
  strlcpy(web_user, doc["web"]["user"] | "admin", sizeof(web_user));
  strlcpy(web_pass, doc["web"]["pass"] | "admin", sizeof(web_pass));

  LOG_I("Config loaded from %s", CONFIG_PATH);
}

// ── save ──────────────────────────────────────────────────────────────────────
void RouterConfig::save() {
  JsonDocument doc;

  JsonObject wan = doc["wan"].to<JsonObject>();
  wan["dhcp"] = wan_dhcp;
  wan["ip"]   = wan_ip.toString();
  wan["mask"] = wan_mask.toString();
  wan["gw"]   = wan_gw.toString();
  wan["dns1"] = wan_dns1.toString();
  wan["dns2"] = wan_dns2.toString();
  JsonArray mac_arr = wan["mac"].to<JsonArray>();
  for (int i=0;i<6;i++) mac_arr.add(wan_mac[i]);

  JsonObject lan = doc["lan"].to<JsonObject>();
  lan["ip"]          = lan_ip.toString();
  lan["mask"]        = lan_mask.toString();
  lan["ssid"]        = wifi_ssid;
  lan["pass"]        = wifi_pass;
  lan["channel"]     = wifi_channel;
  lan["max_clients"] = wifi_max_clients;

  JsonObject dhcp = doc["dhcp"].to<JsonObject>();
  dhcp["enabled"]   = dhcp_enabled;
  dhcp["start"]     = dhcp_start.toString();
  dhcp["end"]       = dhcp_end.toString();
  dhcp["lease_sec"] = dhcp_lease_sec;
  dhcp["domain"]    = dhcp_domain;

  JsonObject fw = doc["fw"].to<JsonObject>();
  fw["default_policy"] = fw_default_policy;
  fw["dos_protect"]    = fw_dos_protect;
  fw["wan_admin"]      = fw_wan_admin;
  JsonArray rules = fw["rules"].to<JsonArray>();
  for (uint8_t i = 0; i < fw_rule_count; i++) {
    JsonObject r = rules.add<JsonObject>();
    r["en"]       = fw_rules[i].enabled;
    r["action"]   = fw_rules[i].action;
    r["dir"]      = fw_rules[i].direction;
    r["proto"]    = fw_rules[i].protocol;
    r["src_ip"]   = fw_rules[i].src_ip;
    r["src_mask"] = fw_rules[i].src_mask;
    r["dst_ip"]   = fw_rules[i].dst_ip;
    r["dst_mask"] = fw_rules[i].dst_mask;
    r["dport_lo"] = fw_rules[i].dst_port_min;
    r["dport_hi"] = fw_rules[i].dst_port_max;
    r["log"]      = fw_rules[i].log_match;
  }

  JsonArray pfwds = doc["port_fwd"].to<JsonArray>();
  for (uint8_t i = 0; i < port_fwd_count; i++) {
    JsonObject p = pfwds.add<JsonObject>();
    p["en"]       = port_fwd[i].enabled;
    p["proto"]    = port_fwd[i].protocol;
    p["ext_port"] = port_fwd[i].ext_port;
    p["int_ip"]   = port_fwd[i].int_ip;
    p["int_port"] = port_fwd[i].int_port;
  }

  JsonObject vpn = doc["vpn"].to<JsonObject>();
  vpn["enabled"]      = vpn_enabled;
  vpn["server"]       = vpn_server;
  vpn["port"]         = vpn_port;
  vpn["privkey"]      = vpn_privkey;
  vpn["pubkey"]       = vpn_pubkey;
  vpn["psk"]          = vpn_psk;
  vpn["tunnel_ip"]    = vpn_tunnel_ip;
  vpn["dns"]          = vpn_dns;
  vpn["kill_switch"]  = vpn_kill_switch;
  vpn["split_tunnel"] = vpn_split_tunnel;
  vpn["allowed_ips"]  = vpn_allowed_ips;

  JsonObject web = doc["web"].to<JsonObject>();
  web["port"]  = web_port;
  web["https"] = web_https;
  web["user"]  = web_user;
  web["pass"]  = web_pass;

  File f = LittleFS.open(CONFIG_PATH, "w");
  if (!f) { LOG_E("Cannot write config"); return; }
  serializeJson(doc, f);
  f.close();
  LOG_I("Config saved");
}
