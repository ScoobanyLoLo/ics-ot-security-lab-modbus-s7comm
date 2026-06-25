@load base/frameworks/notice
@load base/bif/plugins/Zeek_ARP.events.bif.zeek
module MITM;
# zmiana mapowania IP-MAC
# powiazanie jednego MAC z wieloma IP
export {
  redef enum Notice::Type += {
    ARP_IP_MAC_Changed,
    ARP_MAC_Claims_Multiple_IPs
  };
# adresy urzadzen OT, ktore sa monitorowane
  const protected_ips: set[addr] = {
    192.168.0.50,
    192.168.0.20,
    192.168.0.10
  } &redef;
# maksymalna liczba IP akceptowalna dla jednego MAC
  const max_ips_per_mac: count = 3 &redef;
  const mitm_ttl: interval = 5min &redef;

  # deklaracja API (prototypy)
  global mitm_until: table[addr] of time;
  global mitm_is_active: function(ip: addr): bool;
}
# ===== STAN WEWNETRZNY =====
# ostatnie znane mapowanie
global ip2mac: table[addr] of string;
# odwrotne mapowanie IP-MAC
global mac2ips: table[string] of set[addr];
function mitm_is_active(ip: addr): bool
  {
  return ip in mitm_until && network_time() <= mitm_until[ip];
  }
function is_protected(ip: addr): bool
  {
  return ip in protected_ips;
  }
event arp_reply(mac_src: string, mac_dst: string,
                SPA: addr, SHA: string,
                TPA: addr, THA: string)
  {
  # Wykrycie zmiany mapowania ip-mac
  if ( SPA in ip2mac && ip2mac[SPA] != SHA )
    {
    if ( is_protected(SPA) )
      {
      NOTICE([$note=ARP_IP_MAC_Changed,
              $msg=fmt("MITM? ARP IP %s changed MAC %s -> %s (frame_mac_src=%s mac_dst=%s)",
                       SPA, ip2mac[SPA], SHA, mac_src, mac_dst),
              $sub=fmt("%s", SPA),
              $identifier=fmt("%s-%s-%s", SPA, ip2mac[SPA], SHA)]);
# oznaczenie danego IP jako zagrozenie mitm
      mitm_until[SPA] = network_time() + mitm_ttl;
      }
# aktualizacja mapowania IP-mac
    ip2mac[SPA] = SHA;
    }
  else
    {
    ip2mac[SPA] = SHA;
    }
  # wykrycie przypadku gdy jeden MAC posiada wiele IP
  if ( SHA !in mac2ips )
    mac2ips[SHA] = set();
  add mac2ips[SHA][SPA];
  if ( |mac2ips[SHA]| >= max_ips_per_mac )
    {
    local ot_hit = F;
    for ( ip in mac2ips[SHA] )
      {
      if ( is_protected(ip) )
        {
        ot_hit = T;
        break;
        }
      }
    if ( ot_hit )
      {
      NOTICE([$note=ARP_MAC_Claims_Multiple_IPs,
              $msg=fmt("MITM? ARP MAC %s claims %d IPs %s",
                       SHA, |mac2ips[SHA]|, mac2ips[SHA]),
              $sub=SHA,
              $identifier=fmt("%s-%d", SHA, |mac2ips[SHA]|)]);
      }
    }
  }
