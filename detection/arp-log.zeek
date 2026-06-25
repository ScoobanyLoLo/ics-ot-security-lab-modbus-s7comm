@load base/frameworks/logging
@load base/bif/plugins/Zeek_ARP.events.bif.zeek
module ARPLOG;
export {
  redef enum Log::ID += { LOG };
  type Info: record {
    ts: time &log;
    op: string &log;        # request/reply - typ aperacji ARP
    mac_src: string &log;   # MAC zrodlowy z obserwowanej ramki L2
    mac_dst: string &log;   # MAC docelowy z obserwowanej ramki L2
    spa: addr &log;         # Sender Protocol Address (IP nadawcy)
    sha: string &log;       # Sender Hardware Address (MAC deklarowany w polu ARP)
    tpa: addr &log;         # Target Protocol Address (IP celu)
    tha: string &log;       # Target Hardware Address (MAC celu w polu ARP)
  };
}
# Osobny strumien logow: plik arp.log
# Mozliwosc pelnego zapisu mapowac IP-MAC
event zeek_init()
{
  Log::create_stream(ARPLOG::LOG, [$columns=Info, $path="arp"]);
}
# Logowanie kazdego arp request
event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
{
  Log::write(ARPLOG::LOG, [$ts=network_time(), $op="request",
                           $mac_src=mac_src, $mac_dst=mac_dst,
                           $spa=SPA, $sha=SHA, $tpa=TPA, $tha=THA]);
}
# Logowanie kazdego arp reply
event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
{
  Log::write(ARPLOG::LOG, [$ts=network_time(), $op="reply",
                           $mac_src=mac_src, $mac_dst=mac_dst,
                           $spa=SPA, $sha=SHA, $tpa=TPA, $tha=THA]);
}
