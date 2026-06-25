@load base/frameworks/notice
@load base/protocols/modbus
# Wykorzystano stan MITM (mitm_until) z detektora mitm-arp-detect.zeek
# -----------------------------
# 1) MODBUS_TAMPERING - Notice generowane tylko przy aktywnym MiTM
# -----------------------------
module MODBUS_TAMPERING;
export {
  redef enum Notice::Type += {
    Modbus_Read_Observed,    # zauwazono Read podczas MiTM
    Modbus_Write_Observed    # zauwazono Write podczas MiTM
  };
 # legalne źródła - whitelist
  const legal_masters: set[addr] = {
    192.168.0.50,
    192.168.0.20
  } &redef;
  # ograniczenie czestotliwosci generowania Notice (1 sekunda ingorowania)
  const obs_suppress: interval = 1sec &redef;
}
# sprawdzenie aktywnego MiTM na podstawie tablicy mitm_until
function mitm_context(orig: addr, resp: addr): bool
  {
  return (orig in MITM::mitm_until && network_time() <= MITM::mitm_until[orig]) ||
         (resp in MITM::mitm_until && network_time() <= MITM::mitm_until[resp]);
  }
# skupienie sie tylko na requestach
event Modbus::log_modbus(rec: Modbus::Info)
  {
  if ( rec?$pdu_type && rec$pdu_type != "REQ" )
    return;
  if ( !rec?$id || !rec$id?$orig_h || !rec$id?$resp_h )
    return;
  local orig = rec$id$orig_h;
  local resp = rec$id$resp_h;
  #generowanie notice
  if ( !mitm_context(orig, resp) )
    return;
# pominiecie legalnych adresow
  if ( orig !in legal_masters )
    return;
# obserwacja read
  if ( rec?$func && rec$func == "READ_HOLDING_REGISTERS" )
    {
    NOTICE([$note=Modbus_Read_Observed,
            $msg=fmt("Modbus READ observed: func=%s src=%s:%s/tcp dst=%s:502/tcp unit=%d",
                     rec$func, orig, rec$id$orig_p, resp, rec$unit),
            $sub=fmt("%s", resp),
            $identifier=fmt("tamper-read-%s-%s-%d", orig, resp, rec$unit),
            $suppress_for=obs_suppress]);
    }
#obserwacja write
  if ( rec?$func && rec$func == "WRITE_MULTIPLE_REGISTERS" )
    {
    NOTICE([$note=Modbus_Write_Observed,
            $msg=fmt("Modbus WRITE observed: func=%s src=%s:%s/tcp dst=%s:502/tcp unit=%d",
                     rec$func, orig, rec$id$orig_p, resp, rec$unit),
            $sub=fmt("%s", resp),
            $identifier=fmt("tamper-write-%s-%s-%d", orig, resp, rec$unit),
            $suppress_for=obs_suppress]);
    }
  }
# -----------------------------
# 2) MODBUS_REPLAY - Notice generowanie niezaleznie od MiTM
# -----------------------------
module MODBUS_REPLAY;
# Podejrzenie powtorzenia
export {
  redef enum Notice::Type += {
    Modbus_Replay_Suspected
  };
  const replay_window: interval = 20sec &redef;
  # legalne źródła - whitelist
  const legal_srcs: set[addr] = {
    192.168.0.50,
    192.168.0.20
  } &redef;
}
type LastReq: record {
  t: time;
  src: addr;
};
# Zapis ostatniego legalnego request
global last_legal: table[addr, count, string] of LastReq;
event Modbus::log_modbus(rec: Modbus::Info)
  {
  if ( rec?$pdu_type && rec$pdu_type != "REQ" )
    return;
  if ( !rec?$id || !rec$id?$orig_h || !rec$id?$resp_h || !rec?$func )
    return;
  local orig = rec$id$orig_h;
  local resp = rec$id$resp_h;
  local unit = rec$unit;
  local func = rec$func;
  # zapamiętaj ostatni legalny
  if ( orig in legal_srcs )
    {
    last_legal[resp, unit, func] = [$t=network_time(), $src=orig];
    return;
    }
  # jeśli ktoś inny po legalnym request – replay suspected
  if ( [resp, unit, func] in last_legal )
    {
    local dt = network_time() - last_legal[resp, unit, func]$t;
    if ( dt <= replay_window )
      {
      NOTICE([$note=Modbus_Replay_Suspected,
              $msg=fmt("Modbus replay suspected: %s -> %s (unit=%d) after %.3f sec; last legal src=%s",
                       orig, resp, unit, dt, last_legal[resp, unit, func]$src),
              $sub=fmt("%s", resp),
              $identifier=fmt("replay-%s-%s-%d-%s", orig, resp, unit, func),
              $suppress_for=1sec]);
      }
    }
  }
