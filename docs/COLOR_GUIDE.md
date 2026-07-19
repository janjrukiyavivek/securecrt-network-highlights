# Color Guide

SecureCRT stores colors as `00BBGGRR` hex (note: reversed from the usual
RRGGBB). The palette below is defined once in `tools/build.py` as the `C`
dict, so every section pulls from the same set of named colors instead of
hard-coded hex values. Organized here by semantic meaning first (what a
contributor should reach for when adding a rule), with the literal name/hex
as the lookup key into `build.py`.

| Meaning | Name | Hex (00BBGGRR) |
| --- | --- | --- |
| Success / healthy / established / up | green | 0000ff00 |
| Warning / transitional / degraded | orange | 0000a5ff |
| Critical / down / error / dangerous | red | 000000ff |
| Interface names and slots | cyan | 00ffff00 |
| Routing protocols (BGP/OSPF/EIGRP/..) | blue | 00ff8000 |
| Security, crypto, IPsec, IKE | purple | 00ff66ff |
| Services (DHCP/DNS/SNMP/NTP/SSH/QoS) | pink | 00b469ff |
| MPLS/LDP/segment routing/VXLAN/EVPN | magenta | 00ff00ff |
| Hardware, counters, cloud, storage, optics | teal | 00b3b3b3 |
| Addressing (AS numbers, IPs, RT/RD) | gold | 0000d7ff |
| Prompts, syslog, interactive prompts | yellow | 0000ffff |
| Normal / neutral text | white | 00ffffff |
| Section header comments | grey | 00808080 |

When adding a rule, pick the row by what the token *means*, not which
section happens to be nearby -- that's what keeps e.g. all of NX-OS fabric,
SD-WAN, and FHRP sharing `blue` instead of each section inventing its own
"routing-ish" color.

Dangerous commands use reverse video (`0000001f,0000001f`) on top of red
rather than a different color, so they stand out even more than a plain
critical-red error line. Note the keyword-highlight format stores one
foreground color per entry, not an independent background -- reverse video
swaps that color against the session's current background instead of letting
us paint an explicit white background, but it's the strongest combination
the format allows.

## Syslog severity (`[*]======== Syslog ========`)

Cisco severity digits 0-7 are mapped directly to color rather than treated
as one generic `%FACILITY-N-MNEMONIC` token, most-specific-digit-class first
so a `%LINK-3-...` line can't fall through to a less severe color:

| Severity | Meaning | Color |
| --- | --- | --- |
| 0-3 | Emergency/Alert/Crit/Error | red |
| 4-5 | Warning/Notification | orange |
| 6 | Informational | white |
| 7 | Debug | grey |
