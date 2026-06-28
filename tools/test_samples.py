#!/usr/bin/env python3
"""
Smoke-tests the generated keyword rules against realistic sample CLI output
(rather than only checking the .ini file's own structure, which is what
validate_highlights.py does). For each sample line, simulates SecureCRT's
actual matching behaviour: rules are tried top-to-bottom, and once a
character position is claimed by an earlier rule, later rules can't repaint
it -- so this also catches "this rule is unreachable because something
earlier already claims that text" bugs that validate_highlights.py can't see
(it only checks for byte-identical duplicate regex strings).

Run: python3 tools/test_samples.py
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import build  # noqa: E402

COLOR_NAMES = {v: k for k, v in build.C.items()}
COLOR_NAMES[build.C["grey"]] = "grey"

SAMPLES = {
    "show interface": """\
GigabitEthernet0/1 is up, line protocol is up
  Description: Uplink to Core-SW1
  Internet address is 10.10.10.1/30
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,
  Full Duplex, 1000Mbps
  Input queue: 0/375/0/0 (size/max/drops/flushes); Total output drops: 0
     125 packets input, 12345 bytes, 0 no buffer
     12 input errors, 5 CRC, 0 frame, 0 overrun, 0 ignored
     0 output errors, 0 collisions, 2 interface resets
Serial0/0/1 is administratively down, line protocol is down
""",
    "show logging": """\
*Jun 29 10:15:33.123: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
*Jun 29 10:15:34.456: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down
*Jun 29 10:16:01.789: %SYS-6-LOGGINGHOST_STARTSTOP: Logging to host 10.0.0.5 started
""",
    "show bgp ipv4 unicast summary": """\
BGP router identifier 10.0.0.1, local AS number 65001
Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.0.0.2        4 65002    1023    1045      145    0    0 1w2d            120
10.0.0.3        4 65003       0       0        0    0    0 never    Idle
10.0.0.4        4 65004      50      52      145    0    0 00:05:23 Active
10.0.0.5        4 65005     900     901      145    0    0 1w0d     Established
""",
    "show bgp l2vpn evpn": """\
*> [2]:[0]:[0]:[48]:[0050.7966.6801]:[32]:[10.10.10.5]
                    10.0.0.2                 0    100      0 65002 i
*> [3]:[0]:[0]:[32]:[10.0.0.2]
                    10.0.0.2                 0    100      0 65002 i
*> [5]:[0]:[0]:[24]:[192.168.1.0]
                    10.0.0.2                 0    100      0 65002 i
""",
    "show ip route": """\
O    10.1.1.0/24 [110/20] via 10.0.0.2, 00:10:23, GigabitEthernet0/1
B    10.2.2.0/24 [20/0] via 10.0.0.3, 1w2d
C    10.0.0.0/30 is directly connected, GigabitEthernet0/1
""",
    "show ospf neighbor": """\
Neighbor ID     Pri   State           Dead Time   Address         Interface
10.0.0.2          1   FULL/BDR        00:00:39    10.0.0.2        GigabitEthernet0/1
10.0.0.3          1   2WAY/DROTHER    00:00:32    10.0.0.3        GigabitEthernet0/1
10.0.0.4          1   DOWN            -           10.0.0.4        GigabitEthernet0/2
""",
    "show vpc": """\
vPC domain id                     : 10
vPC keep-alive status             : peer is alive
Type-2 consistency status         : success
vPC Peer-link status
1    Po10   up     1,10,20,30
Orphan ports list:
Gi1/0/10
""",
    "show environment": """\
Power Supply:
Status                     Type            Capacity     PID
---------- ------------------------------- -----------  -----------------
Failed     Cisco PWR-C1-1100WAC               1100 W     PWR-C1-1100WAC
Fan 1 Faulty
Fan 2 OK
Temperature: 35C
Temperature Alarm: Critical
""",
    "show module": """\
Mod  Ports  Module-Type                         Model              Status
1    48     48x10/25G/32xFC Supervisor          N9K-SUP-A          active *
2    0      Fabric Module                       N9K-C9508-FM-E     ok
""",
    "show inventory": """\
NAME: "Chassis", DESCR: "Cisco Nexus9000 C93180YC-EX Chassis"
PID: N9K-C93180YC-EX     , VID: V02 , SN: FOC1234X5YZ
""",
    "ip addr": """\
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
""",
    "ip route": """\
default via 192.168.1.1 dev eth0 proto dhcp metric 100
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50
""",
    "bridge link": """\
3: eth0 state UP mtu 1500 master br0 priority 32 cost 2
""",
    "tcpdump": """\
10:15:33.123456 IP 10.0.0.1.443 > 10.0.0.2.51820: Flags [S], seq 1234567890, win 64240, length 0
10:15:33.124001 IP 10.0.0.2.51820 > 10.0.0.1.443: Flags [S.], seq 987654321, ack 1234567891, win 65535, length 0
10:15:33.124200 IP 10.0.0.1.443 > 10.0.0.2.51820: Flags [.], ack 987654322, win 64240, length 0
10:15:40.500000 IP 10.0.0.2.51820 > 10.0.0.1.443: Flags [R.], seq 1, ack 1, win 0, length 0
10:15:41.000000 IP6 2001:db8::1 > 2001:db8::2: ICMP6, echo request
""",
    "sophos show vpn / log": """\
2026-06-29 10:15:00 IPSEC strongswan: IKE SA established, Child SA up
2026-06-29 10:16:00 HA: Heartbeat lost, Failover to Auxiliary
2026-06-29 10:17:00 Firewall_Rule Action=Drop SrcIP=10.0.0.5 DstIP=10.0.0.6
2026-06-29 10:18:00 Firewall_Rule Action=Accept SrcIP=10.0.0.7 DstIP=10.0.0.8
""",
}


def color_name(hexval):
    return COLOR_NAMES.get(hexval, hexval)


def colorize_line(line, rows):
    """rows: list of (regex, color, flags) with header rows already removed.
    Returns list of (text_chunk, color_or_None) reflecting first-match-wins
    per character, same precedence SecureCRT applies top to bottom."""
    claimed = [None] * len(line)
    for regex, color, _flags in rows:
        for m in re.finditer(regex, line, re.IGNORECASE):
            for i in range(m.start(), m.end()):
                if claimed[i] is None:
                    claimed[i] = color
    chunks = []
    cur_color, cur_text = "__unset__", []
    for ch, color in zip(line, claimed):
        if color != cur_color:
            if cur_text:
                chunks.append(("".join(cur_text), None if cur_color == "__unset__" else cur_color))
            cur_text, cur_color = [ch], color
        else:
            cur_text.append(ch)
    if cur_text:
        chunks.append(("".join(cur_text), None if cur_color == "__unset__" else cur_color))
    return chunks


def main():
    rows = [r for r in build.flatten() if not r[0].startswith("[*]")]
    for name, text in SAMPLES.items():
        print(f"\n=== {name} ===")
        for line in text.splitlines():
            if not line.strip():
                continue
            chunks = colorize_line(line, rows)
            rendered = " | ".join(
                f"{t!r}->{color_name(c)}" for t, c in chunks if c is not None
            )
            print(f"  {line}")
            print(f"    matched: {rendered if rendered else '(nothing)'}")


if __name__ == "__main__":
    main()
