#!/usr/bin/env python3
"""
Builds build/Network Engineer Ultimate.ini from the section data below.

SecureCRT keyword highlight list format (V3, "latest SecureCRT"):

    S:"List Name"=<name>
    D:"Regex Line Mode"=00000000
    D:"Match Case"=00000000
    Z:"Keyword List V3"=<hex count of entries>
     "<regex>",<00BBGGRR color>,<flags3>,<flags4>
     ...

Each section starts with a "[*]Section_Name" comment entry (never matches
real text because it starts with a literal "[*]") followed by its regexes.
flags "00000001,00000001" = normal bold text on the given color.
flags "0000001f,0000001f" = reverse video (used for Dangerous Commands only,
matching the one place in the source files where the file's own author
labeled this exact bit pattern "reverse video").
"""
import re

HEADER_FLAGS = "00000001"          # comment/section-header rows
NORMAL_FLAGS = ("00000001", "00000001")   # bold text, normal video
REVERSE_FLAGS = ("0000001f", "0000001f")  # reverse video (dangerous commands)
# Note: the keyword-highlight format stores one foreground color per entry;
# reverse video swaps that color against the session's current background
# rather than letting us set an independent background color per rule. Red
# foreground + reverse video is the strongest combination the format allows.

# ---------------------------------------------------------------------------
# Colour palette (00BBGGRR)
# ---------------------------------------------------------------------------
C = {
    "green":   "0000ff00",   # healthy / up / success
    "cyan":    "00ffff00",   # interfaces
    "blue":    "00ff8000",   # protocols (BGP/OSPF/etc family - orange-blue split below)
    "purple":  "00ff66ff",   # security / crypto
    "yellow":  "0000ffff",   # prompts / warnings-adjacent info
    "orange":  "0000a5ff",   # warnings
    "red":     "000000ff",   # critical / down / errors
    "grey":    "00808080",   # comments / section headers
    "white":   "00ffffff",   # normal text / neutral
    "gold":    "0000d7ff",   # AS numbers, RT/RD
    "teal":    "00b3b3b3",   # counters / misc info
    "magenta": "00ff00ff",   # MPLS / segment routing
    "pink":    "00b469ff",   # services
    "skyblue": "00e8a000",   # routing protocol family banner colour
}

SECTIONS = []


def sec(name, entries):
    """entries: list of (regex, color) or (regex, color, flags_tuple)"""
    SECTIONS.append((name, entries))


# ---------------------------------------------------------------------------
# 1. Prompts / Hostname / Configuration Mode
# ---------------------------------------------------------------------------
sec("Prompts_Enable_Mode", [
    # End-anchored for the same reason as the non-enable prompt below: a
    # real prompt is the whole line, not a "#" that happens to appear
    # followed by other text.
    (r"^\S+\(config[^)]*\)#\s*$", C["orange"]),
    (r"^\S+#\s*$", C["yellow"]),
])

sec("Prompts_Non_Enable_Mode", [
    # End-anchored: a real prompt is the *entire* line ("router>"), whereas
    # BGP's best-path marker ("*> 10.0.0.0/24 ...") also starts with a
    # non-whitespace run followed by ">" but has real content after it.
    (r"^\S+>\s*$", C["teal"]),
])

sec("Hostname_And_Config_Mode_Words", [
    (r"\bhostname\b", C["yellow"]),
    (r"\b(?:config|conf t|configure terminal)\b", C["orange"]),
])

# ---------------------------------------------------------------------------
# 2. Interfaces (ordered most-specific to least-specific; Cisco, Arista,
#    Juniper, Linux, FRR/VyOS, NSX/WireGuard all share this block)
# ---------------------------------------------------------------------------
sec("Interfaces", [
    (r"Embedded-Service-Engine\d/\d", C["cyan"]),
    (r"(?:Ten|TwentyFive|Forty|Hundred)?GigabitEthernet[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?", C["cyan"]),
    (r"\b(?:Te|Tw|Fo|Hu)?[Gg]i[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?", C["cyan"]),
    (r"\bFastEthernet[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?|\bFa[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?", C["cyan"]),
    (r"\bEthernet[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?|\bEt[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?", C["cyan"]),
    (r"\bSerial[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?|\bSe[0-9]+(?:/[0-9]+)*", C["cyan"]),
    (r"\b(?:Port-channel|Po)[0-9]+(?::[0-9]+)?", C["cyan"]),
    (r"\bvfc[0-9]+", C["cyan"]),
    (r"\b(?:Loopback|Lo)[0-9]+", C["cyan"]),
    (r"\b(?:Tunnel|Tu)[0-9]+", C["cyan"]),
    (r"\b(?:Vlan|Vl)[0-9]+", C["cyan"]),
    (r"\bNVI[0-9]+|\bBVI[0-9]+|\bMultilink[0-9]+|\bMu[0-9]+|\bDialer[0-9]+|\bDi[0-9]+", C["cyan"]),
    (r"\b(?:mgmt|null|nve)[0-9]+", C["cyan"]),
    (r"\bMg(?:mtEth)?0/(?:RP)?0/CPU0/0", C["cyan"]),                 # IOS-XR mgmt interface
    (r"\b(?:Bundle-Ether|BE)[0-9]+", C["cyan"]),                      # IOS-XR LAG
    (r"\bxe-[0-9]+/[0-9]+/[0-9]+|\bge-[0-9]+/[0-9]+/[0-9]+|\bet-[0-9]+/[0-9]+/[0-9]+", C["cyan"]),  # Juniper
    (r"\bae[0-9]+(?:\.[0-9]+)?|\birb\.[0-9]+|\blo0(?:\.[0-9]+)?", C["cyan"]),                        # Juniper LAG/IRB/loopback
    (r"\b(?:eth|ens|enp[0-9]+s[0-9]+|bond|vxlan|br|wlan|wg|tun|tap)[0-9]+(?:\.[0-9]+)?", C["cyan"]),  # Linux/WireGuard
    (r"\bswp[0-9]+(?:s[0-9]+)?", C["cyan"]),                          # FRR/Cumulus switch ports
    (r"\beth[0-9]+/[0-9]+(?:/[0-9]+)?", C["cyan"]),                   # Arista EOS
    # Negative lookahead on "line" excludes "line protocol is up/down" --
    # that's interface state, not a console/vty line, and "is up" is
    # the meaningful word.
    (r"\bcon0?\b|\bvty\b|\bline\b(?!\s+protocol)|\baux\b|\bconsole\b", C["cyan"]),
])

# ---------------------------------------------------------------------------
# 3. IP / IPv6 / MAC / WWN
# ---------------------------------------------------------------------------
sec("IPv4_Addresses", [
    (r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(?:/(?:3[0-2]|[12]?[0-9]))?(?::[0-9]{1,5})?", C["gold"]),
])

sec("IPv6_Addresses", [
    (r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?::[0-9A-Fa-f]{1,4}){0,6}|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}", C["gold"]),
])

sec("MAC_Address", [
    (r"(?:[a-f0-9]{2}[:-]){5}[a-f0-9]{2}", C["teal"]),
    (r"[a-f0-9]{4}\.[a-f0-9]{4}\.[a-f0-9]{4}", C["teal"]),
])

sec("Fiber_WWN", [
    (r"\b(?:wwn|pwwn)\b|(?:[a-f0-9]{2}:){7}[a-f0-9]{2}", C["blue"]),
])

# ---------------------------------------------------------------------------
# 4. AS Numbers / Route Targets / VPNv4 / VPNv6 / VLANs / VRFs
# ---------------------------------------------------------------------------
sec("AS_Numbers", [
    (r"\bAS\s?\d{1,10}\b|\bremote-as\s+\d{1,10}\b|\blocal-as\s+\d{1,10}\b", C["blue"]),
])

sec("Route_Targets_And_Distinguishers", [
    # No bare "\d+:\d+" fallback: that pattern also matches the seconds
    # field of an uptime/timer like "00:05:23" (caught during sample-output
    # testing against "show bgp ... summary"), so only the explicitly
    # labeled RT:/RD forms are matched.
    (r"\bRT:\d{1,10}:\d{1,10}\b|\bRD\s+\d{1,10}:\d{1,10}\b", C["blue"]),
])

sec("VPNv4_VPNv6", [
    (r"\bvpnv[46]\b", C["blue"]),
])

sec("VLANs", [
    (r"\bvlan\s?\d{1,4}\b|\bVl\d{1,4}\b", C["cyan"]),
])

sec("VRFs", [
    (r"\bvrf\s+\S+\b|\bVRF\b|\bL3VPN\b|\bL2VPN\b", C["blue"]),
])

# ---------------------------------------------------------------------------
# 5. Routing protocol families
# ---------------------------------------------------------------------------
sec("BGP", [
    (r"\bMaximum (?:Number of )?Prefix(?:es)? (?:Reached|exceeded)\b|\bRIB[- ]failure\b", C["red"]),
    (r"\bIdle\b|\bConnect\b|\bActive\b|\bOpenSent\b|\bOpenConfirm\b", C["orange"]),
    (r"\bEstablished\b", C["green"]),
    (r"\bRoute[- ]Reflector(?:-Client)?\b|\bRR-client\b|\bcluster-id\b", C["blue"]),
    (r"\bbest-?path\b", C["blue"]),
    (r"\blocal-preference\b|\blocalpref\b|\bLocPrf\b", C["blue"]),
    (r"\bweight\s+\d+\b|\bMED\b|\bmetric\b", C["blue"]),
    (r"\borigin\b|\bIGP\b|\bEGP\b|\bincomplete\b", C["blue"]),
    (r"\b(?:large-|extended-)?communit(?:y|ies)\b", C["blue"]),
    (r"\b[ei]?bgp\b", C["blue"]),  # case-insensitive matching already covers BGP/bgp/eBGP/iBGP
])

sec("OSPF", [
    (r"\bExStart\b|\bExchange\b|\bLoading\b", C["orange"]),
    (r"\b2-?way\b", C["orange"]),
    (r"\bFull\b", C["green"]),
    # No bare "Down" here: OSPF neighbor-down is just one more case of the
    # generic down-state problem, and [*]Interface_State_Bad's column-aware
    # down rule (later in the file, same red colour) already covers it.
    (r"\bDROTHER\b|\bBDR\b|\bDR\b", C["blue"]),
    (r"\bNSSA\b|\bABR\b|\bASBR\b|\bopaque\b", C["blue"]),
    (r"\bLSA\b|\bSPF\b", C["blue"]),
    (r"\bospf(?:v3)?\b", C["blue"]),
])

sec("ISIS", [
    (r"\bL1\b|\bL2\b|\bL1L2\b|\blevel-[12]\b", C["blue"]),
    (r"\bis-?is\b|\bCLNS\b", C["blue"]),
])

sec("EIGRP", [
    (r"\bPassive\b|\bActive\b", C["orange"]),
    (r"\beigrp(?:-ipv[46])?\b", C["blue"]),
])

sec("RIP", [
    (r"\brip(?:v[12]|ng)?\b", C["blue"]),
])

# ---------------------------------------------------------------------------
# 6. MPLS / LDP / Segment Routing / VXLAN / EVPN
# ---------------------------------------------------------------------------
sec("MPLS_LDP_SR", [
    (r"\bmpls\b|\blabel(?:s)?\b", C["magenta"]),
    (r"\bldp\b", C["magenta"]),
    (r"\bsegment[- ]routing\b|\bSR-MPLS\b|\bSRGB\b|\bSRLB\b|\badjacency-sid\b|\bprefix-sid\b|\bSRv6\b", C["magenta"]),
])

sec("VXLAN_EVPN", [
    (r"\bvxlan\b|\bVNI\b|\bNVE\b", C["magenta"]),
    # EVPN route types (RFC 7432): Type-2 MAC/IP, Type-3 IMET, Type-5 IP
    # prefix. Real route tables ("show bgp l2vpn evpn") print the type as
    # bracket notation, e.g. "[2]:[0]:[0]:[48]:[mac]:[32]:[ip]" or
    # "[3]:[0]:[0]:[32]:[ip]" -- the spelled-out "Type-2" wording mostly
    # shows up in prose/docs, so both forms are matched.
    (r"\[[25]\]:\[\d+\]:\[\d+\]:\[\d{1,3}\]|\[3\]:\[\d+\]:\[\d{1,3}\]", C["magenta"]),
    # Negative lookahead excludes Nexus vPC's "Type-1/2 (in)consistency"
    # phrasing, which is a different "Type-N" vocabulary entirely.
    (r"\bType-[2356]\b(?!\s+(?:in)?consisten)|\bIMET\b|\bMAC/IP\b|\bBUM\b|\bESI\b", C["magenta"]),
    (r"\bevpn\b|\bL2VNI\b|\bL3VNI\b", C["magenta"]),
])

# ---------------------------------------------------------------------------
# 7. FHRP / Multicast
# ---------------------------------------------------------------------------
sec("FHRP", [
    (r"\bhsrp\b", C["blue"]),
    (r"\bvrrp\b", C["blue"]),
    (r"\bglbp\b", C["blue"]),
    # "Active" is deliberately excluded here: BGP's [*]BGP section owns that
    # token (orange) since it's evaluated first and BGP's "stuck in Active"
    # meaning is the higher-priority signal to surface.
    (r"\bMASTER\b|\bStandby\b|\bListen\b|\bSpeak\b|\bInit\b", C["blue"]),
])

sec("Multicast", [
    (r"\bpim(?:v2)?\b", C["pink"]),
    (r"\bmsdp\b", C["pink"]),
    (r"\bigmp(?:v[123])?\b", C["pink"]),
    (r"\bRP\b|\bRendezvous Point\b", C["pink"]),
])

# ---------------------------------------------------------------------------
# 8. ACL / Prefix Lists / Route Maps / QoS
# ---------------------------------------------------------------------------
sec("ACL", [
    (r"\(hitcnt=0\)", C["grey"]),
    (r"\(hitcnt=[1-9][0-9]*\)", C["blue"]),
    (r"\baccess-(?:list|class|group)s?\b|\bACL\b", C["blue"]),
])

sec("Prefix_Lists_Route_Maps", [
    (r"\bprefix-list\b|\bipv6 prefix-list\b", C["blue"]),
    (r"\broute-map\b", C["blue"]),
])

sec("QoS", [
    (r"\b(?:class|policy|service)-map\b|\bpolicy-map\b", C["pink"]),
    (r"\bDSCP\b|\bCoS\b|\bEXP\b|\btraffic-shape\b|\bpolic(?:e|ing)\b", C["pink"]),
])

# ---------------------------------------------------------------------------
# 9. Security / Crypto / IPSec / IKE / Certificates
# ---------------------------------------------------------------------------
sec("Security_Crypto", [
    (r"\bIKEv[12]\b|\bISAKMP\b", C["purple"]),
    (r"\bIPsec\b|\besp\b|\bah\b(?=\s)", C["purple"]),
    (r"\bcrypto\b|\bcertificate\b|\btrustpoint\b|\bCA\b(?=\s)", C["purple"]),
    (r"\busername\s+\S+|\bpassword\s+\S+|\bsecret\s+\S+|\bkey-chain\b", C["purple"]),
])

# ---------------------------------------------------------------------------
# 10. DHCP / DNS / SNMP / NTP / SSH / Syslog
# ---------------------------------------------------------------------------
sec("DHCP_DNS", [
    (r"\bdhcp(?:v6)?\b", C["pink"]),
    (r"\bdns\b", C["pink"]),
])

sec("SNMP_NTP_SSH", [
    (r"\bsnmp(?:-server)?\b", C["pink"]),
    (r"\bntp\b|\bstratum\s+\d+\b", C["pink"]),
    (r"\bssh\b|\btelnet\b", C["pink"]),
])

# Cisco syslog severity is itself an ordered list: 0-3 are red regardless of
# the facility, 4-5 are orange, 6 is informational white, 7 is debug grey.
# Numbered most-specific-digit first so e.g. "%LINK-3-..." never falls
# through to a generic catch-all colour.
sec("Syslog", [
    (r"%[A-Z0-9_]+-[0-3]-[A-Z0-9_]+", C["red"]),
    (r"%[A-Z0-9_]+-[45]-[A-Z0-9_]+", C["orange"]),
    (r"%[A-Z0-9_]+-6-[A-Z0-9_]+", C["white"]),
    (r"%[A-Z0-9_]+-7-[A-Z0-9_]+", C["grey"]),
])

sec("Cisco_Bug_IDs_And_CVEs", [
    (r"\bCSC[a-z]{2}\d{5}\b", C["yellow"]),       # Cisco bug/defect IDs, e.g. CSCwh12345
    (r"\bCVE-\d{4}-\d{4,7}\b", C["yellow"]),
])

sec("Nexus_vPC", [
    # "show vpc" prints "keep-alive" (hyphenated); config commands use
    # "peer-keepalive" (not hyphenated internally) -- both forms covered.
    (r"\bpeer-link\b|\bpeer-keepalive\b|\bkeep-?alive\b", C["blue"]),
    (r"\borphan(?:ed)?(?:-port)?\b", C["orange"]),
    # "Type-1"/"Type-2" alone are ambiguous with EVPN route types, so vPC
    # only matches the consistency-check phrasing Nexus actually prints.
    (r"\bType-[12]\s+(?:in)?consisten\w*\b|\bvpc\s+consisten\w*\b|\bconsistency\s+(?:check|parameters?)\b", C["blue"]),
])

sec("Stack_And_Chassis_Redundancy", [
    (r"\bStackWise(?:\s+Virtual)?\b|\bVSS\b|\bVirtual Switch(?:ing System)?\b", C["blue"]),
])

sec("NXOS_Fabric", [
    (r"\bCFSoE\b|\bFabricPath\b|\bOTV\b|\bFEX\b|\bVN-Segment\b", C["blue"]),
])

sec("SDWAN", [
    (r"\bOMP\b", C["blue"]),
    (r"\bvSmart\b|\bvBond\b|\bvManage\b|\bvEdge\b", C["blue"]),
    (r"\bTLOC\b|\bControl Connection(?:s)?\b|\bBFD Session(?:s)?\b", C["blue"]),
])

# Sophos Firewall (SFOS): deliberately scoped to high-value operational
# terms that show up in real troubleshooting -- service names, firewall
# actions, VPN/HA events, security modules, and named log files -- not
# every field in the Log Viewer. Generic config nouns (Firewall, Rule,
# Policy, Host, Network, Zone, Object) are intentionally excluded; they're
# common English/networking words that would create noise rather than
# signal. "Active"/"Passive"/"Standby" for HA are intentionally not
# re-added here either -- those tokens are already owned by [*]EIGRP and
# [*]FHRP earlier in the file with the same colour, so a duplicate rule
# here would just be unreachable. Same for "Rollback", already in
# [*]Dangerous_Commands.
sec("Sophos_Firewall", [
    (r"\bSFOS\b|\bXGS\b|\bSophos Central\b|\bZTNA\b|\bRED\b", C["blue"]),
    (r"\bstrongswan\b|\bzebra\b|\bbgpd\b|\bospfd\b|\bipsengine\b|\breportdb\b|\bredis\b|\bpostgres(?:ql)?\b", C["teal"]),
    (r"\bAccept\b", C["green"]),
    (r"\bDrop\b|\bDeny\b|\bReject\b", C["red"]),
    (r"\bBypass\b", C["orange"]),
    (r"\bFastPath\b|\bSlowPath\b|\bConntrack\b", C["teal"]),
    (r"\bChild SA\b|\bIKE SA\b|\bDPD\b|\bRekey\b|\bDead Peer\b|\bSSL VPN\b|\bL2TP\b|\bXFRM\b", C["purple"]),
    (r"\bHeartbeat\b|\bSplit Brain\b|\bFailover\b|\bAuxiliary\b|\bPrimary\b", C["blue"]),
    (r"\bRoute Lookup\b|\bPolicy Route\b|\bGateway Health\b|\bWAN Link Manager\b|\bSD-WAN Route\b", C["blue"]),
    (r"\bIPS\b|\bATP\b|\bSandstorm\b|\bWeb Filter\b|\bApplication Filter\b|\bSSL/TLS Inspection\b", C["purple"]),
    (r"\baccess_server\.log\b|\bawarren\.log\b|\bcsc\.log\b|\bconfd\.log\b|\bfirewall_rule\.log\b|\bfwlog\.log\b|\bsslvpn\.log\b|\breverseproxy\.log\b|\bstrongswan\.log\b", C["yellow"]),
    (r"\bAudit\b|\bConfiguration Change\b|\bAdministrator\b", C["yellow"]),
])

# ---------------------------------------------------------------------------
# 11. Linux / Cloud / Storage / Optics / Hardware
# ---------------------------------------------------------------------------
sec("Linux", [
    (r"\bsystemctl\b|\bjournalctl\b|\biptables\b|\bnft\b", C["teal"]),
    (r"\bip\s+(?:addr|link|neigh|route)\b|\bbridge\b|\btc\b|\bss\b|\bnetstat\b|\bethtool\b|\bnmcli\b", C["teal"]),
])

sec("Tcpdump_Output", [
    # TCP flag brackets, e.g. "Flags [S]", "Flags [S.]", "Flags [R]",
    # ordered most-critical-letter-first: a reset anywhere in the bracket
    # is the most important signal, then SYN (connection start), then FIN
    # (connection close); plain "[.]" is just an ack with no flags set.
    (r"\bFlags \[[^\]]*R[^\]]*\]", C["red"]),
    (r"\bFlags \[[^\]]*S[^\]]*\]", C["green"]),
    (r"\bFlags \[[^\]]*F[^\]]*\]", C["orange"]),
    (r"\bFlags \[\.\]", C["teal"]),
    (r"\bseq \d+(?::\d+)?\b|\back \d+\b|\bwin \d+\b|\blength \d+\b", C["teal"]),
    (r"\bICMP6?\b", C["pink"]),
    (r"\b\d{2}:\d{2}:\d{2}\.\d{6}\b", C["teal"]),  # tcpdump's microsecond timestamp
])

sec("Cloud", [
    (r"\b(?:vpc|subnet-[0-9a-f]+|sg-[0-9a-f]+|eni-[0-9a-f]+|igw-[0-9a-f]+|tgw-[0-9a-f]+)\b", C["teal"]),
    (r"\bTransit Gateway\b|\bDirect Connect\b|\bGWLB\b|\bPrivateLink\b|\bVPC Endpoint\b", C["teal"]),
    (r"\bRoute Table\b|\bNACL\b|\bSecurity Group\b", C["teal"]),
    (r"\bNSG\b|\bVNet\b|\bUDR\b|\bExpressRoute\b", C["teal"]),
    (r"\bNSX\b|\bT0\b|\bT1\b(?=\s)|\bTransport ?node\b", C["teal"]),
])

sec("Storage", [
    (r"\bLUN\b|\biSCSI\b|\bFCoE\b|\bzoneset\b|\bvsan\b", C["teal"]),
])

sec("Optics", [
    (r"\bSFP\+?\b|\bQSFP(?:\+|28)?\b|\bDOM\b|\bLOS\b|\bLOF\b", C["teal"]),
    (r"\bTx Power\b|\bRx Power\b|\bLaser Bias\b", C["teal"]),
    # Bare Temperature/Voltage/Current are too generic on their own (they'd
    # also light up "Current configuration" in every "show run"), so these
    # only match the colon/equals reading format optics DOM output uses.
    (r"\b(?:Temperature|Voltage|Bias Current)\s*[:=]\s*[-\d.]+", C["teal"]),
])

sec("Hardware", [
    # "show inventory" prints "SN: FOC1234X5YZ" with a space after the colon.
    (r"\bPID\b|\bVID\b|\bS/N\b|\bSN:\s*\S+\b|\bserial number\b", C["teal"]),
    (r"\bSupervisor\b|\bLinecard\b|\bFabric Module\b|\bRSP\b|\bFPGA\b", C["teal"]),
    # Bare "LC" is too short/ambiguous as a standalone token; only match it
    # in the slot/subslot form Cisco actually prints (e.g. "LC 1/0").
    (r"\bLC\s?\d+/\d+\b", C["teal"]),
])

# ---------------------------------------------------------------------------
# 12. Counters (only highlighted when non-zero -- the "0 " / "no " prefixed
#     forms are intentionally left unmatched so healthy counters stay plain)
# ---------------------------------------------------------------------------
sec("Counters_Non_Zero", [
    # Covers the three phrasings vendors actually use for the same counter:
    # "123 CRC", "CRC errors: 123", "CRC = 123" (and the input/output/runts/
    # giants/collisions/pause-frames/output-drops/interface-resets family).
    (r"(?:CRC|input errors?|output errors?|runts|giants|collisions?|pause frames?|output drops?|interface resets?)\s*[:=]\s*[1-9][0-9]*\b", C["red"]),
    (r"\b[1-9][0-9]*\s+(?:CRC|input errors?|output errors?|runts|giants|collisions?|pause frames?|output drops?|interface resets?)\b", C["red"]),
    # "show environment" prints status in a separate table column rather
    # than the literal phrase "Power Supply 1 Failed", so this matches
    # Power Supply/Fan and a failure word anywhere on the same line instead
    # of requiring exact adjacency.
    (r"\bPower Supply\b.{0,40}?\b(?:Failed|Faulty|Shutdown)\b|\bFan\s*\d*\b.{0,40}?\b(?:Failed|Faulty)\b", C["red"]),
    (r"\b(?:Temperature|Thermal) Alarm\b|\boverheat\b", C["red"]),
])

# ---------------------------------------------------------------------------
# 13. Errors / Warnings
# ---------------------------------------------------------------------------
sec("Errors", [
    (r"\berr-disabled?\b|\bfail(?:ed|ure)?\b|\binvalid\b|\bdenied\b|\bunreachable\b", C["red"]),
])

sec("Warnings", [
    (r"\bwarning\b|\bdeprecated\b|\bmismatch\b|\bdegraded\b|\bflapping\b", C["orange"]),
])

# ---------------------------------------------------------------------------
# 14. Interface state intelligence (green/orange/red tri-state)
# ---------------------------------------------------------------------------
sec("Interface_State_Good", [
    # "active"/"established" intentionally excluded: BGP's [*]BGP section
    # owns those tokens already (orange/green respectively) and is evaluated
    # first, so duplicating them here would be unreachable, not just redundant.
    (r"\b(?:is )?up\b|\bconnected\b|\bforwarding\b|\bfull[- ]duplex\b|\brunning\b|\benabled\b", C["green"]),
])

sec("Interface_State_Transitional", [
    (r"\binit(?:ializing)?\b|\bloading\b|\bnegotiating\b|\bwaiting\b", C["orange"]),
])

sec("Interface_State_Bad", [
    # Plain \bdown\b is too broad (it'd light up any standalone word "down"
    # regardless of context). Restrict to the phrasings interfaces/protocols
    # actually use: "<x> is down", "line protocol is down", "status: down",
    # or "down" as a table column value (preceded by 2+ spaces of padding).
    (r"\badministratively down\b", C["red"]),
    (r"\b(?:line protocol is|status\s*:?|is)\s+down\b", C["red"]),
    (r"(?<=\s\s)down\b", C["red"]),
    (r"\berr-disabled\b|\bdisabled\b", C["red"]),
])

# ---------------------------------------------------------------------------
# 15. Dangerous commands -- reverse video
# ---------------------------------------------------------------------------
sec("Dangerous_Commands", [
    (r"\breload\b", C["red"], REVERSE_FLAGS),
    (r"\berase\b|\bwrite erase\b|\berase startup-config\b", C["red"], REVERSE_FLAGS),
    (r"\bdelete\b", C["red"], REVERSE_FLAGS),
    (r"\bformat\b", C["red"], REVERSE_FLAGS),
    (r"\bboot system\b", C["red"], REVERSE_FLAGS),
    (r"\bcopy (?:startup-config running-config|running-config startup-config)\b", C["red"], REVERSE_FLAGS),
    (r"\bcommit replace\b", C["red"], REVERSE_FLAGS),
    (r"\brollback\b", C["red"], REVERSE_FLAGS),
    (r"\bfactory[- ]reset\b", C["red"], REVERSE_FLAGS),
    (r"\blicense smart deregister\b", C["red"], REVERSE_FLAGS),
])

# ---------------------------------------------------------------------------
# 16. Interactive prompts / progress indicators
# ---------------------------------------------------------------------------
sec("Interactive_Prompts", [
    (r"\[confirm\]|\(yes/no\)[:?]|\[yes/no\]:|--More--|<--- More --->", C["yellow"]),
])

sec("Progress_Indicators", [
    (r"^\s*!+\s*$|^\s*\.+\s*$|\[#+\]|Building configuration\.\.\.", C["teal"]),
])

# ---------------------------------------------------------------------------
# 17. Misc / catch-all
# ---------------------------------------------------------------------------
sec("Miscellaneous", [
    (r"\bdescription\s+.*", C["teal"]),
    (r"\bMTU\b|\bBW\b|\bDLY\b", C["teal"]),
])


# ---------------------------------------------------------------------------
# Build the output
# ---------------------------------------------------------------------------
def header(name):
    # Banner-style for readability while maintaining a maintenance journal,
    # but every variant still starts with the literal "[*]" prefix used by
    # the source files specifically because it cannot appear in real CLI
    # output -- a "####" banner alone risks colliding with progress-bar
    # output like "[####]", which is exactly the kind of self-inflicted
    # conflict this rewrite is trying to eliminate.
    label = name.replace("_", " ")
    banner = f"[*]{'=' * 8} {label} {'=' * 8}"
    return (banner, C["grey"], (HEADER_FLAGS, HEADER_FLAGS))


def flatten():
    rows = []
    seen = set()
    for name, entries in SECTIONS:
        rows.append(header(name))
        for entry in entries:
            if len(entry) == 2:
                regex, color = entry
                flags = NORMAL_FLAGS
            else:
                regex, color, flags = entry
            if regex in seen:
                raise SystemExit(f"Duplicate regex across sections: {regex!r}")
            seen.add(regex)
            try:
                re.compile(regex)
            except re.error as exc:
                raise SystemExit(f"Invalid regex in section {name!r}: {regex!r} ({exc})")
            rows.append((regex, color, flags))
    return rows


def render(rows):
    lines = []
    lines.append('S:"List Name"=Network Engineer Ultimate')
    lines.append('D:"Regex Line Mode"=00000001')
    lines.append('D:"Match Case"=00000000')
    lines.append(f'Z:"Keyword List V3"={len(rows):08x}')
    for row in rows:
        if len(row) == 2:
            regex, color = row
            flags = NORMAL_FLAGS
        else:
            regex, color, flags = row
        escaped = regex.replace('"', '\\"')
        lines.append(f' "{escaped}",{color},{flags[0]},{flags[1]}')
    return "\n".join(lines) + "\n"


def main():
    rows = flatten()
    out = render(rows)
    out_path = "build/Network Engineer Ultimate.ini"
    with open(out_path, "w") as fh:
        fh.write(out)
    print(f"Wrote {out_path} with {len(rows)} entries "
          f"({sum(1 for r in rows if r[0].startswith('[*]'))} sections, "
          f"{sum(1 for r in rows if not r[0].startswith('[*]'))} regexes)")


if __name__ == "__main__":
    main()
