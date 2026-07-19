# Changelog

## v1.3

- Added a GitHub Pages documentation site at `securecrt.bytebox.network`, generated
  from the actual README/CHANGELOG content: platform/feature tables, install and
  maintaining guides, design principles, and full changelog history, plus a live
  terminal-style demo of the highlighting in action.
- Adopted a shared sidebar-nav documentation template (also used by other projects
  under bytebox.network), matching the main site's navy/sky-blue theme.
- Added VJ + ByteBox logo marks as favicon and nav brand mark.
- Fixed nav consistency: removed inconsistent button-styling from links so every
  nav item reads as plain navigation; "Home" link added back to the main site.
- Fixed a Safari compatibility bug (`backdrop-filter` missing the `-webkit-` prefix
  on the sticky nav).
- Removed `text-wrap: balance` from the docs site for broader Chrome compatibility.
- Cleaned up inline styles on the docs page, moving them into real CSS classes.
- Cleaned up repo hygiene: added a top-level heading to `LICENSE` (markdownlint
  MD041), fixed markdown table formatting and spell-check word list entries,
  removed committed Ruff cache directory and added it to `.gitignore`.

## v1.2

- Added `tools/test_samples.py`, which simulates SecureCRT's actual
  top-to-bottom, first-match-wins-per-character behaviour against realistic
  multi-vendor `show`-command/tool output, rather than only checking the
  generated file's own structure. Running it surfaced four real bugs, now
  fixed:
  - `*>` (BGP best-path marker) was being misidentified as a login prompt
    by the bare `^\S+>` rule; both prompt rules are now end-anchored
    (`^\S+>\s*$`) so they only match when the whole line is the prompt.
  - "line protocol is down" was losing its red colour to the generic
    console-line `\bline\b` rule; that rule now excludes `line` followed by
    `protocol`.
  - The Route Target/Distinguisher fallback `\d{1,10}:\d{1,10}` matched the
    seconds field of a BGP session uptime like `00:05:23`; removed the
    unlabeled fallback, keeping only the explicit `RT:`/`RD` forms.
  - EVPN route types were only matched as spelled-out words ("Type-2"),
    but real route tables print bracket notation
    (`[2]:[0]:[0]:[48]:[mac]:[32]:[ip]`); both forms are now matched.
  - `SN:` (show inventory) didn't allow the space Cisco actually prints
    after the colon; Nexus vPC's `keepalive` didn't match the hyphenated
    `keep-alive` spelling `show vpc` actually uses; Power Supply/Fan
    failure detection assumed an exact phrase that doesn't match real
    tabular `show environment` output and is now a same-line proximity
    match instead.
- Added a curated Sophos Firewall (SFOS) section: core platform terms,
  daemon/service names seen in troubleshooting logs (strongswan, zebra,
  bgpd, ospfd, etc.), firewall actions (Accept/Drop/Deny/Reject/Bypass),
  VPN/HA/routing events, security modules (IPS/ATP/Sandstorm/...), named
  log files, and audit terms. Deliberately excludes generic config nouns
  (Firewall, Rule, Policy, Host, Zone, Object) as noise, and HA's
  Active/Passive/Standby (already owned by earlier sections with the same
  colour).
- Added a tcpdump-output section: TCP flag brackets coloured by
  severity (`[R...]` red, `[S...]` green, `[F...]` orange, `[.]` teal),
  seq/ack/win/length fields, ICMP6, and the microsecond timestamp format.
- Removed the `source/` directory of legacy reference `.ini` files (and all
  references to it in the docs) -- this project is no longer presented as a
  merge of prior highlight packs, so there's no reason to carry them.
- Added a "Design principles" section to the README.

## v1.1

- Added NX-OS fabric (CFSoE, FabricPath, OTV, FEX, VN-Segment), Cisco SD-WAN
  (OMP, vSmart/vBond/vManage/vEdge, TLOC, Control Connections, BFD Sessions),
  expanded AWS (Transit Gateway, Direct Connect, GWLB, PrivateLink, VPC
  Endpoint, Route Table, NACL, Security Group), and expanded Linux (`ip
  addr/link/neigh/route`, bridge, tc, ss, netstat, ethtool, nmcli) sections.
- Added Cisco bug ID (`CSCxxNNNNN`) and CVE highlighting.
- Added Nexus vPC and StackWise/VSS sections.
- Added EVPN route types (Type-2/3/5, IMET, MAC/IP, BUM, ESI), scoped to
  avoid colliding with Nexus vPC's unrelated "Type-1/2 (in)consistency"
  wording.
- Split syslog severity into four colour tiers (0-3 red, 4-5 orange, 6
  white, 7 grey) instead of one flat colour for every `%FACILITY-N-...` line.
- Made interface "down" state context-aware (requires "is down", "line
  protocol is down", "status: down", or a table-column position) instead of
  matching the bare word anywhere on the line; removed OSPF's duplicate
  bare `Down` rule, which had the same problem.
- Removed several redundant case-duplicated alternations (e.g.
  `\bbgp\b|\bBGP\b`) now that `Match Case=0` already makes them
  case-insensitive.
- Reorganized `docs/COLOR_GUIDE.md` by semantic meaning; added LICENSE
  (MIT) and moved CHANGELOG.md to the repo root.

## v1.0 - Network Engineer Ultimate

Initial release. Engineered from scratch (not merged from prior highlight
files) as a generated, validated keyword-highlight pack.

44 sections, 118 regex rules, generated and validated via `tools/build.py`
and `tools/validate_highlights.py`. Covers Cisco IOS/IOS-XE/NX-OS/IOS-XR/ASA,
Arista EOS, Juniper JunOS, Linux, FRRouting, VyOS, Fortinet, Palo Alto,
AWS/Azure/NSX networking, and WireGuard. Dark-background palette only;
targets the current SecureCRT keyword-highlight format (V3 list, no legacy
V2 section).
