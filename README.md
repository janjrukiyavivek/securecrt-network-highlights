# securecrt-network-highlights

A SecureCRT keyword highlighting pack for enterprise network engineers:
**Network Engineer Ultimate**.

📖 **[Full documentation site →](https://securecrt.bytebox.network)**

## Design principles

- Designed for production troubleshooting, not a colorful terminal. A rule
  only exists if it highlights a condition that needs attention or speeds up
  reading dense CLI output -- not because the word looked interesting.
- Highlight the exception, not the norm: counters only light up when
  non-zero, "down" only matches when it's actually describing link/protocol
  state, not any standalone occurrence of the word.
- Specific regex before generic regex, always. SecureCRT applies the first
  matching rule top-to-bottom per character, so ordering is not cosmetic --
  it's the mechanism that decides which color wins a contested word.
- Generated from data (`tools/build.py`), not hand-edited, so duplicate and
  conflicting rules are caught by the build itself instead of accumulating
  silently over years of pasted-in edits.
- **Scope**: this project intentionally focuses on platforms and operational
  outputs that are actively used and validated against real sample output
  (see `tools/test_samples.py`). New vendor support is added based on
  real-world usage rather than completeness for its own sake -- that's why,
  for example, Palo Alto and Fortinet only get generic cross-vendor tokens
  today and ACI isn't covered at all.

## What is this?

A single SecureCRT keyword-highlight file, generated and validated from a
Python build script rather than hand-edited, covering the multi-vendor CLI
output a network engineer actually sees day to day: interface state, routing
protocols, syslog severity, dangerous commands, and more.

## Why is it better than existing highlight packs?

Most highlight files accumulate duplicate and conflicting rules over years
of manual edits -- the same word ends up colored two different ways
depending on which rule was pasted in last, and nobody notices because
SecureCRT silently uses whichever rule comes first. This pack is generated
from `tools/build.py`, which refuses to build if a regex is duplicated or
fails to compile, and `tools/validate_highlights.py` independently checks
the output file's structure. Every cross-section word collision found during
development (e.g. "Active" meaning three different things in BGP vs. HSRP
vs. generic interface state) was deliberately resolved and documented inline
in the build script, not left as a silent bug.

## What platforms are supported?

| Platform     | Supported |
| ------------ | :-------: |
| Cisco IOS    | ✅ |
| Cisco IOS-XE | ✅ |
| Cisco NX-OS  | ✅ |
| Cisco IOS-XR | ✅ |
| Cisco ASA    | ✅ |
| Arista EOS   | ✅ |
| Juniper JunOS| ✅ |
| Linux        | ✅ |
| FRRouting / VyOS | ✅ |
| AWS networking | ✅ |
| Azure networking | ✅ |
| VMware NSX   | ✅ |
| WireGuard    | ✅ |
| Cisco SD-WAN (vManage/vSmart/vBond) | ✅ |
| Sophos Firewall (SFOS) | ✅ |
| tcpdump output | ✅ |

## What features are covered?

| Feature              | Supported |
| --------------------- | :-------: |
| BGP / OSPF / ISIS / EIGRP / RIP | ✅ |
| MPLS / LDP / Segment Routing | ✅ |
| VXLAN / EVPN (route types) | ✅ |
| HSRP / VRRP / GLBP (FHRP) | ✅ |
| PIM / MSDP / IGMP | ✅ |
| Nexus vPC | ✅ |
| StackWise / VSS | ✅ |
| Syslog severity (0-7, colour per tier) | ✅ |
| Dangerous commands (reverse video) | ✅ |
| Optical DOM readings | ✅ |
| Hardware (Supervisor/Linecard/FPGA/...) | ✅ |
| Cisco bug IDs (CSCxxNNNNN) / CVEs | ✅ |
| Sophos VPN/HA/firewall-action events | ✅ |
| tcpdump TCP flags ([S]/[R]/[F]/[.]) | ✅ |

## What isn't supported?

- **Palo Alto / Fortinet / FTD CLI specifics** -- only generic, cross-vendor
  tokens (ACL, IPsec, IKE, etc.) will highlight; vendor-specific command
  syntax for these isn't covered yet.
- **Cisco ACI** -- not covered.
- **Context beyond the current line.** SecureCRT highlighting is per-line
  regex matching; it cannot tell BGP's "Active" state apart from an HSRP
  "Active" router by looking at surrounding lines. See `docs/REGEX_GUIDE.md`
  for how cross-protocol word collisions are resolved.

## How do I import it?

1. `python3 tools/build.py` to (re)generate `build/Network Engineer Ultimate.ini`.
2. `python3 tools/validate_highlights.py` to confirm it's well-formed.
3. In SecureCRT: Options > Session Options > Terminal > Emulation > Keyword
   Highlighting > Import, and select `build/Network Engineer Ultimate.ini`.

Download → Import → Done.

## How is it maintained?

All rules live as data in `tools/build.py` (see `docs/REGEX_GUIDE.md` for
conventions). To add or change a rule:

1. Edit `tools/build.py` -- it will fail loudly on a duplicate or invalid
   regex rather than silently producing a broken file.
2. Run `python3 tools/validate_highlights.py` to check the generated file's
   structure.
3. Run `python3 tools/test_samples.py` to see how the new rule renders
   against realistic multi-vendor `show`-command output, and check nothing
   else's coloring shifted as a side effect.

Releases are tracked in `CHANGELOG.md`.

## Layout

```text
tools/    build.py generates build/Network Engineer Ultimate.ini from data;
          validate_highlights.py checks the generated file for format/dup errors;
          test_samples.py runs the rules against realistic CLI output samples
build/    the generated output -- import this into SecureCRT
docs/     REGEX_GUIDE.md, COLOR_GUIDE.md, and the GitHub Pages documentation
          site (index.html) served at securecrt.bytebox.network
```
