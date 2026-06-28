# Regex Guide

## Conventions used throughout `tools/build.py`

- Non-capturing groups `(?:...)` everywhere a capture isn't needed.
- `\b` word boundaries instead of bare substrings, so e.g. `\bup\b` doesn't
  also light up "backup" or "lookup".
- Bounded quantifiers (`{1,3}`, `[0-9]+` anchored by `\b`) instead of bare
  `.*`, which is both slow and tends to swallow the rest of the line.
- Sections are ordered most-specific first: interface patterns that include
  a slot/port number come before the bare letter-prefix fallback, and
  protocol-specific session states (BGP's `Active`) are placed before
  generic English words that could otherwise shadow them.

## Known, accepted limitation: token reuse across protocols

SecureCRT highlighting matches text, not semantics. Words like `Active`,
`Down`, or `Standby` mean different things in BGP vs. HSRP vs. plain
interface state, and a flat list can only colour each literal token once
(whichever section defines it first wins for that token, everywhere it
appears in the terminal). Every contested token found so far has a single
owning section -- documented inline in `build.py` next to the regex that
"lost" the token -- rather than being left as a silently-unreachable
duplicate rule.

## Adding a new rule

1. Open `tools/build.py`.
2. Find (or add) the relevant `sec("Name", [...])` call.
3. Add `(regex, color)` or `(regex, color, flags_tuple)`.
4. Run `python3 tools/build.py` -- it will raise immediately if your regex
   duplicates an existing one or fails to compile.
5. Run `python3 tools/validate_highlights.py` to confirm the output file
   itself is consistent.
6. Run `python3 tools/test_samples.py` and check your new rule renders the
   way you expect against realistic CLI output -- this is what caught the
   `*>` BGP best-path marker being misidentified as a login prompt, "line
   protocol is down" losing its color to the console-line rule, and a route
   target regex matching a timestamp's seconds field. A regex that compiles
   fine can still be wrong on real text; only running it against samples
   catches that.
