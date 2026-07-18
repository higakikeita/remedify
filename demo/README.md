# 90-second demo

`demo.sh` is a fully offline, reproducible walkthrough (committed example
scans — no real Trivy or network needed). It tells the story the tool is
about: **a scanner found the CVEs → remedify makes the plan → you apply it →
remedify proves what actually got fixed.**

## Record it

```bash
# asciinema + agg (https://github.com/asciinema/agg) for a GIF
asciinema rec -c "demo/demo.sh" remedify-demo.cast
agg remedify-demo.cast docs/remedify-demo.gif
```

Then embed at the top of the main README:

```markdown
![remedify demo](docs/remedify-demo.gif)
```

## Storyboard (~90s)

| t | beat | on screen |
|---|---|---|
| 0–10s | the hook | "Your scanner found the CVEs. Now what do you actually run?" |
| 10–35s | the plan | `remedify scan.json` → 8 findings collapse to 5 steps; libc source-group is one command; backport + reboot called out; container-rebuild banner |
| 35–50s | apply | `remedify scan.json --format shell > fix.sh && sudo bash fix.sh` |
| 50–90s | **the proof** | `remedify --baseline scan.json after.json` → **Fixed 5/7 (71%)**; libssl3 "upgraded but short" (.17→need .18); kernel untouched; libxml2 new |
| end | CTA | `pip install remedify` · repo URL |

## Why this beats a feature list

The payoff is the last beat: most tools stop at "here's the fix." remedify
**proves the fix landed** — and catches the two things that quietly bite you
(upgraded-but-not-far-enough, and a new CVE introduced by the rebuild). That
"oh, that's the thing I do by hand" moment is what makes people share it.
