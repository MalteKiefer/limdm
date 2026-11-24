# LiMDM brand guidelines

LiMDM is an operations console for security and compliance teams. The interface
should read like a well kept instrument panel: calm, dense, exact.

## Voice

- Plain, technical English. Name the thing, then the state: "Firewall active", "3 checks failing".
- No marketing tone, no exclamation marks, no emoji, no filler ("simply", "just", "seamless").
- Numbers and identifiers are shown exactly; units always (GiB, h, min).
- Errors say what failed and what to do next.

## Colour

One accent, neutrals for everything else, status colours only for status.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--accent` | `#0f6e6e` | `#3fb5ad` | primary actions, active navigation, links |
| `--bg` | `#f5f6f7` | `#0e1113` | application background |
| `--surface` | `#ffffff` | `#15191c` | cards, tables |
| `--text` | `#16191d` | `#e6e9ec` | body text (contrast ≥ 12:1) |
| `--text-2` | `#4b535c` | `#aab2ba` | secondary text (≥ 7:1) |
| `--ok` | `#1a7f4b` | `#45c486` | compliant, pass, active |
| `--bad` | `#b42318` | `#f07a6e` | non-compliant, fail, destructive |
| `--warn` | `#8a5a00` | `#e3b341` | pending, stale, exception |
| `--nav` | `#15191c` | `#0a0c0e` | sidebar, in both themes |

No gradients, no glass effects, no coloured shadows. Borders are 1px hairlines.

## Typography

System font stack (the strict CSP allows no external fonts); `ui-monospace` for
IDs, hashes, package names and versions. Tabular figures for all numbers.

| Role | Size / weight |
|---|---|
| Page title | 20px / 600 |
| Section title | 15px / 600 |
| Body, tables | 14px / 400 |
| Labels, meta | 12px / 500 |
| Key figures | 28px / 600, tabular |

## Mark

A rounded square with a terminal prompt chevron: the device under management.
Monochrome, `--accent` on dark, never stretched, minimum 20px.

## Layout

Fixed sidebar, content column up to 1280px. Cards group related facts; tables
carry lists. Status is always a dot plus a word, never colour alone.
