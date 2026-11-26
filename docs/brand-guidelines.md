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
| `--text-3` | `#6b737c` | `#7f8891` | labels, table heads, meta |
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

A rounded square in the accent teal (a slight vertical shade from `#16857f` to `#0c5b58`)
with a white shield and a terminal prompt chevron and cursor in `--accent`: the device under
management. Files: `internal/server/web/static/logo.svg` (also `packaging/artwork/limdm.svg`
and the favicon) and the monochrome `packaging/artwork/limdm-symbolic.svg` for panels and
trays. Never stretched, minimum 20px. The shade inside the mark is the only gradient.

## Layout

Fixed sidebar (224px, `--nav` in both themes) and a content column that uses the full
width. Below 860px the sidebar collapses behind a menu button. Cards group related facts;
tables carry lists. Status is always a dot plus a word, never colour alone.

## Customer branding

Customers can show their own company name, logo and accent colour. LiMDM stays the product
name in texts; the customer branding replaces only the name and mark in the sidebar and in
the desktop helper. The login page has no session yet and always shows the global branding.

| Setting | Where | Rules |
|---|---|---|
| Global branding | **Settings**, **Branding**: **Company name**, **Logo** | name up to 80 characters; logo PNG only, at most 256 KiB, 16 to 1024 px per side |
| Tenant branding | **Company** (tenant admins) or the tenant's page (global administrators), section **Branding**: **Company name**, **Logo (PNG)**, **Accent color** | name up to 100 characters; same logo rules; colour as `#rrggbb` |

* Fallback: an empty tenant name or logo uses the global one; with neither set, the console
  shows the LiMDM mark and the name "LiMDM". There is no global accent colour: without a
  tenant colour the console keeps `--accent` from the table above.
* The tenant accent colour replaces `--accent` in light and dark mode through
  `/branding/tenant.css` (a file, because the CSP forbids inline styles). Choosing the
  default `#0f6e6e` stores no colour. Pick a colour that keeps links and primary buttons at
  4.5:1 or better on `--surface` in both modes; the server does not check contrast.
* Status colours (`--ok`, `--bad`, `--warn`) never change with the branding.
* Devices receive the branding of their tenant (name and logo, no colour) with the check in
  and show it in the desktop helper. Changes reach the console and devices within a minute
  (cached per server instance).
* Only PNG logos: an SVG served from the console's origin could carry script. The sidebar
  shows the logo at up to 120 by 28 px.

See [tenants.md](tenants.md#branding) and [configuration.md](configuration.md#branding).
