# Console app conventions

Rules for everyone who builds screens of the new console (`/app/`). The
component gallery at `/app/dev/components` shows every shared component with
sample data; its source (`src/app/gallery.tsx`) is the usage reference.

## Areas and ownership

Each feature stream owns whole directories and touches shared files only
with one line per addition.

| Stream | Frontend area (`web/src/areas/`) | Go files (`internal/server/`) |
|---|---|---|
| Dashboard | `home`, `inbox`, `activity`, `reports` | `app_home.go`, `app_inbox.go`, `app_activity.go`, `app_reports.go` |
| Devices | `devices` | `app_devices.go` |
| Compliance | `compliance` | `app_compliance.go` |
| Configuration (blueprints, library, software, packages) | `config` | `app_config.go` |
| Administration (users, tenants, tokens, approvals settings, keys, backup, retention, operations, notifications, SSO, directory, network, agents, enrollment, audit) | `settings` | `app_settings.go` |

A new area directory is fine; register it with one line each in
`src/app/areas.ts` and `src/i18n/catalog.ts` (import, list entry, `typeof x.de`).

## File layout of an area

```
web/src/areas/<area>/
  routes.tsx     export const <area>Area: Area  (routes, nav entry, palette commands)
  pages.tsx      page components, loaded lazily (split into more files as it grows)
  api.ts         TanStack Query hooks of the area (query keys start with the area)
  messages.ts    German catalog `de` (source) and English `en` with the same keys
  *.test.ts(x)   Vitest tests of the area's logic
web/e2e/<area>.spec.ts  Playwright tests of the area's main flows
```

Shared code lives in `src/components` (UI), `src/lib` (pure logic),
`src/api` (client, me, live, views), `src/i18n`, `src/app` (shell, router).
Change shared code only to fix it or to add something every area needs; say
so in the commit message.

## Routes

* Add routes in your `routes.tsx` with `createRoute({ getParentRoute: () => shell, path, component: lazyRouteComponent(() => import('./pages'), 'Page'), validateSearch })`.
* Every view state lives in the URL: filter (`q`), sort, selected row (`sel`), tab, open sheet. Read it with `useSearch({ strict: false })`, write it with `useNavigate()({ search })`.
* The nav entry (`nav`) sets order and icon; `permission` hides it from roles without it; `views: '<list>'` lists saved views under it.
* Paths are relative to `/app` (the router's basepath). Links into the classic console are plain `<a href>`.
* Deep links other areas rely on: settings sections are `/settings?s=<section>`, and `/settings/<name>` redirects there through the alias table in `areas/settings/routes.tsx` (`branding`, `sso`, `security`, ...); `/settings/enrollment` redirects to the add device page `/devices/enroll`, which owns the enrollment tokens; the configuration tabs are `/config?tab=<tab>` (`blueprints`, `library`, `software`); the inbox selects with `/inbox?item=a<approval id>` or `?group=approvals|warnings|commands`; activity filters with `/activity?q=&cat=&actor=&action=&target=&from=&to=`.

## API

* Client: `import { api, unwrap } from 'src/api/client'`, then `unwrap(api.GET('/api/v1/...', { params }))`. Types come from `openapi.json`; after changing it run `npm run api` and commit `src/api/schema.d.ts`.
* The session and CSRF header are handled by the client. Never use `fetch` directly for the API.
* Errors are `ApiError` with RFC 9457 problem details; show them with `ErrorState` or `toast(errorText(e), 'error')`. A 422 names the field in `problem.field`.
* Current user: `useMe()` (role, tenant, scopes, permissions, locale) and `useCan('admin' | 'commands' | 'audit' | 'read' | 'tenants')`. Hide what a role cannot do; the server checks again.
* Live updates: the shell opens `/api/v1/events/stream`. Device events invalidate query keys starting with `['devices']` and `['stats']`, activity events `['activity']`, inbox events `['approvals']`. Name your query keys accordingly to get live refreshes for free.

### Go endpoints

* Put them in `internal/server/app_<area>.go` with `func (s *Server) app<Area>Routes(m *http.ServeMux)` and register it with one line in `appAPIRoutes` (`appapi.go`).
* Guard every route with `s.need(level, h)`: `read`, `self`, `audit`, `helpdesk`, `admin`. For data or actions beyond the route's level use `c.can(level)` (role and token scopes), never the role alone.
* Reuse the shared functions of the console (the same ones the console pages and the token API call) so roles, four eyes, tenant, scope and audit rules stay identical. Use `c.sess()` for them, `scopeCond`, `tenantCond`, `auditScope` and `approvalCond` for SQL, `s.auditAction` or `audit(ctx, tx, ...)` for changes.
* Lists follow the conventions of `devicelist.go`: `filter` (query language), `sort` (`field` or `-field`), opaque keyset `cursor` / `next_cursor`, `limit` 1..500, and `<list>/facets` with counts.
* Document every endpoint in `internal/server/openapi.json` (paths and component schemas; keep your entries together) and add one Go test per endpoint in `app_<area>_test.go`.

## Declarations and JSON Schema

`GET /api/v1/schemas/{type}` serves the schema of a declaration payload,
derived from the Go types (`internal/api/schema.go`). Render it with
`SchemaForm`, validate with `validate(schema, value)` (errors keyed by JSON
pointer), offer `JsonEditor` as the expert mode and `DiffViewer` for the
change. Never hand code a declaration form; add `x-section`, `x-enumTitles`,
`x-widget` or `x-patternHint` on the server when the form needs them.

## Texts and languages

* Every visible text goes through `t('<area>.<key>')` (`useT()` in components). German is the source and uses the console glossary (Geräte, Blueprints, Bibliothek, Freigaben, konform, in Karenz, veraltet, ausstehend, ausgemustert, Mandant); English must have the same keys (the `en` type enforces it).
* Plurals: `{ one: '...', other: '...' }` with `{count}`; placeholders `{name}`; numbers in vars are formatted for the locale.
* Format numbers, dates and ages with `src/i18n/format.ts` (`fmt`, `pct`, `dateTime`, `ago`, `bytes`).
* `npm run lint` fails on used keys missing in a catalog and on catalog keys nobody uses.
* No hyphens as dashes in German or English prose.

## Components and accessibility

* Lists: `QueryBar` + `Facets` + `DataGrid` (+ `ColumnChooser`, `SavedViewsMenu`, `BulkActionBar`); details in a `SideSheet` inside `SplitView`. Below 768 px pass `card` to the grid.
* Forms: `Field` or `FormField` (react-hook-form with zod) in `FormSection`, `SaveBar` for unsaved changes, `Wizard` for multi step flows, `Modal` for confirmations.
* Charts: ECharts only through `EChart` and always inside `ChartFrame` with a table; small charts with `Sparkline`, `Bullet`, `StackBar`, `FleetGrid`. Status never by color alone.
* States: `LoadingState`, `EmptyState` (say what appears and offer the next step), `ErrorState`.
* WCAG 2.2 AA: every control has a label, errors use `aria-invalid` and `aria-describedby`, keyboard works everywhere (Esc, J/K in sheets, arrows in tabs), contrast via the color tokens only (`text-muted`, `bg-surface`, `text-bad` ...). Never hard code colors.
* Light, dark, comfortable and compact come from tokens in `src/styles.css`; use `var(--pad-card)`, `var(--gap)`, `row-h` instead of fixed spacing where density matters. Layouts must work at 390 px.

## CSP (no exceptions)

The console sends `default-src 'self'`: no inline script or style element,
no `eval`, no third party requests. React `style` props are fine (CSSOM).
Not allowed: `dangerouslySetInnerHTML`, libraries that compile code at run
time (Ajv, template compilers) or inject `<style>` (emotion, styled
components, Base UI ScrollArea and Select with `alignItemWithTrigger`,
cmdk's own `Command.Dialog`), CDN URLs, `data:` URLs. Every new library is
bundled, pinned to an exact version, and must pass `e2e/csp.spec.ts`: add
your pages to its list.

## Build and checks

* `make web` builds into `internal/server/webapp/dist`, which is committed. After merging another stream, rebuild and commit the dist instead of resolving conflicts in it by hand.
* Before a commit: `npm run lint`, `npm test`, `npm run build` (includes the bundle budget), and `npm run e2e` with `LIMDM_E2E_DATABASE_URL` set to your own disposable database.
