# Auth State Snapshot and SPA Explore Design

## Context

`TOOLS/auth/auth_explore.py` currently discovers authenticated navigation mostly from real `href` links. This misses many modern portal entries, especially Vue/SPA portal cards whose destinations are driven by click handlers, hash routes, or API-returned menu data. On the Taizhou University fusion portal (`https://portal.tzc.edu.cn/main.html#/IndexView`), this causes poor expansion of reachable authenticated surfaces.

The authentication workflow has a second bottleneck: automatic relogin depends too heavily on `browser-use`. That path is slow, sometimes hard to locate in the current environment, and does not make it easy for parallel Codex sessions to reuse cookies or tokens after login succeeds.

## Goals

- Make the logged-in Chrome/CDP session the primary source of truth for authentication state.
- Allow any scanner/review session to quickly capture and reuse cookies, localStorage, sessionStorage, and bearer/JWT-like tokens.
- Keep `browser-use` as a fallback login assistant, not the default session renewal path.
- Improve `auth_explore.py` so it discovers SPA/hash/click-driven portal entries, not only normal anchors.
- Preserve existing DB compatibility for cookie users while adding structured storage for non-cookie tokens.
- Avoid unsafe UI actions such as logout, delete, submit, pay, bind, or destructive confirmation.

## Non-Goals

- This design does not add exploit verification or aggressive vulnerability testing.
- This design does not bypass CAPTCHA/SMS/QR login. Those remain operator-assisted or handled by the existing login helper.
- This design does not replace Burp or existing DB-driven coordination.
- This design does not click form submission or destructive workflow buttons during exploration.

## Architecture

Add a shared auth state layer under `TOOLS/auth/`, preferably `auth_state.py`, with a small CLI:

- `capture --target <name>`: connect to the target's `scan_state.cdp_url`, export browser state, and write it to the DB.
- `ensure --target <name>`: validate existing DB session; if invalid, try CDP capture; only if that fails, call the existing `browser_auth.py` fallback.
- `export-header --target <name> --url <url>`: print a JSON object with reusable headers such as `Cookie` and `Authorization`.

`session_manager.py` should become a thin compatibility wrapper around this shared layer, so existing callers keep working.

`browser_auth.py` should keep handling first login and difficult login flows. After successful login it should call the shared capture logic instead of maintaining separate cookie persistence behavior.

## Data Model

Cookies continue to be written into `auth_sessions` because existing tools already consume that table through `cookie_helper.py`.

Add one new table for storage-backed tokens:

```sql
CREATE TABLE IF NOT EXISTS auth_storage_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT DEFAULT 'primary',
    storage_type TEXT NOT NULL,
    origin TEXT NOT NULL,
    token_name TEXT NOT NULL,
    token_value TEXT NOT NULL,
    token_kind TEXT DEFAULT 'storage',
    is_active INTEGER DEFAULT 1,
    first_seen_at TEXT DEFAULT (datetime('now','localtime')),
    last_seen_at TEXT DEFAULT (datetime('now','localtime')),
    expires_at TEXT,
    source TEXT DEFAULT 'cdp_capture',
    UNIQUE(role, storage_type, origin, token_name)
);
```

`storage_type` values are `localStorage`, `sessionStorage`, or `derived`.

`token_kind` values include `jwt`, `bearer`, `csrf`, `api_key`, and `storage`. The implementation should classify conservatively with simple patterns, not decode or validate secrets unless needed for expiry metadata.

## Auth State Flow

1. `ensure` runs `TOOLS/db/auth_check.py --update`.
2. If `auth_sessions` has an active, unexpired cookie for the target, return success.
3. If the DB has a `cdp_url`, connect to Chrome and capture browser state.
4. Write captured cookies to `auth_sessions` and storage/token values to `auth_storage_tokens`.
5. Re-run the local validity check.
6. If still invalid and credentials/login URL are available, call `browser_auth.py`.
7. If browser auth succeeds, capture state again through `auth_state.py`.
8. If all paths fail, return a clear operator-facing message that manual login is needed.

This keeps fast reuse on the common path and isolates slow login automation to the rare path.

## SPA Explore Flow

`auth_explore.py` should replace the current `nav_hrefs` list with a normalized navigation candidate queue. Candidate sources:

- Normal anchors with absolute, root-relative, relative, or hash routes.
- Hash routes such as `#/IndexView`, `/main.html#/foo`, and route-like strings returned by API responses.
- Clickable UI elements: `button`, `[role=button]`, `[role=menuitem]`, `[role=tab]`, `.el-menu-item`, `.ant-menu-item`, `.el-card`, `.ant-card`, `.menu-item`, `.nav-item`, and elements with `onclick`, `data-url`, `data-href`, `data-route`, or `data-path`.
- XHR/fetch JSON responses containing likely entry fields such as `url`, `href`, `link`, `path`, `route`, `targetUrl`, `redirectUrl`, or `appUrl`.

Each candidate should include:

- `kind`: `url`, `hash`, `click`, or `response_url`.
- `value`: URL/hash/selector payload.
- `label`: short UI or response-derived label.
- `source`: DOM selector, response URL, or parent context.

The explorer should process candidates with bounds:

- Deduplicate by normalized URL/hash/element fingerprint.
- Limit top-level candidates and per-page sub-candidates.
- Stay same-site or same registrable domain, matching current project rules.
- Skip static resources.
- Skip unsafe labels and selectors.

For click candidates, the explorer should:

1. Record the current URL and current request count.
2. Click with a short timeout.
3. Wait briefly for network activity, URL changes, popup pages, or DOM route changes.
4. Add the resulting page URL and any newly discovered API requests.
5. Return to the seed page or previous route when practical.

## Safety Rules

Do not click elements whose visible text, aria label, title, or nearby metadata contains destructive or session-ending terms. The initial denylist should include:

- logout, sign out, exit, delete, remove, submit, save, confirm, pay, bind, unbind
- 退出, 注销, 删除, 移除, 提交, 保存, 确认, 支付, 绑定, 解绑

The explorer should prefer navigation-looking cards and menu items over form buttons. It should not fill forms or submit user-controlled data.

## Error Handling

- CDP unavailable: report clearly and fall back according to `ensure` rules.
- Browser context missing: create a context only when needed, but prefer the existing logged-in context.
- Storage capture failures: keep cookies and continue; log the failed origin.
- SPA click failures: skip the candidate and continue.
- API response parsing failures: ignore that response body and continue.

## Testing

Unit tests should cover:

- URL and hash route normalization.
- Unsafe clickable label filtering.
- Extraction of response URLs/routes from nested JSON.
- Cookie and storage token DB upsert behavior.
- `ensure` priority order: valid DB session, CDP capture, browser-use fallback.

Browser-level verification should use a local/mock SPA when possible. For real targets, only authorized assets may be tested.

## Implementation Order

1. Add schema migration and tests for `auth_storage_tokens`.
2. Add `auth_state.py` pure helpers and DB write functions.
3. Wire `session_manager.py` to prefer auth state capture before browser-use fallback.
4. Update `browser_auth.py` to call the shared capture logic after login.
5. Add SPA candidate extraction helpers in `auth_explore.py`.
6. Replace href-only traversal with candidate queue traversal.
7. Run focused tests, then the existing `TOOLS/tests` suite.

## Acceptance Criteria

- A second session can call `session_manager.py --target <name>` and reuse the Chrome login state without invoking browser-use when CDP has a valid logged-in context.
- Cookies remain available through `cookie_helper.py`.
- Storage-backed JWT/bearer-like tokens are persisted in `auth_storage_tokens`.
- `auth_explore.py` discovers hash routes, click-driven portal cards, and API-returned entry URLs.
- The explorer records resulting authenticated API requests with meaningful `nav_context`.
- The implementation does not write temporary files outside `tmp/`.
