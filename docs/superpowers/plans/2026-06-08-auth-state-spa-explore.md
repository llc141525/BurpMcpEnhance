# Auth State SPA Explore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build reusable CDP authentication-state capture and framework-neutral authenticated portal entry discovery.

**Architecture:** Add a focused `TOOLS/auth/auth_state.py` module for cookies, storage tokens, and CDP state export, then wire `session_manager.py` and `browser_auth.py` through it. Extend `auth_explore.py` with pure candidate extraction helpers and a bounded traversal queue that explores anchors, hash routes, clickable entries, data attributes, inline script routes, iframes, popup tabs, micro-frontend registry payloads, and API-returned menu URLs without depending on a specific frontend framework.

**Tech Stack:** Python 3, sqlite3, patchright CDP, pytest, existing SRC DB migrations.

---

### Task 1: Auth Storage Schema

**Files:**
- Create: `migrations/013_auth_storage_tokens.sql`
- Modify: `TOOLS/db/schema.sql`
- Test: `TOOLS/tests/test_auth_state.py`

- [ ] **Step 1: Write failing schema/token tests**

Add tests that create an in-memory DB with `auth_storage_tokens`, call the future `upsert_storage_tokens`, and assert duplicate `(role, storage_type, origin, token_name)` rows update instead of duplicating.

- [ ] **Step 2: Run the failing test**

Run: `pytest TOOLS/tests/test_auth_state.py -q`
Expected: fail because `auth.auth_state` does not exist.

- [ ] **Step 3: Add migration and schema table**

Create migration `013_auth_storage_tokens.sql` with `CREATE TABLE IF NOT EXISTS auth_storage_tokens (...)` and the unique key from the spec. Add the same table to `TOOLS/db/schema.sql`.

- [ ] **Step 4: Implement minimal DB upsert helper**

Create `TOOLS/auth/auth_state.py` with `upsert_storage_tokens(conn, tokens)` and `classify_token_kind(name, value)`.

- [ ] **Step 5: Verify**

Run: `pytest TOOLS/tests/test_auth_state.py -q`
Expected: pass.

### Task 2: CDP Auth State Capture

**Files:**
- Modify: `TOOLS/auth/auth_state.py`
- Test: `TOOLS/tests/test_auth_state.py`

- [ ] **Step 1: Write pure helper tests**

Cover `classify_token_kind`, `storage_items_to_tokens`, `cookies_to_auth_session_rows`, and safe JWT expiry extraction without requiring a live browser.

- [ ] **Step 2: Implement pure helpers**

Add helpers that normalize Playwright cookies into `auth_sessions` rows and local/session storage entries into `auth_storage_tokens` rows. Classify `jwt`, `bearer`, `csrf`, `api_key`, or `storage` conservatively.

- [ ] **Step 3: Implement CDP capture CLI**

Add `capture --target`, `ensure --target`, and `export-header --target --url` subcommands. `capture` connects to `scan_state.cdp_url`, prefers existing pages matching the target host, captures cookies and storage values, and writes them to DB.

- [ ] **Step 4: Verify helpers**

Run: `pytest TOOLS/tests/test_auth_state.py -q`
Expected: pass.

### Task 3: Session and Browser Auth Wiring

**Files:**
- Modify: `TOOLS/auth/session_manager.py`
- Modify: `TOOLS/auth/browser_auth.py`
- Test: `TOOLS/tests/test_browser_auth.py`
- Test: `TOOLS/tests/test_auth_state.py`

- [ ] **Step 1: Write priority-order tests**

Test that session ensure order is: valid DB session, CDP capture, browser-use fallback. Mock subprocess calls so no browser launches.

- [ ] **Step 2: Wire `session_manager.py`**

Call `auth_state.ensure_session` before browser-use relogin. Keep existing CLI behavior and exit codes.

- [ ] **Step 3: Wire `browser_auth.py`**

After login success, call `auth_state.capture_to_db(target, db_path, cdp_url)` instead of only writing cookies through local duplicated logic.

- [ ] **Step 4: Verify**

Run: `pytest TOOLS/tests/test_browser_auth.py TOOLS/tests/test_auth_state.py -q`
Expected: pass.

### Task 4: Framework-Neutral Candidate Extraction

**Files:**
- Modify: `TOOLS/auth/auth_explore.py`
- Test: `TOOLS/tests/test_auth_explore.py`

- [ ] **Step 1: Write failing pure extraction tests**

Add tests for:
- Hash route normalization.
- Unsafe label filtering.
- Attribute routes from `data-url`, `data-route`, `data-src`, `formaction`, and iframe `src`.
- Inline script routes from `window.open`, `location.href`, `router.push`, and `navigate`.
- Nested JSON entries from `url`, `href`, `link`, `path`, `route`, `targetUrl`, `redirectUrl`, `appUrl`, `menuUrl`, `moduleUrl`, `iframeUrl`, and `openUrl`.
- Representative Vue, React, jQuery/admin-template, iframe, and micro-frontend snippets.

- [ ] **Step 2: Implement candidate model and helpers**

Add a small dict-based candidate shape with `kind`, `value`, `label`, `source`, and `framework_hint`. Add `is_unsafe_label`, `normalize_candidate_url`, `extract_response_candidates`, and `extract_inline_route_literals`.

- [ ] **Step 3: Verify pure extraction**

Run: `pytest TOOLS/tests/test_auth_explore.py -q`
Expected: pass.

### Task 5: Bounded Portal Traversal

**Files:**
- Modify: `TOOLS/auth/auth_explore.py`
- Test: `TOOLS/tests/test_auth_explore.py`

- [ ] **Step 1: Add queue bound tests**

Test dedupe, per-host cap, per-prefix cap, and breadth preservation so one deep subsystem cannot starve peer subsystem candidates.

- [ ] **Step 2: Replace `nav_hrefs` traversal**

Collect a first wave from the portal page, process candidates round-robin, handle `url`, `hash`, `response_url`, and `click`, capture popup/new-tab pages, and return to the seed page or previous route where practical.

- [ ] **Step 3: Preserve existing request capture and DB writes**

Keep `filter_api_requests`, `parse_request_params`, `write_explore_results_to_db`, and hunt queue behavior compatible.

- [ ] **Step 4: Verify focused auth explore tests**

Run: `pytest TOOLS/tests/test_auth_explore.py -q`
Expected: pass.

### Task 6: Full Verification and Commit

**Files:**
- Verify all modified files.

- [ ] **Step 1: Run focused auth tests**

Run: `pytest TOOLS/tests/test_auth_state.py TOOLS/tests/test_auth_explore.py TOOLS/tests/test_browser_auth.py -q`
Expected: pass.

- [ ] **Step 2: Run existing tool tests**

Run: `pytest TOOLS/tests/ -q`
Expected: pass or report unrelated failures with exact failing tests.

- [ ] **Step 3: Review worktree**

Run: `git status --short` and `git diff --stat`.
Expected: only planned files plus pre-existing unrelated dirty files remain.

- [ ] **Step 4: Commit implementation**

Stage only files touched for this implementation and commit with `feat: add auth state and portal discovery`.
