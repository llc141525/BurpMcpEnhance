# AGENTS.md — Burp MCP Server

## Task Routing (READ FIRST)

**Before using Read/Grep/Agent for information gathering, check: can `mmx` do it cheaper?**

| If you need to...             | Use this instead                                          | Saves      |
| ----------------------------- | --------------------------------------------------------- | ---------- |
| Search the web                | `mmx search query "..."`                                  | ~2K tokens |
| Read & summarize a large file | `mmx text chat --message "$(cat file)"`                   | ~5K tokens |
| Summarize a git diff          | `git diff \| mmx text chat --message "summarize changes"` | ~5K tokens |
| Group/classify errors         | pipe errors to `mmx text chat`                            | ~3K tokens |
| Analyze dependencies/config   | `mmx text chat --message "$(cat requirements.txt)"`       | ~2K tokens |
| OCR / describe an image       | `mmx vision describe <image>`                             | ~2K tokens |

**When NOT to use mmx**: writing code, fixing bugs, security analysis, architecture decisions, multi-step reasoning.

## Build & Test

```bash
.\gradlew.bat test              # All tests
.\gradlew.bat shadowJar         # Build → build/libs/burp-mcp-all.jar
.\gradlew.bat test --tests "*.ToolsKtTest"
.\gradlew.bat test --tests "*.KtorServerManagerTest"
```

## Git Workflow

- `master` branch push triggers CI:
  - run tests
  - build `build/libs/burp-mcp-all.jar`
  - upload the JAR as a GitHub Actions Artifact
- `v*` tag push triggers formal GitHub Release:
  - run tests
  - build `build/libs/burp-mcp-all.jar`
  - publish GitHub Release
  - generate Release notes automatically from commit history
- Recommended release flow:

```bash
git push origin master
git tag v1.2.2
git push origin v1.2.2
```

## Delivery Rule

- When a **large feature** is fully implemented, verified, and self-contained, the default expectation is:
  - commit it
  - push `master`
- “Large feature” means a user-visible capability or a meaningful end-to-end improvement, not a tiny fix, typo, local experiment, or half-finished refactor.
- Do **not** auto-push if:
  - tests/build are failing
  - the change is incomplete
  - there are obvious unresolved questions
  - the work includes local-only scratch files or risky unrelated changes
- If a task is clearly only partial work, keep it local and explain what is still missing.

## Architecture

```
ExtensionBase (DI)
├── KtorServerManager — SSE server, CORS, HealthMonitor, auto-restart
│   └── MCP SDK Server → registerTools(Tools.kt)
├── Database — SQLite WAL, SHA-256 dedup, BLOB store, pruning
├── Exporter — Burp API → SQLite poller (30s interval)
├── HealthMonitor — 3-strike → auto-restart
├── LogWriter — ~/.burp-mcp/logs/ JSONL + Burp UI dual-write
├── MessageQueue + FileQueue — async tasks
└── ConfigUi — Swing dashboard + settings panels
```

Key files: `KtorServerManager.kt`, `Database.kt`, `Exporter.kt`, `HealthMonitor.kt`, `logging/LogWriter.kt`

## Code Conventions

- Immutable data classes with `copy()`, never mutate in place
- `Dispatchers.IO` for blocking I/O, `Dispatchers.Default` for CPU
- Backtick test names: `` `returns X when Y` ``
- No silent catch — log or propagate

## Key Behaviors

- Server auto-restart: exponential backoff 1s→2s→4s→30s→...→300s, persistent
- HealthMonitor: 3 consecutive failures → `onUnhealthy` triggers restart
- DB dedup: SHA-256(method|url), 5-min window, hit_count counter
- DB prune: 100K HTTP rows, 10K scanner issues, expired BLOBs
- SSE: 3600s read/write timeout, Ktor native heartbeat keepalive
- Tools: 120s timeout, null-safe error messages
