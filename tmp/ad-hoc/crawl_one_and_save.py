"""Crawl a URL and save result to scanner.db in one step."""
import json, sys, os, subprocess
from pathlib import Path

TOOLS = Path(__file__).parent
url = sys.argv[1]

result = subprocess.run(
    [sys.executable, str(TOOLS / 'scrapling_fetch.py'), url, '--extract-all'],
    capture_output=True, text=True, timeout=25
)

try:
    data = json.loads(result.stdout)
except json.JSONDecodeError:
    print(json.dumps({"error": "JSON parse failed", "url": url, "stderr": result.stderr}))
    sys.exit(1)

# Feed to batch processor
proc = subprocess.run(
    [sys.executable, str(TOOLS / 'batch_crawl_result.py')],
    input=json.dumps([data]), capture_output=True, text=True, timeout=10
)

print(proc.stdout)
if proc.stderr:
    print(f"STDERR: {proc.stderr}", file=sys.stderr)
