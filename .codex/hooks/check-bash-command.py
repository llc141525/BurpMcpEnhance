"""PreToolUse hook: check Bash commands for dangerous patterns.
Reads tool input JSON from stdin. Exits 0 to allow, 2 to block, 1 to warn.
"""
import sys
import json
import re

# ----- Configuration -----
# Authorized targets (SRC scopes). Add your target domains here.
AUTHORIZED_TARGETS = [
    # e.g., "example.com", "*.example.com"
]
# Burp Collaborator domain (data exfiltration check bypass)
COLLABORATOR_DOMAIN = "burpcollaborator.net"


def matches_any_target(hostname):
    """Check if hostname matches any authorized target pattern."""
    for target in AUTHORIZED_TARGETS:
        if target.startswith("*."):
            if hostname.endswith(target[1:]):
                return True
        elif hostname == target:
            return True
    return False


def extract_urls(text):
    """Extract hostnames from URLs in command text."""
    urls = re.findall(r'https?://([^/\s:"\'<>]+)', text)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    return urls + ips


BLOCK_RULES = [
    # ========== System Destruction ==========
    # Root filesystem deletion
    (r"(^|\s)rm\s+(-rf?|--recursive)\s+/($|\s)", "BLOCKED: Recursive root deletion (rm -rf /) is forbidden."),
    (r"(^|\s)rm\s+(-rf?|--recursive)\s+~", "BLOCKED: Deleting home directory is forbidden."),
    (r"(^|\s)rm\s+(-rf?|--recursive)\s+\$HOME", "BLOCKED: Deleting \$HOME is forbidden."),
    (r"(^|\s)rm\s+(-rf?|--recursive)\s+/etc", "BLOCKED: Deleting /etc is forbidden."),
    (r"(^|\s)rm\s+(-rf?|--recursive)\s+/boot", "BLOCKED: Deleting /boot will brick the system."),
    (r"(^|\s)rm\s+(-rf?|--recursive)\s+/var", "BLOCKED: Deleting /var will break the system."),
    (r"(^|\s)rm\s+(-rf?|--recursive)\s+/usr", "BLOCKED: Deleting /usr will break the system."),

    # Disk destruction
    (r"(^|\s)dd\s+if=\S+\s+of=\s*/dev/sd[a-z]", "BLOCKED: Direct disk write (dd to /dev/sdX) is forbidden."),
    (r"(^|\s)dd\s+if=\S+\s+of=\s*/dev/nvme", "BLOCKED: Direct disk write (dd to /dev/nvme) is forbidden."),
    (r"(^|\s)dd\s+if=\S+\s+of=\s*/dev/vd", "BLOCKED: Direct disk write (dd to /dev/vdX) is forbidden."),
    (r">\s*/dev/sd[a-z]", "BLOCKED: Writing directly to disk device is forbidden."),
    (r">\s*/dev/nvme", "BLOCKED: Writing directly to NVMe device is forbidden."),
    (r">\s*/dev/zero", "BLOCKED: Writing to /dev/zero is not allowed."),

    # Filesystem & partition tools (destructive ops)
    (r"(^|\s)mkfs\.", "BLOCKED: Creating filesystems (mkfs) is forbidden."),
    (r"(^|\s)mkswap\s", "BLOCKED: Creating swap filesystem is forbidden."),
    (r"(^|\s)fdisk\s+/dev/sd", "BLOCKED: Partition operations on disk devices are forbidden."),
    (r"(^|\s)fdisk\s+/dev/nvme", "BLOCKED: Partition operations on NVMe devices are forbidden."),
    (r"(^|\s)parted\s+/dev/sd", "BLOCKED: Partition operations on disk devices are forbidden."),
    (r"(^|\s)lvremove\s", "BLOCKED: LVM volume removal is forbidden."),
    (r"(^|\s)vgremove\s", "BLOCKED: LVM volume group removal is forbidden."),
    (r"(^|\s)pvremove\s", "BLOCKED: LVM physical volume removal is forbidden."),

    # chmod/chown to system paths
    (r"chmod\s+-R\s+777\s+/", "BLOCKED: Recursive chmod 777 on root is forbidden."),
    (r"chown\s+-R\s+\S+\s+/$", "BLOCKED: Recursive chown on root is forbidden."),

    # System shutdown/reboot
    (r"(^|\s)shutdown\s", "BLOCKED: System shutdown is forbidden."),
    (r"(^|\s)reboot\s", "BLOCKED: System reboot is forbidden."),
    (r"(^|\s)halt\s", "BLOCKED: System halt is forbidden."),
    (r"(^|\s)poweroff\s", "BLOCKED: System poweroff is forbidden."),
    (r"(^|\s)init\s+0(\s|$)", "BLOCKED: init 0 (shutdown) is forbidden."),
    (r"(^|\s)init\s+6(\s|$)", "BLOCKED: init 6 (reboot) is forbidden."),

    # Fork bombs
    (r":\{\s*:\|:&\s*\}", "BLOCKED: Fork bomb pattern detected."),
    (r"\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", "BLOCKED: Fork bomb pattern detected."),
    (r"while\s+true\s*;?\s*do\s+.*\|\s*.*&\s*done", "BLOCKED: Possible fork bomb pattern detected."),

    # ========== SRC Policy Violations ==========
    # DoS/DDoS tools
    (r"(^|\s)hping3?\s", "BLOCKED: DoS tool (hping) is not permitted in SRC testing."),
    (r"(^|\s)slowhttptest\s", "BLOCKED: DoS tool (slowhttptest) is not permitted."),
    (r"(^|\s)goldeneye\s", "BLOCKED: DoS tool (goldeneye) is not permitted."),
    (r"(^|\s)torhammer\s", "BLOCKED: DoS tool (torhammer) is not permitted."),
    (r"(^|\s)LOIC\s", "BLOCKED: DoS tool (LOIC) is not permitted."),
    (r"(^|\s)HOIC\s", "BLOCKED: DoS tool (HOIC) is not permitted."),
    (r"(^|\s)mdk[34]\s", "BLOCKED: WiFi DoS/attack tool is not permitted."),
    (r"(^|\s)aireplay-ng\s", "BLOCKED: WiFi attack tool is not permitted."),
    (r"(^|\s)hulk\s", "BLOCKED: DoS tool (hulk) is not permitted."),

    # Mass scanning / wide-range attacks
    (r"(^|\s)masscan\s.*/0", "BLOCKED: Masscan on /0 subnet is not permitted."),
    (r"(^|\s)zmap\s.*/0", "BLOCKED: ZMap on /0 subnet is not permitted."),
    (r"(^|\s)masscan\s.*0\.0\.0\.0/0", "BLOCKED: Masscan on entire internet is not permitted."),

    # Unauthorized exploitation tools
    (r"(^|\s)msfconsole\s", "BLOCKED: Metasploit requires explicit authorization."),
    (r"(^|\s)msfvenom\s", "BLOCKED: Payload generation (msfvenom) requires explicit authorization."),
    (r"(^|\s)searchsploit\s+-m\s", "BLOCKED: Downloading exploits requires authorization."),

    # Reverse shell / backdoor patterns
    (r"bash\s+-i\s+>&?\s*/dev/tcp/", "BLOCKED: Reverse shell pattern detected."),
    (r"bash\s+-i\s+>&?\s*/dev/udp/", "BLOCKED: Reverse shell pattern detected."),
    (r"sh\s+-i\s+>&?\s*/dev/tcp/", "BLOCKED: Reverse shell pattern detected."),
    (r"python\s+-c\s+['\"].*socket.*connect.*", "BLOCKED: Reverse shell pattern detected."),
    (r"powershell.*\$client.*New-Object.*Socket", "BLOCKED: Reverse shell pattern detected."),
    (r"powershell.*-e\s+[A-Za-z0-9+/]{50,}={0,2}", "BLOCKED: Encoded PowerShell command detected (possible reverse shell)."),

    # Cryptominers
    (r"(^|\s)xmrig\s", "BLOCKED: Cryptominer (xmrig) is not permitted."),
    (r"(^|\s)minerd\s", "BLOCKED: Cryptominer is not permitted."),
    (r"(^|\s)ccminer\s", "BLOCKED: Cryptominer is not permitted."),
    (r"(^|\s)ethminer\s", "BLOCKED: Cryptominer is not permitted."),

    # ========== Windows-Specific ==========
    (r"(^|\s)format\s+\w:\s*/\s*[QqUu]", "BLOCKED: Formatting a drive is forbidden."),
    (r"(^|\s)diskpart\s", "BLOCKED: Disk partition operations are forbidden."),
    (r"del\s+/[Ff]\s+/[Ss]\s+/[Qq]\s+", "BLOCKED: Forced recursive delete is forbidden."),
    (r"rmdir\s+/[Ss]\s+/[Qq]\s+", "BLOCKED: Forced recursive directory delete is forbidden."),
    (r"(^|\s)reg\s+delete\s", "BLOCKED: Registry deletion is forbidden."),
    (r"(^|\s)sc\s+delete\s", "BLOCKED: Service deletion is forbidden."),
]

WARN_RULES = [
    # ========== Potential Danger ==========
    (r"(^|\s)chmod\s+-R\s+777", "WARNING: Recursive chmod 777 opens full permissions. Prefer more restrictive settings."),

    # ========== SRC Policy Warnings ==========
    # Unauthorized asset testing (if authorized targets configured)
    (r"nuclei\s", "WARNING: Running nuclei. Verify target is in authorized scope."),
    (r"sqlmap\s", "WARNING: Running sqlmap. Per SRC policy, confirm operator authorization."),
    (r"dalfox\s", "WARNING: Running dalfox. Per SRC policy, confirm operator authorization."),

    # curl/wget to external - warn but allow
    (r"curl.*\|\s*(ba)?sh", "WARNING: Piping curl output to shell. Verify the source URL."),

    # Hydra/Brute force (warn, might be legit in SRC)
    (r"(^|\s)hydra\s", "WARNING: Brute force tool (hydra). Verify authorization."),
    (r"(^|\s)medusa\s", "WARNING: Brute force tool (medusa). Verify authorization."),
    (r"(^|\s)john\s", "WARNING: Password cracker (john). Verify authorization."),
    (r"(^|\s)hashcat\s", "WARNING: Password cracker (hashcat). Verify authorization."),

    # Data exfiltration patterns (non-Collaborator)
    # NOTE: heavy regex here; simple heuristic: curl/wget to non-authorized host
    (r"curl\s+https?://(?!.*" + re.escape(COLLABORATOR_DOMAIN) + r")", "WARNING: curl to external URL. Verify destination is authorized."),

    # Unsafe redirects / output to system paths
    (r">\s*/etc/", "WARNING: Writing to /etc/ can break system configuration."),

    # Large data download
    (r"wget\s+--recursive", "WARNING: Recursive wget can download large amounts of data."),
    (r"curl\s+.*-O\s+.*\.(zip|tar\.gz|tgz|tar\.bz2|iso|bin)", "WARNING: Downloading potentially large archive file."),
]

# SRC policy: check for unauthorized target testing
def check_unauthorized_target(command):
    """Check if command targets an unauthorized host."""
    if not AUTHORIZED_TARGETS:
        return None  # No targets configured, skip check

    urls = re.findall(r'https?://([^/\s:"\'<>]+)', command)
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', command)

    # Common scanning tools that take target arguments
    scanner_pattern = re.compile(
        r'(nuclei|sqlmap|dalfox|ffuf|gobuster|dirsearch|nmap|whatweb|subfinder|httpx|naabu|waybackurls|gau|katana|feroxbuster|xsstrike|kxss)'
    )

    if not urls and not ips:
        return None

    if scanner_pattern.search(command):
        for host in urls + ips:
            if not matches_any_target(host):
                return f"BLOCKED: Target '{host}' is not in authorized scope. Add to AUTHORIZED_TARGETS in hook config if authorized."
        return None

    return None


def check_data_exfiltration(command):
    """Check for potential data exfiltration via curl/wget."""
    if AUTHORIZED_TARGETS:
        # Check if sending data to non-authorized server
        post_pattern = re.compile(
            r'curl\s+.*(?:-d|--data|--data-raw|--data-binary|--form|-F)\s+'
        )
        if post_pattern.search(command):
            urls = re.findall(r'https?://([^/\s:"\'<>]+)', command)
            for host in urls:
                if not matches_any_target(host) and COLLABORATOR_DOMAIN not in host:
                    return (2, f"BLOCKED: Sending data to '{host}' which is not in authorized scope.")
    return None


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, Exception):
        sys.exit(0)

    command = data.get("command", "")
    if not command:
        sys.exit(0)

    # 1. Check for unauthorized target scanning
    result = check_unauthorized_target(command)
    if result:
        print(result, file=sys.stderr)
        sys.exit(2)

    # 2. Check for data exfiltration
    result = check_data_exfiltration(command)
    if result:
        print(result[1], file=sys.stderr)
        sys.exit(result[0])

    # 3. Check BLOCK rules (exit 2)
    for pattern, message in BLOCK_RULES:
        if re.search(pattern, command):
            print(message, file=sys.stderr)
            sys.exit(2)

    # 4. Check WARN rules (exit 1)
    for pattern, message in WARN_RULES:
        if re.search(pattern, command):
            print(message, file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
