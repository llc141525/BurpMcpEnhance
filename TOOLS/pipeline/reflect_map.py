"""静态 tech_stack → 插件映射表。每项 name 须全局唯一。"""

STACK_PLUGINS: dict[str, list[dict]] = {
    "Spring Boot": [
        {
            "name": "spring-actuator",
            "type": "nuclei_template",
            "vuln_types": ["info_leak", "config_exposure"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
        {
            "name": "spring4shell",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Shiro": [
        {
            "name": "shiro-deserialization",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "ThinkPHP": [
        {
            "name": "thinkphp-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "FastJSON": [
        {
            "name": "fastjson-deserialization",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Struts2": [
        {
            "name": "struts2-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "WordPress": [
        {
            "name": "wordpress-vulns",
            "type": "nuclei_template",
            "vuln_types": ["rce", "sqli", "xss"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Discuz": [
        {
            "name": "discuz-vulns",
            "type": "nuclei_template",
            "vuln_types": ["rce", "sqli"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "JWT": [
        {
            "name": "jwt-none-alg",
            "type": "python_script",
            "vuln_types": ["auth_bypass"],
            "install_cmd": None,
            "file_path": "TOOLS/plugins/scripts/jwt_none_alg.py",
        },
    ],
    "Laravel": [
        {
            "name": "laravel-debug",
            "type": "nuclei_template",
            "vuln_types": ["info_leak", "rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
}


def get_plugins_for_stacks(stacks: list[str]) -> list[dict]:
    """返回给定技术栈对应的插件列表，去重（按 name）。"""
    seen: set[str] = set()
    result: list[dict] = []
    for stack in stacks:
        for plugin in STACK_PLUGINS.get(stack, []):
            if plugin["name"] not in seen:
                seen.add(plugin["name"])
                result.append({**plugin, "trigger_stack": stack})
    return result
