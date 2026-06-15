"""静态 tech_stack → 插件映射表。每项 name 须全局唯一。"""

STACK_PLUGINS: dict[str, list[dict]] = {
    # ── 已有（保留 + 扩充路径）────────────────────────────────────────────
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
    # ── 国产 OA ───────────────────────────────────────────────────────────
    "泛微 Ecology OA": [
        {
            "name": "ecology-workflow-sqli",
            "type": "nuclei_template",
            "vuln_types": ["sqli"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
        {
            "name": "ecology-bsh-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "致远 OA": [
        {
            "name": "seeyon-unauth",
            "type": "nuclei_template",
            "vuln_types": ["unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "蓝凌 OA": [
        {
            "name": "landray-ssrf-rce",
            "type": "nuclei_template",
            "vuln_types": ["ssrf", "rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "用友 NC": [
        {
            "name": "yonyou-nc-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── 国产安全设备 ──────────────────────────────────────────────────────
    "深信服 VPN": [
        {
            "name": "sangfor-vpn-vulns",
            "type": "nuclei_template",
            "vuln_types": ["unauth", "rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "奇安信 VPN": [
        {
            "name": "qianxin-vpn-vulns",
            "type": "nuclei_template",
            "vuln_types": ["unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── 国产 IAM / 身份 ──────────────────────────────────────────────────
    "Ruijie LinkID": [
        {
            "name": "ruijie-linkid-csrf",
            "type": "nuclei_template",
            "vuln_types": ["unauth", "info_leak"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "CAS SSO": [
        {
            "name": "cas-sso-info",
            "type": "nuclei_template",
            "vuln_types": ["info_leak"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── 微服务 / 网关 ────────────────────────────────────────────────────
    "APISIX": [
        {
            "name": "apisix-admin-unauth",
            "type": "nuclei_template",
            "vuln_types": ["unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Nacos": [
        {
            "name": "nacos-unauth",
            "type": "nuclei_template",
            "vuln_types": ["unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Dubbo": [
        {
            "name": "dubbo-deserialization",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── 存储 ─────────────────────────────────────────────────────────────
    "MinIO": [
        {
            "name": "minio-unauth",
            "type": "nuclei_template",
            "vuln_types": ["unauth", "info_leak"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Nexus": [
        {
            "name": "nexus-unauth",
            "type": "nuclei_template",
            "vuln_types": ["unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Harbor": [
        {
            "name": "harbor-unauth",
            "type": "nuclei_template",
            "vuln_types": ["unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── 运维平台 ─────────────────────────────────────────────────────────
    "Jenkins": [
        {
            "name": "jenkins-unauth-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce", "unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "GitLab": [
        {
            "name": "gitlab-vulns",
            "type": "nuclei_template",
            "vuln_types": ["unauth", "ssrf"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Jira": [
        {
            "name": "jira-ognl-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Confluence": [
        {
            "name": "confluence-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── Java 中间件 ───────────────────────────────────────────────────────
    "WebLogic": [
        {
            "name": "weblogic-t3-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "JBoss": [
        {
            "name": "jboss-jmx-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Log4j": [
        {
            "name": "log4shell",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── PHP 框架 ──────────────────────────────────────────────────────────
    "PHPCMS": [
        {
            "name": "phpcms-vulns",
            "type": "nuclei_template",
            "vuln_types": ["sqli", "unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── 监控 / 分析 ───────────────────────────────────────────────────────
    "Kibana": [
        {
            "name": "kibana-unauth",
            "type": "nuclei_template",
            "vuln_types": ["unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Grafana": [
        {
            "name": "grafana-lfi",
            "type": "nuclei_template",
            "vuln_types": ["lfi"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Zabbix": [
        {
            "name": "zabbix-unauth",
            "type": "nuclei_template",
            "vuln_types": ["sqli", "unauth"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    "Webmin": [
        {
            "name": "webmin-rce",
            "type": "nuclei_template",
            "vuln_types": ["rce"],
            "install_cmd": "nuclei -update-templates",
            "file_path": None,
        },
    ],
    # ── 金融 / 教育专用 ──────────────────────────────────────────────────
    "金智 EMAP": [
        {
            "name": "emap-idor",
            "type": "nuclei_template",
            "vuln_types": ["idor"],
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
