import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.reflect_map import get_plugins_for_stacks


def test_spring_boot_returns_actuator():
    plugins = get_plugins_for_stacks(["Spring Boot"])
    names = [p["name"] for p in plugins]
    assert "spring-actuator" in names


def test_unknown_stack_returns_empty():
    plugins = get_plugins_for_stacks(["UnknownFramework"])
    assert plugins == []


def test_multi_stack_deduplicates():
    plugins = get_plugins_for_stacks(["Spring Boot", "Spring Boot"])
    names = [p["name"] for p in plugins]
    assert names.count("spring-actuator") == 1


def test_plugin_has_required_fields():
    plugins = get_plugins_for_stacks(["Shiro"])
    for p in plugins:
        assert "name" in p
        assert "type" in p
        assert "vuln_types" in p
        assert p["type"] in ("nuclei_template", "python_script", "tool_binary", "config")
