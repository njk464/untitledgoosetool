"""Unit tests for the generator's monitor-path prefix stripping and conf parsing."""

import importlib.util
import os

_SPEC = importlib.util.spec_from_file_location(
    "generate_sourcetypes",
    os.path.join(os.path.dirname(__file__), "..", "scripts", "generate_sourcetypes.py"))
gen = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gen)


def test_strips_up_to_output():
    assert gen.strip_output_prefix("home/user/x/output/azure/.../all_resources_list*json") == \
        "azure/.../all_resources_list*json"


def test_leading_slash_and_nested_output_segment():
    assert gen.strip_output_prefix("/home/u/output/a/output/b.json") == "a/output/b.json"


def test_no_output_segment_unchanged():
    assert gen.strip_output_prefix("azure/x.json") == "azure/x.json"
    assert gen.strip_output_prefix("home/user/outputs/x.json") == "home/user/outputs/x.json"


def test_parse_inputs_conf(tmp_path):
    conf = tmp_path / "inputs.conf"
    conf.write_text("[monitor:///home/user/x/output/azure/.../all_resources_list*json]\n"
                    "sourcetype = ugt:azure:resources\n")
    assert gen.parse_inputs_conf(str(conf)) == [
        {"sourcetype": "ugt:azure:resources", "monitor": "azure/{sub_id}/all_resources_list*json"}]
