from app.services.covenant_visualizer import CovenantInputError, visualize_covenant


def test_visualize_covenant_parses_if_else_cltv_asm_and_builds_timeline():
    result = visualize_covenant(
        {
            "script_asm": "OP_IF 02"
            + "11" * 32
            + " OP_CHECKSIG OP_ELSE 500000 OP_CHECKLOCKTIMEVERIFY OP_DROP 03"
            + "22" * 32
            + " OP_CHECKSIG OP_ENDIF",
            "network": "bitcoin",
        }
    )

    assert result["source_type"] == "script_asm"
    assert result["machine_explanation"]["observed"]["branches_present"] is True
    assert result["machine_explanation"]["observed"]["timelocks"][0]["value"] == 500000
    assert result["timeline"][1]["classification"] == "block_height"
    assert 0.0 <= result["confidence"] <= 1.0
    assert 0.0 <= result["trust_score"] <= 1.0
    assert result["pattern_match"]["variant"] == "cooperative_plus_delayed_exit"
    assert result["simplified_visualization"] is False
    assert "trust_factors" in result["machine_explanation"]


def test_visualize_covenant_produces_mermaid_and_graph_data():
    result = visualize_covenant(
        {
            "descriptor": "raw(63512103" + "33" * 32 + "ac6703010101b1756821" + "02" + "44" * 32 + "ac68)",
        }
    )

    assert result["mermaid"].startswith("flowchart TD")
    assert result["graph"]["nodes"]
    assert "graphviz_dot" in result


def test_visualize_covenant_detects_nested_ladder_pattern():
    asm = (
        "OP_IF 02"
        + "11" * 32
        + " OP_CHECKSIG OP_ELSE OP_IF 500000 OP_CHECKLOCKTIMEVERIFY OP_DROP 03"
        + "22" * 32
        + " OP_CHECKSIG OP_ELSE 600000 OP_CHECKLOCKTIMEVERIFY OP_DROP 02"
        + "11" * 32
        + " OP_CHECKSIG OP_ENDIF OP_ENDIF"
    )
    result = visualize_covenant({"script_asm": asm})

    assert result["pattern_match"]["variant"] == "hodlxxi_two_party_ladder"
    assert result["simplified_visualization"] is True
    assert "nested branch logic detected; visualization is simplified" in result["warnings"]


def test_visualize_covenant_adds_unsupported_opcode_warning_for_hex():
    result = visualize_covenant({"script_hex": "63ff68"})

    assert result["simplified_visualization"] is True
    assert "unsupported opcode(s) detected; graph is approximate" in result["warnings"]


def test_visualize_covenant_flags_xonly_ambiguity():
    asm = "OP_IF " + ("11" * 32) + " OP_CHECKSIG OP_ELSE 500000 OP_CHECKLOCKTIMEVERIFY OP_DROP OP_ENDIF"
    result = visualize_covenant({"script_asm": asm})

    assert "x-only key-like tokens detected; prefix/compression ambiguity remains" in result["warnings"]
    assert result["confidence"] < 0.8


def test_visualize_covenant_descriptor_without_raw_is_partial():
    result = visualize_covenant({"descriptor": "wsh(or_b(pk(key1),after(500000)))"})

    assert result["source_type"] == "descriptor"
    assert result["simplified_visualization"] is True
    assert "descriptor parsing is partial; only raw(...) is fully interpreted" in result["warnings"]


def test_visualize_covenant_handles_malformed_hex_conservatively():
    result = visualize_covenant({"script_hex": "zz11"})

    assert result["pattern_match"]["variant"] == "unclassified"
    assert result["confidence"] <= 0.5
    assert result["trust_score"] <= 0.3
    assert "script_hex is not valid even-length hex" in result["warnings"]


def test_visualize_covenant_trust_score_decreases_with_unsupported_opcode_warning():
    clean = visualize_covenant(
        {
            "script_asm": "OP_IF 02"
            + "11" * 32
            + " OP_CHECKSIG OP_ELSE 500000 OP_CHECKLOCKTIMEVERIFY OP_DROP 03"
            + "22" * 32
            + " OP_CHECKSIG OP_ENDIF",
        }
    )
    noisy = visualize_covenant({"script_hex": "63ff68"})

    assert noisy["trust_score"] < clean["trust_score"]


def test_visualize_covenant_clean_cooperative_pattern_has_higher_trust_score():
    clean = visualize_covenant(
        {
            "script_asm": "OP_IF 02"
            + "aa" * 32
            + " OP_CHECKSIG OP_ELSE 700000 OP_CHECKLOCKTIMEVERIFY OP_DROP 03"
            + "bb" * 32
            + " OP_CHECKSIG OP_ENDIF",
        }
    )
    ambiguous = visualize_covenant({"descriptor": "wsh(or_b(pk(key1),after(500000)))"})

    assert clean["pattern_match"]["variant"] == "cooperative_plus_delayed_exit"
    assert clean["trust_score"] > ambiguous["trust_score"]


def test_visualize_covenant_rejects_empty_supported_inputs():
    try:
        visualize_covenant({"network": "bitcoin"})
        assert False, "expected CovenantInputError"
    except CovenantInputError as exc:
        assert "required" in str(exc)
