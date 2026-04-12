from app.services.covenant_visualizer import CovenantInputError, visualize_covenant


def test_visualize_covenant_parses_if_else_cltv_asm_and_builds_timeline():
    result = visualize_covenant(
        {
            "script_asm": "OP_IF 02" + "11" * 32 + " OP_CHECKSIG OP_ELSE 500000 OP_CHECKLOCKTIMEVERIFY OP_DROP 03"
            + "22" * 32
            + " OP_CHECKSIG OP_ENDIF",
            "network": "bitcoin",
        }
    )

    assert result["source_type"] == "script_asm"
    assert result["machine_explanation"]["observed"]["branches_present"] is True
    assert result["machine_explanation"]["timelocks"][0]["value"] == 500000
    assert result["timeline"][1]["classification"] == "block_height"


def test_visualize_covenant_produces_mermaid_and_graph_data():
    result = visualize_covenant(
        {
            "descriptor": "raw(63512103" + "33" * 32 + "ac6703010101b1756821" + "02" + "44" * 32 + "ac68)",
        }
    )

    assert result["mermaid"].startswith("flowchart TD")
    assert result["graph"]["nodes"]
    assert "graphviz_dot" in result


def test_visualize_covenant_rejects_empty_supported_inputs():
    try:
        visualize_covenant({"network": "bitcoin"})
        assert False, "expected CovenantInputError"
    except CovenantInputError as exc:
        assert "required" in str(exc)
