import json
import subprocess
import sys
from pathlib import Path

from tools.inter_agent_demo import derive_pubkey_hex

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_inter_agent_demo_dry_run_does_not_require_network() -> None:
    agent_a_privkey = ("1" * 63) + "2"
    agent_b_pubkey = derive_pubkey_hex(("2" * 63) + "3")

    proc = subprocess.run(
        [
            sys.executable,
            "tools/inter_agent_demo.py",
            "--dry-run",
            "--agent-a-privkey",
            agent_a_privkey,
            "--agent-b-pubkey",
            agent_b_pubkey,
            "--agent-b-url",
            "http://127.0.0.1:9/agent/message",
            "--message",
            "dry-run ping",
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "OK: dry-run request envelope signature verified locally" in proc.stdout
    assert "Agent B HTTP status" not in proc.stdout

    marker = "=== Dry-run transcript ==="
    assert marker in proc.stdout
    transcript_text = proc.stdout.split(marker, 1)[1].split("OK:", 1)[0].strip()
    transcript = json.loads(transcript_text)

    assert transcript["schema"] == "hodlxxi.inter_agent.dry_run_transcript.v1"
    assert transcript["mode"] == "dry_run_no_network"
    assert transcript["http_post_performed"] is False
    assert transcript["payment_performed"] is False
    assert transcript["verification"]["request_signature_valid"] is True
    assert transcript["verification"]["agent_b_response_verified"] is False
    assert "no_outbound_payment" in transcript["non_goals"]
    assert transcript["request_envelope"]["payload"]["job_type"] == "ping"
    assert transcript["request_envelope"]["payload"]["payload"]["message"] == "dry-run ping"
