#!/usr/bin/env python3
"""Generate a deterministic read-only legacy covenant migration plan.

The command accepts a synthetic/exported input or an explicit live read-only
source. It has no apply/write/bootstrap/activation mode.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from decimal import Decimal
import json
import os
from pathlib import Path
import sys
from urllib.parse import quote

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.legacy_covenant_canonical_migration_planner import (  # noqa: E402
    CanonicalKnownRelationship,
    CanonicalReadSnapshot,
    LegacyCovenantCanonicalMigrationPlanner,
    LegacyWalletObservation,
    LegacyWalletOutpoint,
)
from app.services.canonical_admission_edge import GENESIS_XONLY_KEY, GRAPH_ID  # noqa: E402
from app.services.canonical_admission_edge_storage import (  # noqa: E402
    SqlAlchemyCanonicalAdmissionEdgeRepository,
)
from app.services.canonical_genesis_record_storage import (  # noqa: E402
    SqlAlchemyCanonicalGenesisRecordRepository,
)
from app.services.canonical_root_registration_binding_storage import (  # noqa: E402
    SqlAlchemyCanonicalRootRegistrationBindingRepository,
)
from app.services.trusted_covenant_registration_storage import (  # noqa: E402
    SqlAlchemyTrustedCovenantRegistrationRepository,
)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="READ-ONLY DRY RUN: plan legacy covenant canonical migration candidates."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="read-only observation/Canon JSON export")
    source.add_argument(
        "--live",
        action="store_true",
        help="read configured PostgreSQL and every loaded Bitcoin Core wallet",
    )
    parser.add_argument("--json", action="store_true", help="emit compact deterministic JSON")
    parser.add_argument("--pretty", action="store_true", help="emit indented deterministic JSON")
    parser.add_argument("--output", type=Path, help="write only the minimized report to an operator-selected path")
    return parser.parse_args(argv)


def _load(path: Path) -> tuple[tuple[LegacyWalletObservation, ...], CanonicalReadSnapshot]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict or set(value) != {"canonical", "wallets"}:
        raise ValueError("input must contain exactly canonical and wallets")
    wallets = tuple(
        LegacyWalletObservation(
            wallet_id=item["wallet_id"],
            descriptors=tuple(item["descriptors"]),
            outpoints=tuple(LegacyWalletOutpoint(**outpoint) for outpoint in item["outpoints"]),
        )
        for item in value["wallets"]
    )
    canonical = value["canonical"]
    snapshot = CanonicalReadSnapshot(
        genesis_active=canonical["genesis_active"],
        reachable_depths=tuple((item["xonly"], item["depth"]) for item in canonical["reachable_depths"]),
        known_relationships=tuple(
            CanonicalKnownRelationship(
                participants=tuple(item["participants"]),
                script_sha256s=tuple(item["script_sha256s"]),
                active=item["active"],
                source_ref=item["source_ref"],
            )
            for item in canonical["known_relationships"]
        ),
        browser_user_xonly_keys=frozenset(canonical.get("browser_user_xonly_keys", ())),
    )
    return wallets, snapshot


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or value != value.strip():
        raise ValueError(f"required operator configuration is absent: {name}")
    return value


def _btc_to_sats(value) -> int:
    sats = Decimal(str(value)) * Decimal(100_000_000)
    if sats != sats.to_integral_value() or sats < 0:
        raise ValueError("Bitcoin Core returned a non-canonical amount")
    return int(sats)


def _load_canonical_snapshot(
    *,
    genesis_repository,
    edge_repository,
    registration_repository,
    root_binding_repository,
    evaluated_at: datetime,
) -> CanonicalReadSnapshot:
    """Resolve only current, source-validated Canon using one evaluation time."""
    genesis_records = genesis_repository.list_for_graph(GRAPH_ID)
    edges = edge_repository.list_for_graph(GRAPH_ID)
    effective_root_binding = root_binding_repository.resolve_effective(
        GRAPH_ID,
        GENESIS_XONLY_KEY,
        evaluated_at=evaluated_at,
    )
    registration_ids = sorted(
        {value.trusted_registration_id for value in edges} | {effective_root_binding.trusted_registration_id}
    )
    registrations = tuple(registration_repository.get(value) for value in registration_ids)
    if any(value is None for value in registrations):
        raise ValueError("canonical registration source is incomplete")
    return CanonicalReadSnapshot.from_canonical_records(
        genesis_records=genesis_records,
        evaluated_at=evaluated_at,
        admission_edges=edges,
        registrations=registrations,
        current_root_registration_id=effective_root_binding.trusted_registration_id,
    )


def _collect_live() -> tuple[tuple[LegacyWalletObservation, ...], CanonicalReadSnapshot]:
    """Read configured sources with DB-level read-only enforcement."""
    from bitcoinrpc.authproxy import AuthServiceProxy
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    database_url = _required_environment("DATABASE_URL")
    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        connect_args={
            "connect_timeout": 10,
            "options": "-c default_transaction_read_only=on -c timezone=utc",
        },
    )
    sessions = sessionmaker(bind=engine)
    try:
        genesis_repository = SqlAlchemyCanonicalGenesisRecordRepository(sessions)
        edge_repository = SqlAlchemyCanonicalAdmissionEdgeRepository(sessions)
        registration_repository = SqlAlchemyTrustedCovenantRegistrationRepository(sessions)
        root_binding_repository = SqlAlchemyCanonicalRootRegistrationBindingRepository(
            sessions,
            genesis_repository=genesis_repository,
            trusted_registration_repository=registration_repository,
        )
        evaluated_at = datetime.now(timezone.utc).replace(microsecond=0)
        canonical = _load_canonical_snapshot(
            genesis_repository=genesis_repository,
            edge_repository=edge_repository,
            registration_repository=registration_repository,
            root_binding_repository=root_binding_repository,
            evaluated_at=evaluated_at,
        )
    finally:
        engine.dispose()

    rpc_user = quote(_required_environment("RPC_USER"), safe="")
    rpc_password = quote(_required_environment("RPC_PASSWORD"), safe="")
    rpc_host = _required_environment("RPC_HOST")
    rpc_port = _required_environment("RPC_PORT")
    node = AuthServiceProxy(f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}", timeout=60)
    wallet_names = node.listwallets()
    if type(wallet_names) is not list or any(type(value) is not str or not value for value in wallet_names):
        raise ValueError("Bitcoin Core loaded-wallet inventory is malformed")
    observations = []
    for wallet_name in sorted(wallet_names):
        wallet = AuthServiceProxy(
            f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}/wallet/{quote(wallet_name, safe='')}",
            timeout=60,
        )
        descriptors_result = wallet.listdescriptors()
        unspent_result = wallet.listunspent()
        descriptors = descriptors_result.get("descriptors") if type(descriptors_result) is dict else None
        if type(descriptors) is not list or type(unspent_result) is not list:
            raise ValueError("Bitcoin Core wallet observation is malformed")
        observations.append(
            LegacyWalletObservation(
                wallet_id=wallet_name,
                descriptors=tuple(item["desc"] for item in descriptors),
                outpoints=tuple(
                    LegacyWalletOutpoint(
                        txid=item["txid"],
                        vout=item["vout"],
                        amount_sats=_btc_to_sats(item["amount"]),
                        confirmations=item["confirmations"],
                        script_pubkey_hex=item["scriptPubKey"],
                    )
                    for item in unspent_result
                ),
            )
        )
    return tuple(observations), canonical


def main(argv=None) -> int:
    try:
        args = parse_args(argv)
        observations, canonical = _collect_live() if args.live else _load(args.input)
        plan = LegacyCovenantCanonicalMigrationPlanner().plan(observations, canonical)
        rendered = plan.to_json(pretty=args.pretty) if args.json or args.pretty else plan.human_summary()
        if args.output is not None:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)
        return 0
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        print("READ-ONLY DRY RUN unavailable", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
