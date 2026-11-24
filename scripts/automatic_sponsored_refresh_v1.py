#!/usr/bin/env python3
"""Bounded automatic import/eligibility refresh, for a dedicated runtime only."""

import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    if (
        sys.argv[1:] != ["--once"]
        or os.environ.get("AUTO_SPONSORED_IMPORT_ENABLED") != "true"
        or os.environ.get("AUTO_SPONSORED_ADMISSION_ENABLED") != "true"
        or not os.environ.get("DATABASE_URL")
    ):
        print("automatic sponsored refresh unavailable", file=sys.stderr)
        return 2
    try:
        from app.database import get_session, init_database
        from app.services.automatic_sponsored_admission_v1 import refresh_automatic_imports

        init_database(create_tables=False)
        from datetime import datetime, timezone
        from app.utils import get_rpc_connection
        from app.services.automatic_sponsored_import_v1 import recover_authenticated_sponsored_imports

        expected_wallet = os.environ.get("AUTO_SPONSORED_IMPORT_WATCH_WALLET")
        wallet = get_rpc_connection()
        wallet_info = wallet.getwalletinfo()
        if (
            not expected_wallet
            or expected_wallet == "hodlandwatch"
            or type(wallet_info) is not dict
            or wallet_info.get("walletname") != expected_wallet
            or wallet_info.get("private_keys_enabled") is not False
            or wallet_info.get("descriptors") is not True
        ):
            raise ValueError()
        recovered = recover_authenticated_sponsored_imports(
            get_session, trusted_wallet_rpc=wallet, now=datetime.now(timezone.utc).replace(microsecond=0), maximum=256
        )
        result = refresh_automatic_imports(get_session)
        result["recovered_imports"] = len(recovered)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print("automatic sponsored refresh unavailable", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
