import sqlite3
import time
from pathlib import Path

DB_PATH = "/srv/ubid/pof_attest.db"

def column_exists(conn, table, column):
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r[1] == column for r in rows)

def migrate():
    db_file = Path(DB_PATH)
    if not db_file.exists():
        print(f"❌ DB not found at {DB_PATH}")
        return

    print(f"🔧 Migrating PoF DB: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.isolation_level = None
    cur = conn.cursor()

    # List tables
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )]
    print("   Existing tables:", tables)

    # --- 1) Add columns to pof_attestations if needed ---
    if "pof_attestations" in tables:
        print("   Updating pof_attestations schema...")

        if not column_exists(conn, "pof_attestations", "updated_at"):
            try:
                cur.execute("ALTER TABLE pof_attestations ADD COLUMN updated_at INTEGER")
                print("      ✅ added updated_at")
            except Exception as e:
                print("      ⚠️  could not add updated_at:", e)

        if not column_exists(conn, "pof_attestations", "metadata"):
            try:
                cur.execute("ALTER TABLE pof_attestations ADD COLUMN metadata TEXT DEFAULT '{}'")
                print("      ✅ added metadata")
            except Exception as e:
                print("      ⚠️  could not add metadata:", e)

        # Normalize updated_at
        try:
            cur.execute("""
                UPDATE pof_attestations
                SET updated_at = COALESCE(updated_at, created_at)
            """)
            print("      ✅ normalized updated_at")
        except Exception as e:
            print("      ⚠️  could not normalize updated_at:", e)

    # Refresh table list
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )]

    # --- 2) Create pof_audit_log if missing ---
    if "pof_audit_log" not in tables:
        print("   Creating pof_audit_log...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pof_audit_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pubkey TEXT NOT NULL,
                covenant_id TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                total_sat INTEGER,
                method TEXT,
                privacy_level TEXT,
                proof_hash TEXT,
                challenge_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp INTEGER NOT NULL,
                success INTEGER NOT NULL,
                error_code TEXT,
                metadata TEXT DEFAULT '{}'
            )
        """)
        print("      ✅ pof_audit_log created")

    # --- 3) Create pof_challenges if missing ---
    if "pof_challenges" not in tables:
        print("   Creating pof_challenges...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pof_challenges(
                challenge_id TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                covenant_id TEXT NOT NULL DEFAULT '',
                challenge TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER DEFAULT 0,
                ip_address TEXT
            )
        """)
        print("      ✅ pof_challenges created")

    # --- 4) Indexes ---
    print("   Ensuring indexes...")
    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_attest_expires ON pof_attestations(expires_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_attest_pubkey_expires ON pof_attestations(pubkey, expires_at)")
    except Exception as e:
        print("      ⚠️  attest index issue:", e)

    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON pof_audit_log(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_pubkey ON pof_audit_log(pubkey)")
    except Exception as e:
        print("      ⚠️  audit index issue:", e)

    try:
        cur.execute("CREATE INDEX IF NOT EXISTS idx_challenge_expires ON pof_challenges(expires_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_challenge_pubkey ON pof_challenges(pubkey)")
    except Exception as e:
        print("      ⚠️  challenge index issue:", e)

    conn.commit()
    conn.close()
    print("✅ Migration complete.")

if __name__ == "__main__":
    migrate()
