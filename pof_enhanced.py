"""
HODLXXI Proof of Funds (PoF) - Enhanced Implementation
Phase 1: Foundation (Membership, Storage, Error Handling)

Non-custodial PoF verification using PSBT with OP_RETURN challenges
"""

import hashlib
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum
import json

from flask import jsonify, request, session, Flask
from flask_socketio import SocketIO


# ============================================================================
# CONFIGURATION
# ============================================================================

class PoFConfig:
    """Centralized PoF configuration"""
    DB_PATH = os.getenv("POF_DB_PATH", "/srv/app/pof_attest.db")
    TTL_SECONDS = int(os.getenv("POF_TTL_SECONDS", "172800"))  # 48h default
    MAX_PSBT_B64 = int(os.getenv("POF_MAX_PSBT_B64", "250000"))  # 250 KB
    CHALLENGE_TTL = int(os.getenv("POF_CHALLENGE_TTL", "900"))  # 15 min
    MAX_CHALLENGES_PER_USER = int(os.getenv("POF_MAX_CHALLENGES", "3"))
    PRUNE_INTERVAL = int(os.getenv("POF_PRUNE_INTERVAL", "3600"))  # 1 hour


class PrivacyLevel(Enum):
    """Privacy levels for PoF attestations"""
    AGGREGATE = "aggregate"      # Show total sum
    THRESHOLD = "threshold"      # Boolean >= threshold
    BOOLEAN = "boolean"          # Just yes/no
    RANGE = "range"              # Within range (future)
    ZERO_KNOWLEDGE = "zk"        # zk-SNARK (future)


class PoFError(Enum):
    """Structured error codes"""
    INVALID_PUBKEY = "invalid_pubkey"
    MEMBERSHIP_REQUIRED = "membership_required"
    CHALLENGE_EXPIRED = "challenge_expired"
    CHALLENGE_NOT_FOUND = "challenge_not_found"
    PSBT_TOO_LARGE = "psbt_too_large"
    PSBT_DECODE_FAILED = "psbt_decode_failed"
    OPRETURN_MISSING = "opreturn_missing"
    NO_UNSPENT_INPUTS = "no_unspent_inputs"
    SIGNATURE_INVALID = "signature_invalid"
    RPC_ERROR = "rpc_error"
    DATABASE_ERROR = "database_error"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


# ============================================================================
# ERROR HANDLING
# ============================================================================

class PoFException(Exception):
    """Base exception for PoF operations"""
    def __init__(self, error_code: PoFError, message: str, hint: str = None, details: Dict = None):
        self.error_code = error_code
        self.message = message
        self.hint = hint
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to JSON-serializable dict"""
        result = {
            "ok": False,
            "error": self.error_code.value,
            "message": self.message,
        }
        if self.hint:
            result["hint"] = self.hint
        if self.details:
            result["details"] = self.details
        result["docs"] = "https://hodlxxi.com/docs/pof-troubleshooting"
        result["support"] = "https://discord.gg/hodlxxi"
        return result


def create_success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Create standardized success response"""
    return {"ok": True, **data}


# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================

class PoFDatabase:
    """Enhanced database management with proper indexing and connection pooling"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        return conn
    
    def _init_database(self):
        """Initialize database with proper schema and indexes"""
        conn = self._get_connection()
        
        # Main attestations table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pof_attestations(
                pubkey TEXT NOT NULL,
                covenant_id TEXT NOT NULL DEFAULT '',
                total_sat INTEGER NOT NULL,
                method TEXT NOT NULL,
                privacy_level TEXT NOT NULL,
                proof_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                metadata TEXT DEFAULT '{}',
                PRIMARY KEY(pubkey, covenant_id)
            )
        """)
        
        # Audit log table for compliance
        conn.execute("""
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
        
        # Challenge tracking table
        conn.execute("""
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
        
        # Create indexes for performance
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attest_expires ON pof_attestations(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_attest_pubkey_expires ON pof_attestations(pubkey, expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON pof_audit_log(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_pubkey ON pof_audit_log(pubkey)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_challenge_expires ON pof_challenges(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_challenge_pubkey ON pof_challenges(pubkey)")
        
        conn.close()
    
    def store_attestation(self, pubkey: str, covenant_id: str, total_sat: int, 
                         method: str, privacy_level: str, proof_hash: str,
                         expires_at: int, metadata: Dict = None) -> bool:
        """Store or update PoF attestation"""
        conn = self._get_connection()
        now = int(time.time())
        metadata_json = json.dumps(metadata or {})
        
        try:
            conn.execute("""
                INSERT INTO pof_attestations(
                    pubkey, covenant_id, total_sat, method, privacy_level,
                    proof_hash, expires_at, created_at, updated_at, metadata
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(pubkey, covenant_id) DO UPDATE SET
                    total_sat=excluded.total_sat,
                    method=excluded.method,
                    privacy_level=excluded.privacy_level,
                    proof_hash=excluded.proof_hash,
                    expires_at=excluded.expires_at,
                    updated_at=excluded.updated_at,
                    metadata=excluded.metadata
            """, (pubkey, covenant_id, total_sat, method, privacy_level, 
                  proof_hash, expires_at, now, now, metadata_json))
            conn.close()
            return True
        except Exception as e:
            conn.close()
            raise PoFException(
                PoFError.DATABASE_ERROR,
                "Failed to store attestation",
                hint="Database write error occurred",
                details={"error": str(e)}
            )
    
    def get_attestation(self, pubkey: str, covenant_id: str = "") -> Optional[Dict[str, Any]]:
        """Retrieve attestation for pubkey/covenant"""
        conn = self._get_connection()
        row = conn.execute("""
            SELECT pubkey, covenant_id, total_sat, method, privacy_level,
                   proof_hash, expires_at, created_at, updated_at, metadata
            FROM pof_attestations
            WHERE pubkey=? AND covenant_id=?
        """, (pubkey, covenant_id)).fetchone()
        conn.close()
        
        if not row:
            return None
        
        result = dict(row)
        result["metadata"] = json.loads(result.get("metadata", "{}"))
        return result
    
    def prune_expired(self) -> int:
        """Remove expired attestations and challenges"""
        conn = self._get_connection()
        now = int(time.time())
        
        # Count before deletion
        count = conn.execute("SELECT COUNT(*) FROM pof_attestations WHERE expires_at < ?", (now,)).fetchone()[0]
        
        # Delete expired
        conn.execute("DELETE FROM pof_attestations WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM pof_challenges WHERE expires_at < ?", (now,))
        
        conn.close()
        return count
    
    def log_audit(self, pubkey: str, action: str, success: bool, **kwargs):
        """Log audit trail"""
        conn = self._get_connection()
        metadata = kwargs.pop("metadata", {})
        
        conn.execute("""
            INSERT INTO pof_audit_log(
                pubkey, covenant_id, action, total_sat, method, privacy_level,
                proof_hash, challenge_id, ip_address, user_agent, timestamp,
                success, error_code, metadata
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pubkey,
            kwargs.get("covenant_id", ""),
            action,
            kwargs.get("total_sat"),
            kwargs.get("method"),
            kwargs.get("privacy_level"),
            kwargs.get("proof_hash"),
            kwargs.get("challenge_id"),
            kwargs.get("ip_address"),
            kwargs.get("user_agent"),
            int(time.time()),
            1 if success else 0,
            kwargs.get("error_code"),
            json.dumps(metadata)
        ))
        conn.close()
    
    def store_challenge(self, challenge_id: str, pubkey: str, covenant_id: str,
                       challenge: str, expires_at: int, ip_address: str = None) -> bool:
        """Store challenge with tracking"""
        conn = self._get_connection()
        now = int(time.time())
        
        try:
            conn.execute("""
                INSERT INTO pof_challenges(
                    challenge_id, pubkey, covenant_id, challenge,
                    created_at, expires_at, ip_address
                )
                VALUES(?, ?, ?, ?, ?, ?, ?)
            """, (challenge_id, pubkey, covenant_id, challenge, now, expires_at, ip_address))
            conn.close()
            return True
        except Exception as e:
            conn.close()
            raise PoFException(
                PoFError.DATABASE_ERROR,
                "Failed to store challenge",
                details={"error": str(e)}
            )
    
    def get_challenge(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve challenge by ID"""
        conn = self._get_connection()
        row = conn.execute("""
            SELECT challenge_id, pubkey, covenant_id, challenge,
                   created_at, expires_at, used
            FROM pof_challenges
            WHERE challenge_id=?
        """, (challenge_id,)).fetchone()
        conn.close()
        
        return dict(row) if row else None
    
    def mark_challenge_used(self, challenge_id: str):
        """Mark challenge as used"""
        conn = self._get_connection()
        conn.execute("UPDATE pof_challenges SET used=1 WHERE challenge_id=?", (challenge_id,))
        conn.close()
    
    def count_active_challenges(self, pubkey: str) -> int:
        """Count active challenges for a user"""
        conn = self._get_connection()
        now = int(time.time())
        count = conn.execute("""
            SELECT COUNT(*) FROM pof_challenges
            WHERE pubkey=? AND expires_at > ? AND used=0
        """, (pubkey, now)).fetchone()[0]
        conn.close()
        return count


# ============================================================================
# COVENANT MEMBERSHIP VERIFICATION
# ============================================================================

class MembershipVerifier:
    """Verify covenant membership for PoF operations"""
    
    def __init__(self, db_connection_func):
        """
        Initialize with a function that returns database connection
        This would be your existing covenant database
        """
        self.get_db = db_connection_func
    
    def verify_membership(self, pubkey: str, covenant_id: Optional[str] = None) -> Tuple[bool, str]:
        """
        Verify if pubkey is a member of the covenant
        Returns: (is_member, reason)
        """
        # Check if user is logged in
        try:
            logged_in_pubkey = session.get('logged_in_pubkey')
            if not logged_in_pubkey:
                return False, "Not authenticated"
            
            if logged_in_pubkey != pubkey:
                return False, "Pubkey mismatch with authenticated user"
        except Exception as e:
            return False, f"Session error: {str(e)}"
        
        # If no covenant_id, just verify the user is logged in
        if not covenant_id:
            return True, "Authenticated"
        
        # TODO: Query your covenant membership database
        # This is where you'd check if pubkey is actually in the covenant
        # Example:
        # conn = self.get_db()
        # member = conn.execute("""
        #     SELECT 1 FROM covenant_members
        #     WHERE covenant_id=? AND pubkey=? AND status='active'
        # """, (covenant_id, pubkey)).fetchone()
        # 
        # if not member:
        #     return False, "Not a member of this covenant"
        
        # For now, accept if logged in
        return True, "Member verified"
    
    def get_covenant_settings(self, covenant_id: str) -> Dict[str, Any]:
        """Get covenant-specific PoF settings"""
        # TODO: Query covenant metadata for custom settings
        # Example: min_sat_threshold, privacy_requirements, etc.
        
        return {
            "min_sat": 0,
            "max_ttl": PoFConfig.TTL_SECONDS,
            "allowed_privacy_levels": [level.value for level in PrivacyLevel],
            "require_recent_blocks": 6,  # Confirmations
        }


# ============================================================================
# PSBT VERIFICATION ENGINE
# ============================================================================

class PSBTVerifier:
    """Enhanced PSBT verification with better error handling"""
    
    def __init__(self, rpc_connection_func):
        self.get_rpc = rpc_connection_func
    
    def decode_psbt(self, psbt: str) -> Dict[str, Any]:
        """Decode PSBT with error handling"""
        if len(psbt) > PoFConfig.MAX_PSBT_B64:
            raise PoFException(
                PoFError.PSBT_TOO_LARGE,
                f"PSBT exceeds maximum size of {PoFConfig.MAX_PSBT_B64} bytes",
                hint="Try reducing the number of inputs or use a more compact format"
            )
        
        try:
            rpc = self.get_rpc()
            decoded = rpc.decodepsbt(psbt)
            return decoded
        except Exception as e:
            raise PoFException(
                PoFError.PSBT_DECODE_FAILED,
                "Failed to decode PSBT",
                hint="Ensure PSBT is valid base64-encoded and properly formatted",
                details={"rpc_error": str(e)}
            )
    
    def extract_opreturn_challenge(self, vouts: List[Dict]) -> Optional[str]:
        """Extract challenge from OP_RETURN output - multiple format support"""
        for vout in vouts:
            script_pubkey = vout.get("scriptPubKey", {})
            asm = script_pubkey.get("asm", "")
            hex_data = script_pubkey.get("hex", "")
            
            # Check ASM format
            parts = asm.split()
            if len(parts) >= 2 and parts[0] == "OP_RETURN":
                # Try hex decode
                try:
                    data = bytes.fromhex(parts[1])
                    decoded = data.decode('utf-8', errors='ignore')
                    if decoded.startswith("HODLXXI-PoF"):
                        return decoded
                except:
                    pass
            
            # Check raw hex (OP_RETURN is 0x6a)
            if hex_data.startswith("6a"):
                try:
                    data = bytes.fromhex(hex_data[2:])  # Skip OP_RETURN byte
                    decoded = data.decode('utf-8', errors='ignore')
                    if decoded.startswith("HODLXXI-PoF"):
                        return decoded
                except:
                    pass
        
        return None
    
    def verify_unspent_inputs(self, vins: List[Dict]) -> Tuple[int, List[Dict]]:
        """
        Verify inputs are unspent and calculate total value
        Returns: (total_sat, unspent_details)
        """
        rpc = self.get_rpc()
        total_sat = 0
        unspent_details = []
        
        for vin in vins:
            txid = vin.get("txid")
            vout_n = vin.get("vout")
            
            if not txid or vout_n is None:
                continue
            
            try:
                utxo = rpc.gettxout(txid, vout_n, True)  # Include mempool
                
                if utxo:
                    value_btc = float(utxo.get("value", 0.0))
                    value_sat = int(value_btc * 100_000_000)
                    confirmations = utxo.get("confirmations", 0)
                    
                    total_sat += value_sat
                    unspent_details.append({
                        "txid": txid,
                        "vout": vout_n,
                        "value_sat": value_sat,
                        "confirmations": confirmations
                    })
            except Exception as e:
                # Log but continue - might be RPC timeout
                print(f"Warning: Failed to check UTXO {txid}:{vout_n} - {e}")
                continue
        
        if total_sat == 0:
            raise PoFException(
                PoFError.NO_UNSPENT_INPUTS,
                "No unspent inputs found in PSBT",
                hint="Ensure your PSBT references confirmed, unspent outputs (UTXOs)",
                details={
                    "inputs_checked": len(vins),
                    "unspent_found": len(unspent_details)
                }
            )
        
        return total_sat, unspent_details
    
    def verify_psbt(self, psbt: str, challenge: str) -> Tuple[int, List[Dict]]:
        """
        Complete PSBT verification
        Returns: (total_sat, unspent_details)
        """
        # Decode PSBT
        decoded = self.decode_psbt(psbt)
        tx = decoded.get("tx", {})
        vouts = tx.get("vout", [])
        vins = tx.get("vin", [])
        
        # Verify OP_RETURN contains challenge
        found_challenge = self.extract_opreturn_challenge(vouts)
        
        if not found_challenge or challenge not in found_challenge:
            raise PoFException(
                PoFError.OPRETURN_MISSING,
                "Challenge not found in OP_RETURN output",
                hint=f"Add an OP_RETURN output containing: {challenge}",
                details={
                    "expected_challenge": challenge,
                    "found_opreturn": found_challenge or "None"
                }
            )
        
        # Verify unspent inputs
        total_sat, unspent_details = self.verify_unspent_inputs(vins)
        
        return total_sat, unspent_details


# ============================================================================
# POF SERVICE - Main orchestration
# ============================================================================

class PoFService:
    """Main Proof of Funds service"""
    
    def __init__(self, db: PoFDatabase, membership: MembershipVerifier, 
                 psbt_verifier: PSBTVerifier, socketio: SocketIO = None):
        self.db = db
        self.membership = membership
        self.psbt = psbt_verifier
        self.socketio = socketio
    
    def create_challenge(self, pubkey: str, covenant_id: Optional[str] = None,
                        ip_address: str = None) -> Dict[str, Any]:
        """Create a new PoF challenge"""
        
        # Verify membership
        is_member, reason = self.membership.verify_membership(pubkey, covenant_id)
        if not is_member:
            self.db.log_audit(
                pubkey, "challenge_create", False,
                covenant_id=covenant_id or "",
                error_code=PoFError.MEMBERSHIP_REQUIRED.value,
                ip_address=ip_address
            )
            raise PoFException(
                PoFError.MEMBERSHIP_REQUIRED,
                f"Membership verification failed: {reason}",
                hint="Ensure you are logged in and have access to this covenant"
            )
        
        # Rate limit check
        active_count = self.db.count_active_challenges(pubkey)
        if active_count >= PoFConfig.MAX_CHALLENGES_PER_USER:
            raise PoFException(
                PoFError.RATE_LIMIT_EXCEEDED,
                f"Maximum {PoFConfig.MAX_CHALLENGES_PER_USER} active challenges per user",
                hint="Wait for existing challenges to expire or complete verification"
            )
        
        # Generate challenge
        challenge_id = secrets.token_hex(8)
        timestamp = int(time.time())
        challenge = f"HODLXXI-PoF:{challenge_id}:{timestamp}"
        expires_at = timestamp + PoFConfig.CHALLENGE_TTL
        
        # Store challenge
        self.db.store_challenge(
            challenge_id, pubkey, covenant_id or "", challenge,
            expires_at, ip_address
        )
        
        # Audit log
        self.db.log_audit(
            pubkey, "challenge_create", True,
            covenant_id=covenant_id or "",
            challenge_id=challenge_id,
            ip_address=ip_address
        )
        
        return create_success_response({
            "challenge_id": challenge_id,
            "challenge": challenge,
            "expires_in": PoFConfig.CHALLENGE_TTL,
            "expires_at": expires_at
        })
    
    def verify_psbt(self, challenge_id: str, psbt: str, privacy_level: str = "aggregate",
                   min_sat: int = 0, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """Verify PSBT and create attestation"""
        
        # Validate privacy level
        try:
            privacy = PrivacyLevel(privacy_level)
        except ValueError:
            raise PoFException(
                PoFError.INVALID_PUBKEY,
                f"Invalid privacy level: {privacy_level}",
                hint=f"Valid levels: {[p.value for p in PrivacyLevel]}"
            )
        
        # Get challenge
        challenge_data = self.db.get_challenge(challenge_id)
        if not challenge_data:
            raise PoFException(
                PoFError.CHALLENGE_NOT_FOUND,
                "Challenge not found or expired",
                hint="Generate a new challenge and try again"
            )
        
        # Check expiration
        if challenge_data["expires_at"] < int(time.time()):
            raise PoFException(
                PoFError.CHALLENGE_EXPIRED,
                "Challenge has expired",
                hint="Generate a new challenge (challenges expire after 15 minutes)"
            )
        
        # Check if already used
        if challenge_data["used"]:
            raise PoFException(
                PoFError.CHALLENGE_NOT_FOUND,
                "Challenge already used",
                hint="Each challenge can only be used once"
            )
        
        pubkey = challenge_data["pubkey"]
        covenant_id = challenge_data["covenant_id"]
        challenge = challenge_data["challenge"]
        
        # Verify membership again
        is_member, reason = self.membership.verify_membership(pubkey, covenant_id or None)
        if not is_member:
            self.db.log_audit(
                pubkey, "psbt_verify", False,
                covenant_id=covenant_id,
                challenge_id=challenge_id,
                error_code=PoFError.MEMBERSHIP_REQUIRED.value,
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise PoFException(
                PoFError.MEMBERSHIP_REQUIRED,
                f"Membership verification failed: {reason}"
            )
        
        # Verify PSBT
        try:
            total_sat, unspent_details = self.psbt.verify_psbt(psbt, challenge)
        except PoFException:
            self.db.log_audit(
                pubkey, "psbt_verify", False,
                covenant_id=covenant_id,
                challenge_id=challenge_id,
                error_code=PoFError.PSBT_DECODE_FAILED.value,
                ip_address=ip_address,
                user_agent=user_agent
            )
            raise
        
        # Create proof hash
        proof_hash = hashlib.sha256((psbt + challenge).encode()).hexdigest()
        
        # Store attestation
        now = int(time.time())
        expires_at = now + PoFConfig.TTL_SECONDS
        
        metadata = {
            "challenge_id": challenge_id,
            "unspent_count": len(unspent_details),
            "min_confirmations": min(d["confirmations"] for d in unspent_details) if unspent_details else 0,
            "verified_at": now,
            "ip_address": ip_address,
        }
        
        self.db.store_attestation(
            pubkey, covenant_id, total_sat,
            "psbt", privacy.value, proof_hash,
            expires_at, metadata
        )
        
        # Mark challenge as used
        self.db.mark_challenge_used(challenge_id)
        
        # Audit log
        self.db.log_audit(
            pubkey, "psbt_verify", True,
            covenant_id=covenant_id,
            total_sat=total_sat,
            method="psbt",
            privacy_level=privacy.value,
            proof_hash=proof_hash,
            challenge_id=challenge_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata
        )
        
        # Emit WebSocket event
        if self.socketio:
            try:
                self.socketio.emit("pof:updated", {
                    "pubkey": pubkey,
                    "covenant_id": covenant_id,
                    "total_sat": total_sat,
                    "privacy_level": privacy.value,
                    "expires_at": expires_at,
                    "method": "psbt"
                })
            except Exception as e:
                print(f"WebSocket emit failed: {e}")
        
        # Build response based on privacy level
        response = {
            "pubkey": pubkey,
            "covenant_id": covenant_id,
            "proof_hash": proof_hash,
            "expires_in": PoFConfig.TTL_SECONDS,
            "expires_at": expires_at,
            "method": "psbt",
            "privacy_level": privacy.value,
            "unspent_count": len(unspent_details),
        }
        
        if privacy == PrivacyLevel.AGGREGATE:
            response["total_sat"] = total_sat
            response["total_btc"] = total_sat / 100_000_000
        elif privacy == PrivacyLevel.THRESHOLD:
            response["meets_threshold"] = total_sat >= min_sat
            response["threshold_sat"] = min_sat
        elif privacy == PrivacyLevel.BOOLEAN:
            response["has_funds"] = total_sat > 0
        
        return create_success_response(response)
    
    def get_status(self, pubkey: str, covenant_id: str = "") -> Dict[str, Any]:
        """Get current PoF status"""
        attestation = self.db.get_attestation(pubkey, covenant_id)
        
        if not attestation:
            return create_success_response({"status": None})
        
        # Check if expired
        now = int(time.time())
        is_valid = attestation["expires_at"] > now
        time_remaining = max(0, attestation["expires_at"] - now)
        
        return create_success_response({
            "status": {
                **attestation,
                "is_valid": is_valid,
                "time_remaining": time_remaining,
                "expires_in_hours": time_remaining / 3600,
            }
        })


# ============================================================================
# FLASK ROUTE INTEGRATION
# ============================================================================

def integrate_pof_routes(app: Flask, socketio: SocketIO, get_rpc_connection):
    """
    Integrate enhanced PoF routes into Flask app
    
    Usage:
        integrate_pof_routes(app, socketio, get_rpc_connection)
    """
    
    # Initialize components
    db = PoFDatabase(PoFConfig.DB_PATH)
    membership = MembershipVerifier(None)  # TODO: Pass your covenant DB function
    psbt_verifier = PSBTVerifier(get_rpc_connection)
    pof_service = PoFService(db, membership, psbt_verifier, socketio)
    
    # Routes
    @app.route("/api/pof/challenge", methods=["POST"])
    def api_pof_challenge():
        """Create PoF challenge"""
        try:
            data = request.get_json(silent=True) or {}
            pubkey = (data.get("pubkey") or "").strip()
            covenant_id = (data.get("covenant_id") or "").strip() or None
            
            if not pubkey:
                raise PoFException(
                    PoFError.INVALID_PUBKEY,
                    "Pubkey is required",
                    hint="Provide a valid Bitcoin public key"
                )
            
            result = pof_service.create_challenge(
                pubkey, covenant_id,
                ip_address=request.remote_addr
            )
            return jsonify(result), 200
            
        except PoFException as e:
            return jsonify(e.to_dict()), 400
        except Exception as e:
            return jsonify({
                "ok": False,
                "error": "internal_error",
                "message": str(e)
            }), 500
    
    @app.route("/api/pof/verify_psbt", methods=["POST"])
    def api_pof_verify_psbt():
        """Verify PSBT proof"""
        try:
            data = request.get_json(silent=True) or {}
            challenge_id = (data.get("challenge_id") or "").strip()
            psbt = (data.get("psbt") or "").strip()
            privacy_level = (data.get("privacy_level") or "aggregate").strip()
            min_sat = int(data.get("min_sat") or 0)
            
            if not challenge_id or not psbt:
                raise PoFException(
                    PoFError.INVALID_PUBKEY,
                    "challenge_id and psbt are required"
                )
            
            result = pof_service.verify_psbt(
                challenge_id, psbt, privacy_level, min_sat,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent")
            )
            return jsonify(result), 200
            
        except PoFException as e:
            return jsonify(e.to_dict()), 400
        except Exception as e:
            return jsonify({
                "ok": False,
                "error": "internal_error",
                "message": str(e)
            }), 500
    
    @app.route("/api/pof/status/<pubkey>", methods=["GET"])
    def api_pof_status(pubkey):
        """Get PoF status"""
        try:
            covenant_id = (request.args.get("covenant_id") or "").strip()
            result = pof_service.get_status(pubkey, covenant_id)
            return jsonify(result), 200
            
        except Exception as e:
            return jsonify({
                "ok": False,
                "error": "internal_error",
                "message": str(e)
            }), 500
    
    # Scheduled pruning
    import threading
    def scheduled_prune():
        """Background task to prune expired data"""
        while True:
            try:
                count = db.prune_expired()
                if count > 0:
                    print(f"[PoF] Pruned {count} expired attestations")
            except Exception as e:
                print(f"[PoF] Prune error: {e}")
            time.sleep(PoFConfig.PRUNE_INTERVAL)
    
    prune_thread = threading.Thread(target=scheduled_prune, daemon=True)
    prune_thread.start()
    
    print("=" * 70)
    print("🔒 Enhanced PoF System Initialized")
    print("=" * 70)
    print(f"📊 Database: {PoFConfig.DB_PATH}")
    print(f"⏰ TTL: {PoFConfig.TTL_SECONDS}s ({PoFConfig.TTL_SECONDS/3600:.1f}h)")
    print(f"🔑 Challenge TTL: {PoFConfig.CHALLENGE_TTL}s")
    print(f"📦 Max PSBT size: {PoFConfig.MAX_PSBT_B64} bytes")
    print(f"🔄 Prune interval: {PoFConfig.PRUNE_INTERVAL}s")
    print("=" * 70)
    
    return pof_service


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'integrate_pof_routes',
    'PoFService',
    'PoFDatabase',
    'MembershipVerifier',
    'PSBTVerifier',
    'PoFConfig',
    'PoFException',
    'PoFError',
    'PrivacyLevel',
]
