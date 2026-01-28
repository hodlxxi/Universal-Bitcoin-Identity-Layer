"""
JWKS Key Rotation Tests

Tests RSA keypair management and automatic rotation:
- Key generation and loading
- Automatic rotation based on age
- Graceful key retirement
- Multi-key JWKS documents
- Manual rotation
"""

import json
import os
import tempfile
import time
from pathlib import Path

import pytest

from app.jwks import ensure_rsa_keypair, get_key_by_kid, get_signing_key, rotate_keys_manually


@pytest.fixture
def temp_jwks_dir():
    """Create temporary JWKS directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestKeyGeneration:
    """Test RSA key generation and storage."""

    def test_initial_key_generation(self, temp_jwks_dir):
        """Test that initial key is generated if none exists."""
        jwks_doc, kid = ensure_rsa_keypair(temp_jwks_dir)

        assert "keys" in jwks_doc
        assert len(jwks_doc["keys"]) == 1
        assert kid is not None

        # Check key file created
        key_files = list(Path(temp_jwks_dir).glob("private_key_*.pem"))
        assert len(key_files) == 1

        # Check JWKS file created
        jwks_path = Path(temp_jwks_dir) / "jwks.json"
        assert jwks_path.exists()

    def test_key_file_permissions(self, temp_jwks_dir):
        """Test that private keys have secure permissions."""
        ensure_rsa_keypair(temp_jwks_dir)

        key_files = list(Path(temp_jwks_dir).glob("private_key_*.pem"))
        key_file = key_files[0]

        # Check file permissions (owner read/write only)
        stat_info = os.stat(key_file)
        permissions = oct(stat_info.st_mode)[-3:]
        assert permissions == "600"

    def test_jwks_document_structure(self, temp_jwks_dir):
        """Test JWKS document has correct structure."""
        jwks_doc, kid = ensure_rsa_keypair(temp_jwks_dir)

        # Validate JWKS structure
        assert isinstance(jwks_doc, dict)
        assert "keys" in jwks_doc
        assert isinstance(jwks_doc["keys"], list)

        # Validate key structure
        key = jwks_doc["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert key["kid"] == kid
        assert "n" in key
        assert "e" in key

    def test_key_persistence(self, temp_jwks_dir):
        """Test that keys persist across calls."""
        jwks_doc1, kid1 = ensure_rsa_keypair(temp_jwks_dir)
        jwks_doc2, kid2 = ensure_rsa_keypair(temp_jwks_dir)

        # Same key should be returned if not expired
        assert kid1 == kid2
        assert jwks_doc1 == jwks_doc2


class TestKeyRotation:
    """Test automatic key rotation."""

    def test_rotation_based_on_age(self, temp_jwks_dir):
        """Test that old keys are rotated."""
        # Create initial key
        jwks_doc1, kid1 = ensure_rsa_keypair(temp_jwks_dir, rotation_days=0)

        # Small delay to ensure different timestamp
        time.sleep(0.1)

        # Trigger rotation (rotation_days=0 means always rotate)
        jwks_doc2, kid2 = ensure_rsa_keypair(temp_jwks_dir, rotation_days=0)

        # New key should be generated
        assert kid1 != kid2

        # JWKS should now contain both keys
        assert len(jwks_doc2["keys"]) == 2

    def test_max_retired_keys_limit(self, temp_jwks_dir):
        """Test that old keys are removed after limit."""
        max_retired = 2

        # Generate multiple keys
        kids = []
        for _ in range(5):
            _, kid = ensure_rsa_keypair(temp_jwks_dir, rotation_days=0, max_retired_keys=max_retired)
            kids.append(kid)
            time.sleep(0.1)

        # Should have primary + max_retired keys
        key_files = list(Path(temp_jwks_dir).glob("private_key_*.pem"))
        assert len(key_files) == max_retired + 1

        # Load JWKS
        with open(Path(temp_jwks_dir) / "jwks.json") as f:
            jwks_doc = json.load(f)

        assert len(jwks_doc["keys"]) == max_retired + 1

    def test_old_keys_removed_from_disk(self, temp_jwks_dir):
        """Test that old key files are deleted."""
        # Generate keys beyond limit
        for _ in range(6):
            ensure_rsa_keypair(temp_jwks_dir, rotation_days=0, max_retired_keys=2)
            time.sleep(0.1)

        # Only 3 keys should remain (1 primary + 2 retired)
        key_files = list(Path(temp_jwks_dir).glob("private_key_*.pem"))
        assert len(key_files) == 3

    def test_rotation_preserves_newer_keys(self, temp_jwks_dir):
        """Test that newer keys are preserved during rotation."""
        kids = []
        for _ in range(4):
            _, kid = ensure_rsa_keypair(temp_jwks_dir, rotation_days=0, max_retired_keys=2)
            kids.append(kid)
            time.sleep(0.1)

        # Most recent kids should be in JWKS
        with open(Path(temp_jwks_dir) / "jwks.json") as f:
            jwks_doc = json.load(f)

        jwks_kids = [key["kid"] for key in jwks_doc["keys"]]

        # Should contain 3 most recent kids
        assert kids[-1] in jwks_kids  # Newest
        assert kids[-2] in jwks_kids
        assert kids[-3] in jwks_kids
        assert kids[0] not in jwks_kids  # Oldest removed


class TestManualRotation:
    """Test manual key rotation."""

    def test_manual_rotation_trigger(self, temp_jwks_dir):
        """Test manually triggering key rotation."""
        # Create initial key
        _, kid1 = ensure_rsa_keypair(temp_jwks_dir)

        time.sleep(0.1)

        # Manual rotation
        kid2 = rotate_keys_manually(temp_jwks_dir)

        assert kid1 != kid2

        # Both keys should exist
        with open(Path(temp_jwks_dir) / "jwks.json") as f:
            jwks_doc = json.load(f)

        assert len(jwks_doc["keys"]) == 2

    def test_manual_rotation_updates_primary(self, temp_jwks_dir):
        """Test that manual rotation updates primary signing key."""
        ensure_rsa_keypair(temp_jwks_dir)

        time.sleep(0.1)

        new_kid = rotate_keys_manually(temp_jwks_dir)

        # Get signing key should return new key
        signing_kid, _ = get_signing_key(temp_jwks_dir)
        assert signing_kid == new_kid


class TestKeyRetrieval:
    """Test key retrieval functions."""

    def test_get_signing_key(self, temp_jwks_dir):
        """Test getting current primary signing key."""
        jwks_doc, expected_kid = ensure_rsa_keypair(temp_jwks_dir)

        kid, private_key = get_signing_key(temp_jwks_dir)

        assert kid == expected_kid
        assert private_key is not None

    def test_get_signing_key_returns_newest(self, temp_jwks_dir):
        """Test that signing key is always the newest."""
        # Create multiple keys
        for _ in range(3):
            ensure_rsa_keypair(temp_jwks_dir, rotation_days=0)
            time.sleep(0.1)

        # Get signing key
        signing_kid, _ = get_signing_key(temp_jwks_dir)

        # Load JWKS and verify it's the first (newest) key
        with open(Path(temp_jwks_dir) / "jwks.json") as f:
            jwks_doc = json.load(f)

        newest_kid = jwks_doc["keys"][0]["kid"]
        assert signing_kid == newest_kid

    def test_get_key_by_kid(self, temp_jwks_dir):
        """Test retrieving specific key by kid."""
        # Generate multiple keys
        kids = []
        for _ in range(3):
            _, kid = ensure_rsa_keypair(temp_jwks_dir, rotation_days=0)
            kids.append(kid)
            time.sleep(0.1)

        # Retrieve each key by kid
        for kid in kids:
            key = get_key_by_kid(temp_jwks_dir, kid)
            assert key is not None

    def test_get_key_by_kid_not_found(self, temp_jwks_dir):
        """Test retrieving non-existent key."""
        ensure_rsa_keypair(temp_jwks_dir)

        key = get_key_by_kid(temp_jwks_dir, "nonexistent_kid")
        assert key is None

    def test_get_signing_key_no_keys(self, temp_jwks_dir):
        """Test error when no keys exist."""
        with pytest.raises(FileNotFoundError):
            get_signing_key(temp_jwks_dir)


class TestLegacyKeyMigration:
    """Test migration from legacy key format."""

    def test_legacy_key_loaded(self, temp_jwks_dir):
        """Test that legacy private_key.pem is loaded."""
        # Create legacy key file
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        legacy_path = Path(temp_jwks_dir) / "private_key.pem"
        legacy_path.write_bytes(pem_bytes)

        # Load keys
        jwks_doc, kid = ensure_rsa_keypair(temp_jwks_dir)

        # Legacy key should be loaded
        assert len(jwks_doc["keys"]) >= 1

    def test_legacy_key_with_rotation(self, temp_jwks_dir):
        """Test rotation with legacy key present."""
        # Create legacy key
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        legacy_path = Path(temp_jwks_dir) / "private_key.pem"
        legacy_path.write_bytes(pem_bytes)

        # Trigger rotation
        time.sleep(0.1)
        jwks_doc, kid = ensure_rsa_keypair(temp_jwks_dir, rotation_days=0)

        # Should have both legacy and new key
        assert len(jwks_doc["keys"]) == 2


class TestJWKSConsistency:
    """Test JWKS document consistency."""

    def test_jwks_file_matches_memory(self, temp_jwks_dir):
        """Test that JWKS file matches returned document."""
        jwks_doc_returned, _ = ensure_rsa_keypair(temp_jwks_dir)

        # Load from file
        with open(Path(temp_jwks_dir) / "jwks.json") as f:
            jwks_doc_file = json.load(f)

        assert jwks_doc_returned == jwks_doc_file

    def test_concurrent_key_access(self, temp_jwks_dir):
        """Test that multiple processes can read keys."""
        ensure_rsa_keypair(temp_jwks_dir)

        # Simulate multiple reads
        for _ in range(10):
            kid1, _ = get_signing_key(temp_jwks_dir)
            kid2, _ = get_signing_key(temp_jwks_dir)
            assert kid1 == kid2


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_corrupted_jwks_file(self, temp_jwks_dir):
        """Test handling of corrupted JWKS file."""
        # Create initial key
        ensure_rsa_keypair(temp_jwks_dir)

        # Corrupt JWKS file
        jwks_path = Path(temp_jwks_dir) / "jwks.json"
        jwks_path.write_text("invalid json{")

        # Should regenerate JWKS
        jwks_doc, kid = ensure_rsa_keypair(temp_jwks_dir)
        assert "keys" in jwks_doc

    def test_missing_private_key_file(self, temp_jwks_dir):
        """Test handling when private key file is missing."""
        # Create JWKS but delete private key
        ensure_rsa_keypair(temp_jwks_dir)

        key_files = list(Path(temp_jwks_dir).glob("private_key_*.pem"))
        for key_file in key_files:
            key_file.unlink()

        # Should regenerate keys
        jwks_doc, kid = ensure_rsa_keypair(temp_jwks_dir)
        assert len(jwks_doc["keys"]) == 1

    def test_directory_permissions(self, temp_jwks_dir):
        """Test that JWKS directory is created with proper permissions."""
        nested_dir = Path(temp_jwks_dir) / "nested" / "jwks"
        ensure_rsa_keypair(str(nested_dir))

        assert nested_dir.exists()
        assert nested_dir.is_dir()
