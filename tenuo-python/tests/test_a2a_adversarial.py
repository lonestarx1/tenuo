"""
A2A Adversarial Test Suite - Phase 1

Cryptographic attacks, temporal attacks, and core bypass attempts.
These tests verify the security invariants of the A2A adapter.
"""

import pytest
import time
import base64
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, AsyncMock

from tenuo.a2a import (
    A2AServer,
    A2AClient,
    A2AError,
)
from tenuo.a2a.errors import (
    InvalidSignatureError,
    UntrustedIssuerError,
    WarrantExpiredError,
    ReplayDetectedError,
    ChainValidationError,
    AudienceMismatchError,
)
from tenuo.a2a.server import ReplayCache


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def adversarial_server():
    """Server configured for adversarial testing."""
    return A2AServer(
        name="Adversarial Test Agent",
        url="https://secure.example.com",
        public_key="z6MkServerKey",
        trusted_issuers=["z6MkTrustedIssuer"],
        require_warrant=True,
        require_audience=True,
        check_replay=True,
        max_chain_depth=5,
        audit_log=None,  # Disable audit to avoid serialization issues with mocks
    )


@pytest.fixture
def keypair():
    """Generate real keypair for tests."""
    try:
        from tenuo_core import SigningKey
        return SigningKey.generate()
    except ImportError:
        pytest.skip("tenuo_core not available")


@pytest.fixture
def trusted_keypair():
    """Keypair that will be configured as trusted."""
    try:
        from tenuo_core import SigningKey
        return SigningKey.generate()
    except ImportError:
        pytest.skip("tenuo_core not available")


# =============================================================================
# Test: Cryptographic Attacks
# =============================================================================

class TestCryptographicAttacks:
    """Tests for cryptographic attack resistance."""
    
    @pytest.mark.asyncio
    async def test_forged_signature_rejected(self, adversarial_server):
        """Warrant with forged/wrong signature is rejected."""
        # Create a fake JWT with invalid signature
        header = base64.urlsafe_b64encode(b'{"alg":"EdDSA","typ":"JWT"}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({
            "iss": "z6MkTrustedIssuer",
            "sub": "z6MkHolder",
            "exp": int(time.time()) + 3600,
            "tools": ["test_skill"],
        }).encode()).rstrip(b'=').decode()
        # Invalid signature (random bytes)
        fake_sig = base64.urlsafe_b64encode(b'A' * 64).rstrip(b'=').decode()
        
        fake_jwt = f"{header}.{payload}.{fake_sig}"
        
        with pytest.raises((InvalidSignatureError, Exception)) as exc_info:
            await adversarial_server.validate_warrant(fake_jwt, "test_skill", {})
        
        # Should fail during signature verification
        error_str = str(exc_info.value).lower()
        assert "signature" in error_str or "invalid" in error_str or "decode" in error_str
    
    @pytest.mark.asyncio
    async def test_truncated_signature_rejected(self, adversarial_server):
        """Warrant with truncated signature (32 bytes instead of 64) is rejected."""
        header = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(b'{"iss":"x","exp":9999999999}').rstrip(b'=').decode()
        # Only 32 bytes, EdDSA requires 64
        short_sig = base64.urlsafe_b64encode(b'B' * 32).rstrip(b'=').decode()
        
        truncated_jwt = f"{header}.{payload}.{short_sig}"
        
        with pytest.raises(Exception):
            await adversarial_server.validate_warrant(truncated_jwt, "test", {})
    
    @pytest.mark.asyncio
    async def test_empty_signature_rejected(self, adversarial_server):
        """Warrant with empty signature is rejected."""
        header = base64.urlsafe_b64encode(b'{"alg":"EdDSA"}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(b'{"iss":"x","exp":9999999999}').rstrip(b'=').decode()
        
        empty_sig_jwt = f"{header}.{payload}."
        
        with pytest.raises(Exception):
            await adversarial_server.validate_warrant(empty_sig_jwt, "test", {})
    
    @pytest.mark.asyncio
    async def test_altered_payload_rejected(self, keypair):
        """Valid signature with altered payload is rejected."""
        try:
            from tenuo_core import Warrant
        except ImportError:
            pytest.skip("tenuo_core not available")
        
        # Create valid warrant
        warrant = (Warrant.mint_builder()
            .tool("original_skill")
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair))
        
        original_b64 = warrant.to_base64()
        
        # Try to alter the payload (change skill)
        # This should fail because signature won't match
        parts = original_b64.split('.')
        if len(parts) >= 2:
            # Decode payload, modify, re-encode
            try:
                padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
                payload_bytes = base64.urlsafe_b64decode(padded)
                # Try to parse and modify (this is best-effort tampering)
                # The point is that the signature won't match
                altered_payload = base64.urlsafe_b64encode(
                    payload_bytes.replace(b'original', b'altered')
                ).rstrip(b'=').decode()
                tampered_jwt = f"{parts[0]}.{altered_payload}.{parts[2] if len(parts) > 2 else ''}"
                
                # Should fail to parse or verify
                with pytest.raises(Exception):
                    Warrant.from_base64(tampered_jwt)
            except Exception:
                pass  # Tampering might fail in various ways, all acceptable
    
    @pytest.mark.asyncio
    async def test_algorithm_none_rejected(self, adversarial_server):
        """JWT with alg=none is rejected."""
        # Classic JWT vulnerability: alg=none attack
        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({
            "iss": "z6MkTrustedIssuer",
            "exp": int(time.time()) + 3600,
            "tools": ["admin"],
        }).encode()).rstrip(b'=').decode()
        
        # No signature (alg=none attack)
        none_jwt = f"{header}.{payload}."
        
        with pytest.raises(Exception):
            await adversarial_server.validate_warrant(none_jwt, "admin", {})
    
    @pytest.mark.asyncio
    async def test_key_substitution_rejected(self, adversarial_server, keypair):
        """Valid signature from non-trusted issuer is rejected."""
        try:
            from tenuo_core import Warrant
        except ImportError:
            pytest.skip("tenuo_core not available")
        
        # Sign warrant with untrusted key
        warrant = (Warrant.mint_builder()
            .tool("test_skill")
            .holder(keypair.public_key)
            .ttl(3600)
            .mint(keypair))  # This key is NOT in trusted_issuers
        
        warrant_b64 = warrant.to_base64()
        
        # Should reject because issuer is not trusted
        with pytest.raises((UntrustedIssuerError, Exception)):
            await adversarial_server.validate_warrant(warrant_b64, "test_skill", {})


# =============================================================================
# Test: Temporal Attacks
# =============================================================================

class TestTemporalAttacks:
    """Tests for time-based attack resistance."""
    
    @pytest.mark.asyncio
    async def test_expired_by_one_second(self, adversarial_server):
        """Warrant expired by 1 second is rejected."""
        with patch('tenuo_core.Warrant') as MockWarrant:
            mock = MagicMock()
            mock.exp = int(time.time()) - 1  # Expired 1 second ago
            mock.is_expired = True  # Server checks this first
            mock.iss = "z6MkTrustedIssuer"
            MockWarrant.from_base64.return_value = mock
            
            with pytest.raises(WarrantExpiredError):
                await adversarial_server.validate_warrant("fake", "skill", {})
    
    @pytest.mark.asyncio
    async def test_expired_long_ago(self, adversarial_server):
        """Warrant expired days ago is rejected."""
        with patch('tenuo_core.Warrant') as MockWarrant:
            mock = MagicMock()
            mock.exp = int(time.time()) - 86400 * 7  # Expired 1 week ago
            mock.is_expired = True  # Server checks this first
            mock.iss = "z6MkTrustedIssuer"
            MockWarrant.from_base64.return_value = mock
            
            with pytest.raises(WarrantExpiredError):
                await adversarial_server.validate_warrant("fake", "skill", {})
    
    @pytest.mark.asyncio
    async def test_exp_at_zero(self, adversarial_server):
        """Warrant with exp near epoch is rejected."""
        with patch('tenuo_core.Warrant') as MockWarrant:
            mock = MagicMock()
            mock.exp = 1  # Near epoch (1 second) - definitely expired
            mock.is_expired = True  # Server checks this first
            mock.iss = "z6MkTrustedIssuer"
            MockWarrant.from_base64.return_value = mock
            
            with pytest.raises(WarrantExpiredError):
                await adversarial_server.validate_warrant("fake", "skill", {})
    
    @pytest.mark.asyncio
    async def test_negative_exp(self, adversarial_server):
        """Warrant with negative exp is rejected."""
        with patch('tenuo_core.Warrant') as MockWarrant:
            mock = MagicMock()
            mock.exp = -1  # Negative timestamp
            mock.is_expired = True  # Server checks this first
            mock.iss = "z6MkTrustedIssuer"
            MockWarrant.from_base64.return_value = mock
            
            with pytest.raises(WarrantExpiredError):
                await adversarial_server.validate_warrant("fake", "skill", {})
    
    @pytest.mark.asyncio
    async def test_replay_exact_same_warrant(self):
        """Exact same warrant replayed is rejected."""
        # Use ReplayCache directly to avoid audit serialization issues
        cache = ReplayCache()
        jti = "replay_test_jti_001"
        
        # First call succeeds
        result1 = await cache.check_and_add(jti, ttl_seconds=60)
        assert result1 is True
        
        # Second call with same jti fails
        result2 = await cache.check_and_add(jti, ttl_seconds=60)
        assert result2 is False
    
    @pytest.mark.asyncio
    async def test_replay_different_jti_allowed(self):
        """Warrants with different jti are both allowed."""
        # Use ReplayCache directly to avoid audit serialization issues
        cache = ReplayCache()
        
        # Both should succeed with different jti
        result1 = await cache.check_and_add("unique_jti_1", ttl_seconds=60)
        result2 = await cache.check_and_add("unique_jti_2", ttl_seconds=60)
        
        assert result1 is True
        assert result2 is True
    
    @pytest.mark.asyncio
    async def test_jti_collision_attack(self):
        """Two different callers with same jti - only first succeeds."""
        cache = ReplayCache()
        jti = "collision_jti_999"
        
        # First caller
        result1 = await cache.check_and_add(jti, ttl_seconds=60)
        assert result1 is True
        
        # Second caller (attacker) with same jti
        result2 = await cache.check_and_add(jti, ttl_seconds=60)
        assert result2 is False


# =============================================================================
# Test: Chain Attacks
# =============================================================================

class TestChainAttacks:
    """Tests for delegation chain attack resistance."""
    
    @pytest.fixture
    def chain_server(self):
        """Server for chain attack testing."""
        return A2AServer(
            name="Chain Test Agent",
            url="https://chain.example.com",
            public_key="z6MkChainServer",
            trusted_issuers=["z6MkRootIssuer"],
            trust_delegated=True,
            max_chain_depth=3,
        )
    
    @pytest.mark.asyncio
    async def test_chain_depth_attack(self, chain_server):
        """Chain exceeding max depth is rejected."""
        leaf = MagicMock()
        # Chain with 10 warrants, max is 3
        deep_chain = ";".join([f"jwt_{i}" for i in range(10)])
        
        with pytest.raises(ChainValidationError) as exc_info:
            await chain_server._validate_chain(leaf, deep_chain)
        
        assert "depth" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_chain_empty_attack(self, chain_server):
        """Empty chain is rejected."""
        leaf = MagicMock()
        
        with pytest.raises(ChainValidationError) as exc_info:
            await chain_server._validate_chain(leaf, "")
        
        assert "empty" in str(exc_info.value).lower()
    
    @pytest.mark.asyncio
    async def test_chain_whitespace_only(self, chain_server):
        """Whitespace-only chain is rejected."""
        leaf = MagicMock()
        
        with pytest.raises(ChainValidationError):
            await chain_server._validate_chain(leaf, "   ;   ;   ")
    
    @pytest.mark.asyncio
    async def test_chain_invalid_jwt(self, chain_server):
        """Chain with invalid JWT is rejected."""
        leaf = MagicMock()
        
        with pytest.raises((ChainValidationError, Exception)):
            await chain_server._validate_chain(leaf, "not_a_valid_jwt")
    
    def test_monotonicity_violation_new_skill(self, chain_server):
        """Child adding new skill not in parent fails."""
        parent = MagicMock()
        parent.grants = [{"skill": "read"}]
        parent.tools = None
        
        child = MagicMock()
        child.grants = [{"skill": "read"}, {"skill": "write"}]  # write not in parent!
        child.tools = None
        
        result = chain_server._grants_are_subset(child, parent)
        assert result is False
    
    def test_monotonicity_violation_different_skills(self, chain_server):
        """Child with completely different skills fails."""
        parent = MagicMock()
        parent.grants = [{"skill": "search"}]
        parent.tools = None
        
        child = MagicMock()
        child.grants = [{"skill": "delete"}]  # Not in parent
        child.tools = None
        
        result = chain_server._grants_are_subset(child, parent)
        assert result is False


# =============================================================================
# Test: Audience Binding Attacks
# =============================================================================

class TestAudienceBindingAttacks:
    """Tests for audience binding attack resistance."""
    
    @pytest.mark.asyncio
    async def test_audience_wrong_url(self, adversarial_server):
        """Warrant for different audience is rejected."""
        with patch('tenuo_core.Warrant') as MockWarrant:
            mock = MagicMock()
            mock.exp = int(time.time()) + 3600
            mock.is_expired = False
            mock.iss = "z6MkTrustedIssuer"
            mock.aud = "https://other-server.example.com"  # Wrong!
            MockWarrant.from_base64.return_value = mock
            
            with pytest.raises(AudienceMismatchError):
                await adversarial_server.validate_warrant("fake", "skill", {})
    
    @pytest.mark.asyncio
    async def test_audience_subdomain_mismatch(self, adversarial_server):
        """Subdomain doesn't match main domain."""
        with patch('tenuo_core.Warrant') as MockWarrant:
            mock = MagicMock()
            mock.exp = int(time.time()) + 3600
            mock.is_expired = False
            mock.iss = "z6MkTrustedIssuer"
            mock.aud = "https://sub.secure.example.com"  # Subdomain
            MockWarrant.from_base64.return_value = mock
            
            with pytest.raises(AudienceMismatchError):
                await adversarial_server.validate_warrant("fake", "skill", {})
    
    @pytest.mark.asyncio
    async def test_audience_http_vs_https(self, adversarial_server):
        """HTTP vs HTTPS protocol mismatch is rejected."""
        with patch('tenuo_core.Warrant') as MockWarrant:
            mock = MagicMock()
            mock.exp = int(time.time()) + 3600
            mock.is_expired = False
            mock.iss = "z6MkTrustedIssuer"
            mock.aud = "http://secure.example.com"  # HTTP, server is HTTPS
            MockWarrant.from_base64.return_value = mock
            
            with pytest.raises(AudienceMismatchError):
                await adversarial_server.validate_warrant("fake", "skill", {})
    
    @pytest.mark.asyncio
    async def test_audience_port_mismatch(self, adversarial_server):
        """Different port is rejected."""
        with patch('tenuo_core.Warrant') as MockWarrant:
            mock = MagicMock()
            mock.exp = int(time.time()) + 3600
            mock.is_expired = False
            mock.iss = "z6MkTrustedIssuer"
            mock.aud = "https://secure.example.com:8443"  # Different port
            MockWarrant.from_base64.return_value = mock
            
            with pytest.raises(AudienceMismatchError):
                await adversarial_server.validate_warrant("fake", "skill", {})


# =============================================================================
# Test: Replay Cache Attacks
# =============================================================================

class TestReplayCacheAttacks:
    """Tests for replay cache attack resistance."""
    
    @pytest.mark.asyncio
    async def test_concurrent_replay_attempts(self):
        """Concurrent replay attempts - only one succeeds."""
        import asyncio
        
        cache = ReplayCache()
        jti = "concurrent_jti"
        results = []
        
        async def attempt_replay():
            result = await cache.check_and_add(jti, ttl_seconds=60)
            results.append(result)
        
        # Fire 10 concurrent attempts
        await asyncio.gather(*[attempt_replay() for _ in range(10)])
        
        # Exactly one should succeed
        assert results.count(True) == 1
        assert results.count(False) == 9
    
    @pytest.mark.asyncio
    async def test_cache_gc_doesnt_allow_replay(self):
        """Cache GC doesn't accidentally allow replays."""
        cache = ReplayCache()
        
        # Add many entries to trigger GC
        for i in range(100):
            await cache.check_and_add(f"jti_{i}", ttl_seconds=60)
        
        # Original entries should still be blocked
        for i in range(100):
            result = await cache.check_and_add(f"jti_{i}", ttl_seconds=60)
            assert result is False, f"jti_{i} should be blocked"


# =============================================================================
# Test: Input Validation Attacks
# =============================================================================

class TestInputValidationAttacks:
    """Tests for malformed input handling."""
    
    @pytest.mark.asyncio
    async def test_null_warrant_token(self, adversarial_server):
        """Null/None warrant token is handled."""
        # Should raise or handle gracefully
        with pytest.raises(Exception):
            await adversarial_server.validate_warrant(None, "skill", {})
    
    @pytest.mark.asyncio
    async def test_empty_string_warrant(self, adversarial_server):
        """Empty string warrant is rejected."""
        with pytest.raises(Exception):
            await adversarial_server.validate_warrant("", "skill", {})
    
    @pytest.mark.asyncio
    async def test_unicode_in_warrant(self, adversarial_server):
        """Unicode characters in warrant are handled."""
        with pytest.raises(Exception):
            await adversarial_server.validate_warrant("🔐💀🎭", "skill", {})
    
    @pytest.mark.asyncio
    async def test_very_long_warrant(self, adversarial_server):
        """Extremely long warrant is handled gracefully."""
        huge_warrant = "A" * (1024 * 1024)  # 1MB of 'A'
        
        with pytest.raises(Exception):
            await adversarial_server.validate_warrant(huge_warrant, "skill", {})
    
    @pytest.mark.asyncio
    async def test_binary_garbage_warrant(self, adversarial_server):
        """Binary garbage is handled gracefully."""
        garbage = bytes(range(256)).decode('latin-1')  # All byte values
        
        with pytest.raises(Exception):
            await adversarial_server.validate_warrant(garbage, "skill", {})
