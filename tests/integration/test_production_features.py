"""Integration tests for production-ready features"""
import asyncio
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from marty_credentials.infrastructure.observability.rate_limiter import (
    RateLimiter,
    RateLimitExceededError,
)
from marty_credentials.infrastructure.events import (
    CredentialIssuedEvent,
    CredentialVerifiedEvent,
    CredentialVerificationFailedEvent,
)
from marty_credentials.infrastructure.events.publisher import (
    LoggingEventPublisher,
    KafkaEventPublisher,
    create_event_publisher,
)
from marty_credentials.infrastructure.auth.token_validator import (
    CredentialVerificationError,
)


class TestRateLimiter:
    """Test rate limiting functionality"""
    
    @pytest.mark.asyncio
    async def test_rate_limit_allows_within_limit(self):
        """Test that requests within limit are allowed"""
        redis_mock = AsyncMock()
        redis_mock.incr.return_value = 5
        redis_mock.ttl.return_value = 55
        
        limiter = RateLimiter(redis_mock, default_limit=10, window_seconds=60)
        
        allowed, remaining = await limiter.check_rate_limit(
            key="test:key",
            resource_type="test",
            resource_id="123"
        )
        
        assert allowed is True
        assert remaining == 5
        redis_mock.incr.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_rate_limit_blocks_over_limit(self):
        """Test that requests over limit are blocked"""
        redis_mock = AsyncMock()
        redis_mock.incr.return_value = 101
        redis_mock.ttl.return_value = 30
        
        limiter = RateLimiter(redis_mock, default_limit=100, window_seconds=60)
        
        with pytest.raises(RateLimitExceededError) as exc_info:
            await limiter.check_rate_limit(
                key="test:key",
                resource_type="test",
                resource_id="123"
            )
        
        assert exc_info.value.retry_after_seconds == 30
    
    @pytest.mark.asyncio
    async def test_rate_limit_sets_expiry_on_first_request(self):
        """Test that expiry is set on first request"""
        redis_mock = AsyncMock()
        redis_mock.incr.return_value = 1
        
        limiter = RateLimiter(redis_mock, default_limit=100, window_seconds=60)
        
        await limiter.check_rate_limit(
            key="test:key",
            resource_type="test",
            resource_id="123"
        )
        
        redis_mock.expire.assert_called_once_with("rate_limit:test:key", 60)
    
    @pytest.mark.asyncio
    async def test_rate_limit_reset(self):
        """Test rate limit reset"""
        redis_mock = AsyncMock()
        
        limiter = RateLimiter(redis_mock)
        await limiter.reset_rate_limit("test:key")
        
        redis_mock.delete.assert_called_once_with("rate_limit:test:key")
    
    @pytest.mark.asyncio
    async def test_rate_limit_fails_open_on_redis_error(self):
        """Test graceful degradation when Redis fails"""
        redis_mock = AsyncMock()
        redis_mock.incr.side_effect = Exception("Redis connection failed")
        
        limiter = RateLimiter(redis_mock, default_limit=100)
        
        # Should not raise exception, fail open
        allowed, remaining = await limiter.check_rate_limit(
            key="test:key",
            resource_type="test",
            resource_id="123"
        )
        
        assert allowed is True
        assert remaining == 100


class TestEventPublishing:
    """Test event publishing functionality"""
    
    @pytest.mark.asyncio
    async def test_logging_publisher_logs_event(self):
        """Test that LoggingEventPublisher logs events"""
        publisher = LoggingEventPublisher()
        
        event = CredentialIssuedEvent(
            event_id=str(uuid4()),
            event_timestamp=datetime.utcnow(),
            event_type="credential.issued",
            credential_id="cred-123",
            credential_type="UniversityDegree",
            format="w3c_vc",
            issuer_id="did:example:issuer",
            holder_id="did:example:holder",
        )
        
        with patch('marty_credentials.infrastructure.events.publisher.logger') as mock_logger:
            await publisher.publish(event)
            
            mock_logger.info.assert_called_once()
            call_args = mock_logger.info.call_args
            assert "Event published" in call_args[0][0]
            assert call_args[1]["extra"]["event_type"] == "credential.issued"
    
    @pytest.mark.asyncio
    async def test_kafka_publisher_sends_to_topic(self):
        """Test that KafkaEventPublisher sends to correct topic"""
        with patch('marty_credentials.infrastructure.events.publisher.get_config') as mock_config:
            mock_config.return_value.enable_event_publishing = True
            mock_config.return_value.kafka_bootstrap_servers = "localhost:9092"
            mock_config.return_value.event_topic_prefix = "test.events"
            
            publisher = KafkaEventPublisher(topic_prefix="test.events")
            
            # Mock the producer
            mock_producer = AsyncMock()
            publisher._producer = mock_producer
            
            event = CredentialVerifiedEvent(
                event_id=str(uuid4()),
                event_timestamp=datetime.utcnow(),
                event_type="credential.verified",
                credential_id="cred-123",
                credential_type="UniversityDegree",
                verifier_id="did:example:verifier",
                verification_result=True,
                verification_method="signature",
            )
            
            await publisher.publish(event)
            
            # Check that producer.send_and_wait was called with correct topic
            mock_producer.send_and_wait.assert_called_once()
            call_args = mock_producer.send_and_wait.call_args
            assert call_args[0][0] == "test.events.credential.verified"
            assert call_args[1]["key"] == "cred-123"
    
    def test_create_event_publisher_returns_logging_in_dev_mode(self):
        """Test that dev mode returns LoggingEventPublisher"""
        with patch('marty_credentials.infrastructure.events.publisher.get_config') as mock_config:
            mock_config.return_value.enable_event_publishing = True
            mock_config.return_value.dev_mode = True
            
            publisher = create_event_publisher()
            
            assert isinstance(publisher, LoggingEventPublisher)
    
    def test_create_event_publisher_returns_kafka_in_production(self):
        """Test that production mode returns KafkaEventPublisher"""
        with patch('marty_credentials.infrastructure.events.publisher.get_config') as mock_config:
            mock_config.return_value.enable_event_publishing = True
            mock_config.return_value.dev_mode = False
            mock_config.return_value.kafka_bootstrap_servers = "localhost:9092"
            
            publisher = create_event_publisher()
            
            assert isinstance(publisher, KafkaEventPublisher)


class TestDomainEvents:
    """Test domain event data classes"""
    
    def test_credential_issued_event_creation(self):
        """Test CredentialIssuedEvent creation"""
        event = CredentialIssuedEvent(
            event_id=str(uuid4()),
            event_timestamp=datetime.utcnow(),
            event_type="credential.issued",
            credential_id="cred-123",
            credential_type="UniversityDegree",
            format="w3c_vc",
            issuer_id="did:example:issuer",
            holder_id="did:example:holder",
        )
        
        assert event.event_type == "credential.issued"
        assert event.credential_id == "cred-123"
        assert event.format == "w3c_vc"
    
    def test_credential_verification_failed_event_creation(self):
        """Test CredentialVerificationFailedEvent creation"""
        event = CredentialVerificationFailedEvent(
            event_id=str(uuid4()),
            event_timestamp=datetime.utcnow(),
            event_type="credential.verification_failed",
            credential_type="UniversityDegree",
            issuer="did:example:issuer",
            error="Invalid signature",
            error_details={"reason": "Key not found"},
        )
        
        assert event.event_type == "credential.verification_failed"
        assert event.error == "Invalid signature"
        assert event.error_details["reason"] == "Key not found"


class TestCredentialVerificationError:
    """Test custom exception classes"""
    
    def test_credential_verification_error_creation(self):
        """Test CredentialVerificationError creation"""
        error = CredentialVerificationError(
            "Verification failed",
            details={"issuer": "did:example:issuer", "reason": "Invalid signature"}
        )
        
        assert str(error) == "Verification failed"
        assert error.details["issuer"] == "did:example:issuer"
        assert error.details["reason"] == "Invalid signature"
    
    def test_credential_verification_error_without_details(self):
        """Test CredentialVerificationError without details"""
        error = CredentialVerificationError("Verification failed")
        
        assert str(error) == "Verification failed"
        assert error.details == {}


class TestMetricsIntegration:
    """Test metrics integration"""
    
    def test_metrics_are_importable(self):
        """Test that metrics can be imported"""
        from marty_credentials.infrastructure.observability.metrics import (
            credentials_issued_total,
            credentials_verified_total,
            credential_verification_failures_total,
            credential_issuance_duration_seconds,
            credential_verification_duration_seconds,
            active_credentials,
            rate_limit_remaining,
        )
        
        # Verify metrics exist
        assert credentials_issued_total is not None
        assert credentials_verified_total is not None
        assert credential_verification_failures_total is not None
        assert credential_issuance_duration_seconds is not None
        assert credential_verification_duration_seconds is not None
        assert active_credentials is not None
        assert rate_limit_remaining is not None
    
    def test_metrics_can_be_incremented(self):
        """Test that metrics can be incremented"""
        from marty_credentials.infrastructure.observability.metrics import (
            credentials_issued_total,
        )
        
        # Get initial value
        initial = credentials_issued_total.labels(
            credential_type="test",
            format="test",
            issuer_id="test"
        )._value.get()
        
        # Increment
        credentials_issued_total.labels(
            credential_type="test",
            format="test",
            issuer_id="test"
        ).inc()
        
        # Verify increment
        final = credentials_issued_total.labels(
            credential_type="test",
            format="test",
            issuer_id="test"
        )._value.get()
        
        assert final == initial + 1


@pytest.fixture
def mock_redis():
    """Fixture for mocked Redis client"""
    redis_mock = AsyncMock()
    redis_mock.incr.return_value = 1
    redis_mock.get.return_value = None
    return redis_mock


@pytest.fixture
def mock_db_session():
    """Fixture for mocked database session"""
    return MagicMock()


# Integration test example
@pytest.mark.asyncio
async def test_complete_credential_lifecycle_with_observability(mock_redis, mock_db_session):
    """Integration test for complete credential lifecycle with all features"""
    
    # Setup
    rate_limiter = RateLimiter(mock_redis, default_limit=100)
    event_publisher = LoggingEventPublisher()
    
    issuer_did = "did:example:issuer"
    holder_did = "did:example:holder"
    
    # 1. Check rate limit
    mock_redis.incr.return_value = 50
    allowed, remaining = await rate_limiter.check_rate_limit(
        key=f"issuer:{issuer_did}",
        resource_type="issuer",
        resource_id=issuer_did
    )
    assert allowed is True
    assert remaining == 50
    
    # 2. Simulate credential issuance (metrics would be tracked)
    credential_id = str(uuid4())
    
    # 3. Publish issuance event
    with patch('marty_credentials.infrastructure.events.publisher.logger') as mock_logger:
        await event_publisher.publish(
            CredentialIssuedEvent(
                event_id=str(uuid4()),
                event_timestamp=datetime.utcnow(),
                event_type="credential.issued",
                credential_id=credential_id,
                credential_type="UniversityDegree",
                format="w3c_vc",
                issuer_id=issuer_did,
                holder_id=holder_did,
            )
        )
        mock_logger.info.assert_called_once()
    
    # 4. Simulate verification
    with patch('marty_credentials.infrastructure.events.publisher.logger') as mock_logger:
        await event_publisher.publish(
            CredentialVerifiedEvent(
                event_id=str(uuid4()),
                event_timestamp=datetime.utcnow(),
                event_type="credential.verified",
                credential_id=credential_id,
                credential_type="UniversityDegree",
                verifier_id="did:example:verifier",
                verification_result=True,
                verification_method="signature",
            )
        )
        mock_logger.info.assert_called_once()
    
    print("✅ Complete lifecycle test passed!")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
