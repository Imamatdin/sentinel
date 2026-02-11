"""Temporal client for Sentinel workflow orchestration."""

from temporalio.client import Client
from sentinel.core import get_settings, get_logger, OrchestrationError

logger = get_logger(__name__)

_client: Client | None = None


async def get_temporal_client() -> Client:
    """Get or create the Temporal client singleton."""
    global _client
    if _client is None:
        settings = get_settings()
        try:
            _client = await Client.connect(
                settings.temporal_host,
                namespace=settings.temporal_namespace,
            )
            logger.info(
                "Connected to Temporal",
                host=settings.temporal_host,
                namespace=settings.temporal_namespace,
            )
        except Exception as e:
            raise OrchestrationError(f"Failed to connect to Temporal: {e}")
    return _client


async def close_temporal_client() -> None:
    """Close Temporal client."""
    global _client
    if _client:
        _client = None
        logger.info("Temporal client reference cleared")
