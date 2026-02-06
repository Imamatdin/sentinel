"""Engagement state manager.

Manages the lifecycle of a single engagement: creation, execution,
event streaming, and result retrieval. Holds all shared state between
REST endpoints and WebSocket handlers.

This is a singleton within the FastAPI application.
"""

import asyncio
import os
import time
from typing import Any, Optional
from enum import Enum

import aiohttp

from sentinel.config import Settings, get_settings
from sentinel.orchestrator.engine import EngagementOrchestrator, EngagementResult
from sentinel.events.bus import EventBus, Event, EventType
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class EngagementState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class EngagementManager:
    """Manages the current engagement lifecycle.

    Thread-safe via asyncio. Only one engagement can run at a time.
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.event_bus = EventBus(history_size=2000)

        # Engagement state
        self._state = EngagementState.IDLE
        self._phase: Optional[str] = None
        self._target_url: Optional[str] = None
        self._start_time: Optional[float] = None
        self._task: Optional[asyncio.Task] = None
        self._orchestrator: Optional[EngagementOrchestrator] = None
        self._result: Optional[EngagementResult] = None

        # Subscribe to phase transitions to track current phase
        self._phase_queue = self.event_bus.subscribe(
            EventType.PHASE_TRANSITION.value
        )
        self._phase_tracker_task: Optional[asyncio.Task] = None

    @property
    def state(self) -> EngagementState:
        return self._state

    @property
    def phase(self) -> Optional[str]:
        return self._phase

    @property
    def target_url(self) -> Optional[str]:
        return self._target_url

    @property
    def elapsed(self) -> Optional[float]:
        if self._start_time is None:
            return None
        return time.time() - self._start_time

    @property
    def result(self) -> Optional[EngagementResult]:
        return self._result

    async def start_engagement(
        self,
        target_url: str = "http://localhost:3000",
        monitor_poll_interval: float = 3.0,
        monitor_max_cycles: int = 10,
        defender_max_responses: int = 10,
        exploit_max_iterations: int = 15,
        skip_recon: bool = False,
        skip_reports: bool = False,
    ) -> bool:
        """Start a new engagement.

        Returns True if engagement was started, False if one is already running.
        """
        if self._state == EngagementState.RUNNING:
            logger.warning("engagement_already_running")
            return False

        # Reset state
        self.event_bus.clear_history()
        self._state = EngagementState.RUNNING
        self._phase = None
        self._target_url = target_url
        self._start_time = time.time()
        self._result = None

        # Create orchestrator with shared event bus
        self._orchestrator = EngagementOrchestrator(
            target_url=target_url,
            settings=self.settings,
            event_bus=self.event_bus,
            monitor_poll_interval=monitor_poll_interval,
            monitor_max_cycles=monitor_max_cycles,
            defender_max_responses=defender_max_responses,
            exploit_max_iterations=exploit_max_iterations,
            skip_recon=skip_recon,
            skip_reports=skip_reports,
        )

        # Start phase tracker
        self._phase_tracker_task = asyncio.create_task(self._track_phases())

        # Start engagement in background task
        self._task = asyncio.create_task(self._run_engagement())

        logger.info("engagement_started", target=target_url)
        return True

    async def stop_engagement(self) -> bool:
        """Stop the running engagement.

        Returns True if stop was initiated, False if nothing is running.
        """
        if self._state != EngagementState.RUNNING or self._task is None:
            return False

        logger.info("engagement_stop_requested")
        self._task.cancel()

        try:
            await self._task
        except asyncio.CancelledError:
            pass

        self._state = EngagementState.FAILED
        self._phase = None

        if self._phase_tracker_task:
            self._phase_tracker_task.cancel()
            try:
                await self._phase_tracker_task
            except asyncio.CancelledError:
                pass

        return True

    async def check_juice_shop(self, url: str = "http://localhost:3000") -> bool:
        """Check if Juice Shop is reachable."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def _run_engagement(self) -> None:
        """Background task that runs the engagement."""
        try:
            result = await self._orchestrator.run()
            self._result = result
            self._state = (
                EngagementState.COMPLETED if result.success
                else EngagementState.FAILED
            )
            logger.info(
                "engagement_finished",
                success=result.success,
                duration=f"{result.duration:.1f}s",
            )

            # ── Run Security Genome Pipeline ──
            if result.agent_results:
                try:
                    from sentinel.genome.pipeline import GenomePipeline

                    pipeline = GenomePipeline(
                        client=self._orchestrator._create_client(),
                        enable_nvd=bool(os.environ.get("NVD_API_KEY")),
                    )
                    genome_stats = await pipeline.run(
                        agent_results=result.agent_results,
                        session_id=result.target_url,
                    )

                    # Emit genome event
                    from sentinel.events.bus import Event
                    await self.event_bus.publish(Event(
                        type="genome.pipeline_complete",
                        data=genome_stats,
                        source="genome",
                    ))
                    logger.info("genome_pipeline_complete", **genome_stats)
                except Exception as e:
                    logger.error("genome_pipeline_failed", error=str(e))

        except asyncio.CancelledError:
            logger.info("engagement_cancelled")
            self._state = EngagementState.FAILED
            raise
        except Exception as e:
            logger.error("engagement_crashed", error=str(e))
            self._state = EngagementState.FAILED
        finally:
            self._phase = None
            if self._phase_tracker_task:
                self._phase_tracker_task.cancel()

    async def _track_phases(self) -> None:
        """Background task that tracks current phase from events."""
        try:
            while True:
                event = await self._phase_queue.get()
                phase = event.data.get("phase")
                if phase:
                    self._phase = phase
                    logger.debug("phase_tracked", phase=phase)
        except asyncio.CancelledError:
            pass