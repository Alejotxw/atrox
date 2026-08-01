"""Tests unitarios para modelos de la cola de trabajos (HU-004)."""

from datetime import datetime, timezone
from uuid import UUID

import pytest

from atrox.queue.models import Job, JobStatus, JobType, QueueMetrics


# -- JobStatus enum ----------------------------------------------------------


class TestJobStatusEnum:
    def test_status_has_all_expected_values(self) -> None:
        expected = {"pending", "running", "done", "failed"}
        actual = {s.value for s in JobStatus}
        assert actual == expected

    def test_status_is_string_enum(self) -> None:
        assert isinstance(JobStatus.PENDING, str)
        assert JobStatus.PENDING == "pending"


# -- JobType enum -------------------------------------------------------------


class TestJobTypeEnum:
    def test_type_has_expected_values(self) -> None:
        expected = {"discovery", "vulnscan"}
        actual = {t.value for t in JobType}
        assert actual == expected

    def test_type_is_string_enum(self) -> None:
        assert isinstance(JobType.DISCOVERY, str)
        assert JobType.DISCOVERY == "discovery"


# -- Job model ----------------------------------------------------------------


class TestJobCreationDefaults:
    """Scenario: Valid job fields at creation (spec requirement)."""

    def test_job_id_is_uuid(self) -> None:
        job = Job(job_type=JobType.DISCOVERY, params={"target": "192.168.1.1"})
        assert isinstance(job.id, UUID)

    def test_job_status_defaults_to_pending(self) -> None:
        job = Job(job_type=JobType.DISCOVERY, params={"target": "192.168.1.1"})
        assert job.status == JobStatus.PENDING

    def test_job_created_at_is_set(self) -> None:
        job = Job(job_type=JobType.DISCOVERY, params={"target": "192.168.1.1"})
        assert isinstance(job.created_at, datetime)

    def test_job_nullable_fields_are_none(self) -> None:
        job = Job(job_type=JobType.DISCOVERY, params={"target": "192.168.1.1"})
        assert job.started_at is None
        assert job.finished_at is None
        assert job.result is None
        assert job.error is None

    def test_job_vulnscan_type(self) -> None:
        job = Job(job_type=JobType.VULNSCAN, params={"target": "example.com"})
        assert job.job_type == JobType.VULNSCAN
        assert job.status == JobStatus.PENDING


# -- QueueMetrics model -------------------------------------------------------


class TestQueueMetricsModel:
    def test_metrics_accepts_all_fields(self) -> None:
        metrics = QueueMetrics(
            queue_depth=2,
            active_jobs=3,
            completed_count=5,
            failed_count=1,
            avg_duration_seconds=10.0,
        )
        assert metrics.queue_depth == 2
        assert metrics.active_jobs == 3
        assert metrics.completed_count == 5
        assert metrics.failed_count == 1
        assert metrics.avg_duration_seconds == 10.0

    def test_metrics_with_zero_values(self) -> None:
        metrics = QueueMetrics(
            queue_depth=0,
            active_jobs=0,
            completed_count=0,
            failed_count=0,
            avg_duration_seconds=0.0,
        )
        assert metrics.queue_depth == 0
        assert metrics.avg_duration_seconds == 0.0


# -- Job.transition_to() — State transition validation -------------------------


class TestJobStateTransition:
    """Scenario: Invalid transition rejected (spec requirement).

    The system MUST enforce valid state transitions:
      pending->running, running->done, running->failed.
    The system MUST NOT allow any other transitions.
    """

    def test_transition_done_to_running_raises_value_error(self) -> None:
        """GIVEN a job with status 'done', WHEN transitioning to 'running',
        THEN ValueError is raised."""
        job = Job(job_type=JobType.DISCOVERY, params={"target": "10.0.0.1"})
        job.status = JobStatus.DONE  # force to done for test setup

        with pytest.raises(ValueError, match="Transicion invalida"):
            job.transition_to(JobStatus.RUNNING)

    def test_transition_pending_to_running_succeeds(self) -> None:
        """GIVEN a job with status 'pending', WHEN transitioning to 'running',
        THEN status becomes 'running'."""
        job = Job(job_type=JobType.DISCOVERY, params={"target": "10.0.0.1"})

        job.transition_to(JobStatus.RUNNING)

        assert job.status == JobStatus.RUNNING

    def test_transition_running_to_done_succeeds(self) -> None:
        """GIVEN a job with status 'running', WHEN transitioning to 'done',
        THEN status becomes 'done'."""
        job = Job(job_type=JobType.DISCOVERY, params={"target": "10.0.0.1"})
        job.status = JobStatus.RUNNING

        job.transition_to(JobStatus.DONE)

        assert job.status == JobStatus.DONE

    def test_transition_running_to_failed_succeeds(self) -> None:
        """GIVEN a job with status 'running', WHEN transitioning to 'failed',
        THEN status becomes 'failed'."""
        job = Job(job_type=JobType.DISCOVERY, params={"target": "10.0.0.1"})
        job.status = JobStatus.RUNNING

        job.transition_to(JobStatus.FAILED)

        assert job.status == JobStatus.FAILED

    def test_transition_pending_to_done_raises_value_error(self) -> None:
        """Invalid: pending cannot go directly to done."""
        job = Job(job_type=JobType.DISCOVERY, params={"target": "10.0.0.1"})

        with pytest.raises(ValueError, match="Transicion invalida"):
            job.transition_to(JobStatus.DONE)

    def test_transition_pending_to_failed_raises_value_error(self) -> None:
        """Invalid: pending cannot go directly to failed."""
        job = Job(job_type=JobType.DISCOVERY, params={"target": "10.0.0.1"})

        with pytest.raises(ValueError, match="Transicion invalida"):
            job.transition_to(JobStatus.FAILED)

    def test_transition_failed_to_running_raises_value_error(self) -> None:
        """Invalid: failed cannot go back to running."""
        job = Job(job_type=JobType.DISCOVERY, params={"target": "10.0.0.1"})
        job.status = JobStatus.FAILED

        with pytest.raises(ValueError, match="Transicion invalida"):
            job.transition_to(JobStatus.RUNNING)

    def test_transition_done_to_failed_raises_value_error(self) -> None:
        """Invalid: done cannot go to failed."""
        job = Job(job_type=JobType.DISCOVERY, params={"target": "10.0.0.1"})
        job.status = JobStatus.DONE

        with pytest.raises(ValueError, match="Transicion invalida"):
            job.transition_to(JobStatus.FAILED)
