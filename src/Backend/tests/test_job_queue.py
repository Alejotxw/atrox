"""Tests unitarios para el servicio JobQueue (HU-004)."""

import asyncio
from uuid import UUID

import pytest

from atrox.queue.models import Job, JobStatus, JobType, QueueMetrics
from atrox.queue.service import JobQueue, QueueFullError


# -- Task 2.1: submit creates pending job ------------------------------------


class TestJobQueueSubmit:
    """Scenario: Submit creates a pending job (spec requirement)."""

    def test_submit_returns_job_with_pending_status(self) -> None:
        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        job = asyncio.run(queue.submit(JobType.DISCOVERY, {"target": "192.168.1.1"}))

        assert isinstance(job, Job)
        assert job.status == JobStatus.PENDING
        assert isinstance(job.id, UUID)
        assert job.job_type == JobType.DISCOVERY
        assert job.params == {"target": "192.168.1.1"}

    def test_submit_vulnscan_job(self) -> None:
        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        job = asyncio.run(queue.submit(JobType.VULNSCAN, {"target": "example.com"}))

        assert job.job_type == JobType.VULNSCAN
        assert job.status == JobStatus.PENDING


# -- Task 2.3: submit rejects when queue full --------------------------------


class TestJobQueueFull:
    """Scenario: Queue full rejection (spec requirement)."""

    def test_submit_raises_queue_full_error_when_at_capacity(self) -> None:
        queue = JobQueue(max_concurrent=1, max_queue_size=2)

        async def fill_and_overflow():
            await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.1"})
            await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.2"})
            with pytest.raises(QueueFullError, match="Cola llena"):
                await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.3"})

        asyncio.run(fill_and_overflow())

    def test_submit_allows_up_to_max_queue_size(self) -> None:
        queue = JobQueue(max_concurrent=1, max_queue_size=3)

        async def fill_exactly():
            j1 = await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.1"})
            j2 = await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.2"})
            j3 = await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.3"})
            return j1, j2, j3

        j1, j2, j3 = asyncio.run(fill_exactly())
        assert j1.status == JobStatus.PENDING
        assert j2.status == JobStatus.PENDING
        assert j3.status == JobStatus.PENDING


# -- Task 2.5: worker runs mock scanner, sets status=done -------------------


class TestJobQueueWorker:
    """Scenario: Worker executes scanner and transitions job to done."""

    def test_worker_completes_job_with_result(self) -> None:
        mock_result = {"hosts": [{"address": "192.168.1.1", "ports": []}]}

        async def mock_scanner(job: Job) -> dict:
            return mock_result

        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run_worker_test():
            await queue.start(scanner=mock_scanner)
            job = await queue.submit(JobType.DISCOVERY, {"target": "192.168.1.1"})
            # Esperamos que el worker procese el trabajo
            await asyncio.sleep(0.2)
            processed_job = queue.get_job(job.id)
            await queue.shutdown()
            return processed_job

        result_job = asyncio.run(run_worker_test())

        assert result_job is not None
        assert result_job.status == JobStatus.DONE
        assert result_job.result == mock_result
        assert result_job.started_at is not None
        assert result_job.finished_at is not None

    def test_worker_sets_started_at_before_running(self) -> None:
        started_at_captured = []

        async def capturing_scanner(job: Job) -> dict:
            started_at_captured.append(job.started_at)
            return {"done": True}

        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run():
            await queue.start(scanner=capturing_scanner)
            await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.1"})
            await asyncio.sleep(0.2)
            await queue.shutdown()

        asyncio.run(run())

        assert len(started_at_captured) == 1
        assert started_at_captured[0] is not None


# -- Task 2.7: worker sets status=failed on exception -----------------------


class TestJobQueueWorkerFailure:
    """Scenario: Running to failed (spec requirement)."""

    def test_worker_sets_failed_on_scanner_exception(self) -> None:
        async def failing_scanner(job: Job) -> dict:
            raise RuntimeError("Nmap exploto inesperadamente")

        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run():
            await queue.start(scanner=failing_scanner)
            job = await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.1"})
            await asyncio.sleep(0.2)
            await queue.shutdown()
            return queue.get_job(job.id)

        result_job = asyncio.run(run())

        assert result_job is not None
        assert result_job.status == JobStatus.FAILED
        assert result_job.error == "Nmap exploto inesperadamente"
        assert result_job.finished_at is not None

    def test_worker_sets_failed_preserves_started_at(self) -> None:
        async def failing_scanner(job: Job) -> dict:
            raise ValueError("error de validacion")

        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run():
            await queue.start(scanner=failing_scanner)
            job = await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.2"})
            await asyncio.sleep(0.2)
            await queue.shutdown()
            return queue.get_job(job.id)

        result_job = asyncio.run(run())

        assert result_job is not None
        assert result_job.started_at is not None
        assert result_job.finished_at is not None
        assert result_job.status == JobStatus.FAILED


# -- Task 2.9: metrics property returns correct counts ----------------------


class TestJobQueueMetrics:
    """Scenario: Metrics with mixed state jobs (spec requirement)."""

    def test_metrics_returns_queue_metrics_model(self) -> None:
        queue = JobQueue(max_concurrent=2, max_queue_size=10)
        metrics = queue.metrics
        assert isinstance(metrics, QueueMetrics)

    def test_metrics_empty_queue(self) -> None:
        queue = JobQueue(max_concurrent=2, max_queue_size=10)
        metrics = queue.metrics
        assert metrics.queue_depth == 0
        assert metrics.active_jobs == 0
        assert metrics.completed_count == 0
        assert metrics.failed_count == 0
        assert metrics.avg_duration_seconds == 0.0

    def test_metrics_after_completed_jobs(self) -> None:
        async def mock_scanner(job: Job) -> dict:
            await asyncio.sleep(0.05)
            return {"result": "ok"}

        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run():
            await queue.start(scanner=mock_scanner)
            await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.1"})
            await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.2"})
            await asyncio.sleep(0.5)
            await queue.shutdown()

        asyncio.run(run())

        metrics = queue.metrics
        assert metrics.completed_count == 2
        assert metrics.failed_count == 0
        assert metrics.queue_depth == 0
        assert metrics.active_jobs == 0
        assert metrics.avg_duration_seconds > 0.0

    def test_metrics_with_failed_job(self) -> None:
        async def failing_scanner(job: Job) -> dict:
            raise RuntimeError("boom")

        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run():
            await queue.start(scanner=failing_scanner)
            await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.1"})
            await asyncio.sleep(0.3)
            await queue.shutdown()

        asyncio.run(run())

        metrics = queue.metrics
        assert metrics.failed_count == 1
        assert metrics.completed_count == 0


# -- Task 2.11: start/shutdown lifecycle ------------------------------------


class TestJobQueueLifecycle:
    """Scenario: Lifecycle start/shutdown (spec requirement)."""

    def test_start_creates_workers(self) -> None:
        async def noop_scanner(job: Job) -> dict:
            return {}

        queue = JobQueue(max_concurrent=3, max_queue_size=10)

        async def run():
            await queue.start(scanner=noop_scanner)
            worker_count = len(queue._workers)
            await queue.shutdown()
            return worker_count

        count = asyncio.run(run())
        assert count == 3

    def test_shutdown_cancels_all_workers(self) -> None:
        async def slow_scanner(job: Job) -> dict:
            await asyncio.sleep(10)
            return {}

        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run():
            await queue.start(scanner=slow_scanner)
            assert len(queue._workers) == 2
            await queue.shutdown()
            return len(queue._workers)

        remaining = asyncio.run(run())
        assert remaining == 0

    def test_list_jobs_returns_all_submitted(self) -> None:
        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run():
            await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.1"})
            await queue.submit(JobType.VULNSCAN, {"target": "10.0.0.2"})
            return queue.list_jobs()

        jobs = asyncio.run(run())
        assert len(jobs) == 2
        types = {j.job_type for j in jobs}
        assert types == {JobType.DISCOVERY, JobType.VULNSCAN}
