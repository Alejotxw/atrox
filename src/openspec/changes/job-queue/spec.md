# Job Queue Specification

## Purpose

Defines the concurrent scan job queue and its REST API for Atrox. Covers job lifecycle, concurrency control, CPU-bound delegation, metrics, and configuration.

## Requirements

### Requirement: Job Model

The system MUST represent each scan job with: `id` (UUID), `type` (discovery | vulnscan), `status` (pending | running | done | failed), `params` (scan request payload), `result` (scan output, nullable), `error` (string, nullable), `created_at`, `started_at` (nullable), `finished_at` (nullable).

#### Scenario: Valid job fields at creation

- GIVEN a job is created with type "discovery" and valid params
- WHEN the job is instantiated
- THEN id is a UUID4, status is "pending", created_at is set, started_at/finished_at/result/error are None

### Requirement: Job Lifecycle Transitions

The system MUST enforce valid state transitions: pending->running, running->done, running->failed. The system MUST NOT allow any other transitions.

#### Scenario: Pending to running

- GIVEN a job with status "pending"
- WHEN a worker picks it up
- THEN status becomes "running" AND started_at is set

#### Scenario: Running to done

- GIVEN a job with status "running"
- WHEN the scan completes successfully
- THEN status becomes "done", result contains scan output, finished_at is set

#### Scenario: Running to failed

- GIVEN a job with status "running"
- WHEN the scan raises an exception
- THEN status becomes "failed", error contains the message, finished_at is set

#### Scenario: Invalid transition rejected

- GIVEN a job with status "done"
- WHEN an attempt is made to transition to "running"
- THEN the system MUST raise an error

### Requirement: Queue Concurrency Control

The system MUST limit concurrent running jobs via a semaphore (default: 10, configurable). The system MUST reject new submissions with HTTP 503 when the queue reaches max size (default: 50, configurable).

#### Scenario: Concurrent execution within limit

- GIVEN max_concurrent_scans is 3 and 3 jobs are running
- WHEN a 4th job is submitted
- THEN it stays "pending" until a running job finishes

#### Scenario: Queue full rejection

- GIVEN queue_max_size is 5 and 5 jobs are already queued
- WHEN a new job is submitted
- THEN the API returns HTTP 503 with message indicating queue is full

### Requirement: CPU-Bound Parsing Delegation

The system MUST offload XML/JSONL parsing to a ProcessPoolExecutor (configurable workers, default: 2). Parse functions MUST be module-level (picklable).

#### Scenario: Parsing runs in process pool

- GIVEN a completed Nmap subprocess with XML output
- WHEN the worker processes the result
- THEN parsing is executed via ProcessPoolExecutor (or ThreadPoolExecutor substitute in tests)

### Requirement: Job Submission API

The system MUST expose POST `/api/jobs` accepting `{"type": "discovery"|"vulnscan", ...scan_params}`. The system MUST return HTTP 202 with `{"job_id": "<uuid>"}`.

#### Scenario: Submit discovery job

- GIVEN the queue has capacity
- WHEN POST `/api/jobs` with type "discovery", target "192.168.1.1", port_range "80,443"
- THEN response is 202 with a job_id UUID

#### Scenario: Submit vulnscan job

- GIVEN the queue has capacity
- WHEN POST `/api/jobs` with type "vulnscan", target "example.com"
- THEN response is 202 with a job_id UUID

#### Scenario: Submit with invalid target

- GIVEN any queue state
- WHEN POST `/api/jobs` with target "not_valid!!!"
- THEN response is HTTP 422

### Requirement: Job Polling API

The system MUST expose GET `/api/jobs/{job_id}` returning the full job object with current status and result/error.

#### Scenario: Poll pending job

- GIVEN a submitted job still pending
- WHEN GET `/api/jobs/{job_id}`
- THEN response includes status "pending", result is null

#### Scenario: Poll completed job

- GIVEN a job that finished successfully
- WHEN GET `/api/jobs/{job_id}`
- THEN response includes status "done" and result with scan data

#### Scenario: Poll failed job

- GIVEN a job that failed
- WHEN GET `/api/jobs/{job_id}`
- THEN response includes status "failed" and error message

#### Scenario: Poll nonexistent job

- GIVEN no job with the given ID exists
- WHEN GET `/api/jobs/{nonexistent_id}`
- THEN response is HTTP 404

### Requirement: Job Listing API

The system MUST expose GET `/api/jobs` returning all jobs as an array.

#### Scenario: List jobs

- GIVEN 3 jobs exist in various states
- WHEN GET `/api/jobs`
- THEN response is an array of 3 job objects with their current statuses

### Requirement: Queue Metrics API

The system MUST expose GET `/api/jobs/metrics` returning: queue_depth (pending count), active_jobs (running count), completed_count, failed_count, avg_duration_seconds.

#### Scenario: Metrics with mixed state jobs

- GIVEN 2 pending, 3 running, 5 done (avg 10s), 1 failed job
- WHEN GET `/api/jobs/metrics`
- THEN response contains queue_depth=2, active_jobs=3, completed_count=5, failed_count=1, avg_duration_seconds=10.0

### Requirement: Configuration Settings

The system MUST add to Settings: `max_concurrent_scans` (int, default 10), `queue_max_size` (int, default 50), `parse_workers` (int, default 2). All MUST use the `ATROX_` env prefix.

#### Scenario: Custom configuration via env

- GIVEN ATROX_MAX_CONCURRENT_SCANS=5 is set
- WHEN the application starts
- THEN the semaphore permits 5 concurrent scans

## Testing Requirements

- Each requirement above MUST have at least one unit test using mock runners (no real Nmap/Nuclei)
- ProcessPoolExecutor tests MAY substitute ThreadPoolExecutor for unit testing
- Integration tests requiring real scanners MUST use `@pytest.mark.integration`
- Load test demonstrating 10 concurrent mock jobs MUST be documented
