# Tasks: Cola de trabajos de escaneo concurrente (HU-004)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 650-800 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (Foundation + Queue service) -> PR 2 (Parse extraction + API + Wiring) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Queue models, config, JobQueue service with tests | PR 1 | Base: main or feature/HU-004; standalone, no API yet |
| 2 | Parse extraction, API router, lifespan wiring, e2e + load tests | PR 2 | Depends on PR 1; completes the feature |

## Phase 1: Foundation -- Models and Config (Strict TDD)

- [ ] 1.1 RED: `tests/test_queue_models.py` -- test JobStatus/JobType enums, Job creation defaults (pending, timestamps null), invalid state transition raises error
- [ ] 1.2 GREEN: Create `atrox/queue/__init__.py` and `atrox/queue/models.py` with JobStatus, JobType, Job, JobSubmitRequest, JobSubmitResponse, QueueMetrics
- [ ] 1.3 RED: `tests/test_queue_models.py` -- test config fields: max_concurrent_scans=10, queue_max_size=50, parse_workers=2
- [ ] 1.4 GREEN: Add `max_concurrent_scans`, `queue_max_size`, `parse_workers` to `atrox/config.py` Settings class

## Phase 2: Queue Service (Strict TDD)

- [ ] 2.1 RED: `tests/test_job_queue.py` -- test submit creates pending job, returns Job with UUID
- [ ] 2.2 GREEN: Create `atrox/queue/service.py` with JobQueue.submit() storing jobs in dict, putting id on asyncio.Queue
- [ ] 2.3 RED: test submit rejects when queue full (503-scenario: qsize >= max_size)
- [ ] 2.4 GREEN: Implement queue-full guard in submit()
- [ ] 2.5 RED: test worker picks job, runs mock scanner, sets status=done with result
- [ ] 2.6 GREEN: Implement worker loop with semaphore, async scanner dispatch, status transitions
- [ ] 2.7 RED: test worker sets status=failed and error on scanner exception
- [ ] 2.8 GREEN: Add exception handling in worker, set failed + error + finished_at
- [ ] 2.9 RED: test metrics property returns correct counts (queue_depth, active, completed, failed, avg_duration)
- [ ] 2.10 GREEN: Implement metrics computed property on JobQueue
- [ ] 2.11 RED: test start() spawns workers, shutdown() cancels them
- [ ] 2.12 GREEN: Implement start/shutdown lifecycle; export JobQueue from `atrox/queue/__init__.py`
- [ ] 2.13 REFACTOR: Clean up service; verify all Phase 2 tests pass together

## Phase 3: Parse Extraction (Strict TDD)

- [ ] 3.1 RED: `tests/test_nmap_wrapper.py` -- test module-level `parse_nmap_xml()` with existing XML fixtures
- [ ] 3.2 GREEN: Extract `NmapWrapper._parse_xml` to module-level `parse_nmap_xml()` in `atrox/scanner/nmap_wrapper.py`; delegate from method
- [ ] 3.3 RED: `tests/test_nuclei_wrapper.py` -- test module-level `parse_nuclei_jsonl()` with existing JSONL fixtures
- [ ] 3.4 GREEN: Extract `NucleiWrapper._parse_jsonl` to module-level `parse_nuclei_jsonl()` in `atrox/scanner/nuclei_wrapper.py`; delegate from method
- [ ] 3.5 RED: test worker uses ProcessPoolExecutor (substitute ThreadPoolExecutor in tests) to call parse function
- [ ] 3.6 GREEN: Add executor integration in JobQueue worker -- `loop.run_in_executor(pool, parse_fn, raw_output)`

## Phase 4: API Layer (Strict TDD)

- [ ] 4.1 RED: `tests/test_jobs_api.py` -- test POST /api/jobs returns 202 with job_id UUID
- [ ] 4.2 GREEN: Create `atrox/api/jobs.py` with router, `get_job_queue` DI (from request.app.state), POST /api/jobs endpoint
- [ ] 4.3 RED: test POST /api/jobs with invalid target returns 422
- [ ] 4.4 GREEN: Wire validation through JobSubmitRequest model
- [ ] 4.5 RED: test GET /api/jobs/{job_id} returns job object; 404 for nonexistent
- [ ] 4.6 GREEN: Implement GET /api/jobs/{job_id}
- [ ] 4.7 RED: test GET /api/jobs returns list of all jobs
- [ ] 4.8 GREEN: Implement GET /api/jobs
- [ ] 4.9 RED: test GET /api/jobs/metrics returns QueueMetrics shape
- [ ] 4.10 GREEN: Implement GET /api/jobs/metrics
- [ ] 4.11 RED: test POST /api/jobs returns 503 when queue is full
- [ ] 4.12 GREEN: Handle QueueFullError in endpoint, return 503

## Phase 5: Integration -- Lifespan and Wiring

- [ ] 5.1 Modify `atrox/main.py` lifespan: create JobQueue with settings, store in app.state, call start() on enter, shutdown() on exit
- [ ] 5.2 Register jobs router in `create_app()`
- [ ] 5.3 RED: `tests/test_jobs_api.py` -- e2e test: submit job via POST, poll GET until done, verify result
- [ ] 5.4 GREEN: Ensure full pipeline works with mock scanner via dependency_overrides

## Phase 6: Load Test -- Concurrency Validation

- [ ] 6.1 RED: `tests/test_job_queue.py` -- test 10 concurrent mock jobs all reach done; semaphore caps active count
- [ ] 6.2 GREEN: Verify existing implementation handles concurrency; fix if needed
- [ ] 6.3 REFACTOR: Final cleanup across all new files; verify `pytest tests/ -v -m "not integration"` passes clean
