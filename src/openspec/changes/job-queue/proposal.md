# Proposal: Cola de trabajos de escaneo concurrente (HU-004)

## Intent

Atrox runs all scans synchronously: the HTTP response blocks until Nmap/Nuclei finishes (up to 300s). Users cannot submit multiple targets, track progress, or run concurrent scans. HU-004 requires an internal job queue with concurrency control, CPU-bound task delegation, metrics, and support for at least 10 simultaneous scans.

## Scope

### In Scope
- `JobQueue` singleton service with `asyncio.Queue` + worker coroutines + `asyncio.Semaphore`
- `ProcessPoolExecutor` for CPU-bound XML/JSONL parsing (satisfies multiprocessing requirement)
- Job model with lifecycle states: `pending -> running -> done | failed`
- Jobs REST API: submit, poll, list, metrics
- In-memory job store (dict[UUID, Job])
- Queue metrics endpoint (depth, active, completed, failed, avg duration)
- Configuration settings for concurrency, queue size, parse workers
- Unit tests with mock runners (strict TDD)
- Basic load test documentation

### Out of Scope
- Persistent job storage (SQLite/Redis) -- future HU
- Job cancellation or pause
- WebSocket/SSE real-time updates
- Distributed queue / multi-instance scaling
- Deprecation of existing direct-scan endpoints
- Frontend integration
- Job result TTL / eviction policy (deferred to follow-up)

## Capabilities

### New Capabilities
- `job-queue`: In-process async job queue with concurrency control, job lifecycle management, ProcessPoolExecutor parsing delegation, and internal metrics
- `jobs-api`: REST endpoints for job submission, polling, listing, and metrics retrieval

### Modified Capabilities
- None (existing discovery/vulnscan endpoints remain unchanged)

## Approach

**Hybrid in-process queue (Approach C from exploration)** -- asyncio primitives for I/O-bound scan orchestration, ProcessPoolExecutor for CPU-bound parsing.

1. **JobQueue service** -- singleton created in `lifespan`, holds `asyncio.Queue`, job state `dict[UUID, Job]`, `Semaphore(max_concurrent)`, `ProcessPoolExecutor(max_workers=parse_workers)`
2. **Worker coroutines** -- N persistent tasks consuming from the queue; acquire semaphore, run scanner wrapper (I/O-bound async subprocess), offload `_parse_xml`/`_parse_jsonl` to process pool via `loop.run_in_executor()`
3. **Parse function extraction** -- move `NmapWrapper._parse_xml` and `NucleiWrapper._parse_jsonl` to module-level functions (required for pickling across process boundary)
4. **Jobs router** -- new `atrox/api/jobs.py` with FastAPI DI to inject `JobQueue` from `app.state`
5. **Config** -- 3 new settings: `ATROX_MAX_CONCURRENT_SCANS=10`, `ATROX_QUEUE_MAX_SIZE=100`, `ATROX_PARSE_WORKERS=2`

**Why not Redis/Celery**: Zero external deps, fits existing async arch, "internal metrics" implies in-process, deployment stays zero-config.

**Why ProcessPoolExecutor**: HU-004 explicitly requires CPU-bound delegation to multiprocessing. Even though parsing is fast for typical outputs, this satisfies the requirement and scales for large scan results.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `atrox/queue/__init__.py` | New | Module init |
| `atrox/queue/service.py` | New | JobQueue service: queue, workers, semaphore, executor |
| `atrox/queue/models.py` | New | Job, JobStatus, JobType, QueueMetrics models |
| `atrox/api/jobs.py` | New | Jobs REST router (submit, poll, list, metrics) |
| `atrox/main.py` | Modified | Lifespan init/shutdown for JobQueue + ProcessPoolExecutor |
| `atrox/config.py` | Modified | 3 new settings with ATROX_ prefix |
| `atrox/scanner/nmap_wrapper.py` | Modified | Extract `_parse_xml` to module-level function |
| `atrox/scanner/nuclei_wrapper.py` | Modified | Extract `_parse_jsonl` to module-level function |
| `tests/test_job_queue.py` | New | Unit tests for queue service |
| `tests/test_jobs_api.py` | New | API integration tests for jobs endpoints |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| State loss on server restart | High (by design) | Acceptable for MVP; document as known limitation; SQLite persistence is a future HU |
| ProcessPoolExecutor overhead for small outputs | Medium | Add size threshold: only offload parsing to pool if output > N bytes; otherwise parse in-process |
| Semaphore starvation (10 slow scans block queue) | Low | Queue max size (100) rejects new jobs with 503; scan timeout (300s) bounds wait time |
| Job memory accumulation | Medium | Implement max completed jobs limit with FIFO eviction in the job store |
| Pickling failures across process boundary | Low | Module-level parse functions use only stdlib types; test serialization explicitly |

## Rollback Plan

All changes are additive. Existing `/api/discovery/scan` and `/api/vulnscan/scan` endpoints remain untouched. To rollback:
1. Remove `atrox/queue/` module and `atrox/api/jobs.py`
2. Revert `main.py` lifespan to empty `yield`
3. Revert `config.py` to remove 3 settings
4. Revert parse function extraction in wrappers (move back to instance methods)
5. Remove new test files

No database migrations. No schema changes. No external dependencies.

## Dependencies

- Python stdlib only: `asyncio`, `concurrent.futures`, `uuid`, `datetime`
- Existing scanner wrappers (NmapWrapper, NucleiWrapper) -- used as-is, only parse methods refactored
- No new pip dependencies

## Success Criteria

- [ ] Jobs API accepts scan requests and returns job UUID immediately (< 100ms response)
- [ ] Job states transition correctly: pending -> running -> done | failed
- [ ] At least 10 simultaneous scans execute concurrently in test environment
- [ ] CPU-bound parsing (XML/JSONL) is delegated to ProcessPoolExecutor
- [ ] GET /api/jobs/metrics returns queue_depth, active_jobs, completed_count, failed_count, avg_duration_seconds
- [ ] All unit tests pass with mock runners (no Nmap/Nuclei required)
- [ ] Basic load test script documented demonstrating 10 concurrent jobs
- [ ] Existing direct-scan endpoints continue to work unchanged
