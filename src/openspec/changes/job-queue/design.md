# Design: Cola de trabajos de escaneo concurrente (HU-004)

## Technical Approach

Layered in-process queue built on asyncio primitives (Queue, Semaphore, Tasks) with ProcessPoolExecutor for CPU-bound parsing. Follows the existing singleton-via-lifespan + FastAPI DI pattern already established in the codebase. All new code lives in a new `atrox/queue/` package; the API layer reuses the same router + dependency pattern as `discovery.py` and `vulnscan.py`.

## Architecture Decisions

| Decision | Choice | Alternatives Rejected | Rationale |
|----------|--------|----------------------|-----------|
| Queue primitive | `asyncio.Queue` + `asyncio.Semaphore` | `queue.Queue` (thread-safe, blocks event loop); Redis/Celery (external dep) | Matches existing async subprocess pattern; zero deps; semaphore decouples queue depth from concurrency |
| Worker lifecycle | N persistent `asyncio.Task` coroutines spawned in lifespan | On-demand task-per-job; ThreadPoolExecutor workers | Persistent workers amortize startup, give clean shutdown via `task.cancel()`; on-demand risks unbounded concurrency |
| Parse offloading | `ProcessPoolExecutor` via `loop.run_in_executor()` | In-process only; `multiprocessing.Pool` | HU-004 requires multiprocessing; `run_in_executor` is idiomatic asyncio; `multiprocessing.Pool` lacks executor protocol |
| Parse extraction | Module-level `parse_nmap_xml()` / `parse_nuclei_jsonl()` | Keep as methods, wrap with `functools.partial` | Module-level functions are inherently picklable; `partial` of bound methods fails across process boundary |
| Job store | `dict[UUID, Job]` with FIFO eviction | SQLite; `collections.OrderedDict` | In-memory is MVP scope; plain dict + deque for eviction order is simpler than OrderedDict; SQLite deferred to future HU |
| DI pattern | `get_job_queue(request: Request) -> JobQueue` from `request.app.state` | `Depends(get_settings)` factory per-request; global singleton | Matches how FastAPI recommends lifespan-scoped resources; consistent with how the codebase would evolve for DB connections |
| Metrics | Computed property on `JobQueue`, not a separate service | Dedicated MetricsService; Prometheus client | Simple dict-counting is enough for MVP; no external deps; property keeps the interface minimal |

## Data Flow

### Job Submission

```
POST /api/jobs/submit
        |
        v
  jobs.py router ──Depends──> get_job_queue(request)
        |
        v
  JobQueue.submit(scan_type, params)
        |
        ├─ validate params (reuse existing Pydantic models)
        ├─ create Job(id=uuid4, status=pending, ...)
        ├─ store in _jobs[job_id]
        └─ await _queue.put(job_id)
        |
        v
  Return {job_id, status: "pending"} immediately
```

### Worker Execution

```
Worker coroutine (N running)
        |
  job_id = await _queue.get()
        |
  async with _semaphore:
        |
        ├─ _jobs[job_id].status = running
        ├─ _jobs[job_id].started_at = now()
        |
        ├─ scanner = NmapWrapper(...) or NucleiWrapper(...)
        ├─ result = await scanner.scan(...)        # I/O-bound (subprocess)
        |
        ├─ IF parse_pool AND output > threshold:
        │     parsed = await loop.run_in_executor(pool, parse_fn, raw)
        │  ELSE:
        │     parsed = parse_fn(raw)               # small output, skip pool
        |
        ├─ _jobs[job_id].result = parsed
        ├─ _jobs[job_id].status = done
        └─ _jobs[job_id].finished_at = now()
        |
  _queue.task_done()
```

Note: The worker catches exceptions around the scan+parse block and sets `status=failed` with the error message. The semaphore release happens via `async with` regardless of success/failure.

### Metrics Collection

```
GET /api/jobs/metrics
        |
  JobQueue.metrics  (computed property)
        |
        ├─ queue_depth = _queue.qsize()
        ├─ active_jobs = count(status == running)
        ├─ completed = count(status == done)
        ├─ failed = count(status == failed)
        └─ avg_duration = mean(finished - started) for done jobs
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `atrox/queue/__init__.py` | Create | Exports `JobQueue` |
| `atrox/queue/models.py` | Create | `JobStatus`, `JobType`, `Job`, `JobSubmitRequest`, `JobSubmitResponse`, `QueueMetrics` Pydantic models |
| `atrox/queue/service.py` | Create | `JobQueue` class: queue, workers, semaphore, executor, submit, metrics |
| `atrox/api/jobs.py` | Create | Router: submit, get, list, metrics endpoints; `get_job_queue` DI |
| `atrox/main.py` | Modify | Lifespan: create `JobQueue`, store in `app.state.job_queue`, start workers, shutdown on exit |
| `atrox/config.py` | Modify | Add `max_concurrent_scans`, `queue_max_size`, `parse_workers` settings |
| `atrox/scanner/nmap_wrapper.py` | Modify | Extract `_parse_xml` to module-level `parse_nmap_xml()`; instance method delegates to it |
| `atrox/scanner/nuclei_wrapper.py` | Modify | Extract `_parse_jsonl` to module-level `parse_nuclei_jsonl()`; instance method delegates to it |
| `tests/test_job_queue.py` | Create | Unit tests for `JobQueue` service |
| `tests/test_jobs_api.py` | Create | API tests for jobs router |

## Interfaces / Contracts

```python
# atrox/queue/models.py

class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"

class JobType(str, Enum):
    DISCOVERY = "discovery"
    VULNSCAN = "vulnscan"

class Job(BaseModel):
    id: UUID
    job_type: JobType
    status: JobStatus = JobStatus.PENDING
    params: dict              # scan parameters (target, port_range, etc.)
    result: dict | None = None
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

class QueueMetrics(BaseModel):
    queue_depth: int
    active_jobs: int
    completed_count: int
    failed_count: int
    avg_duration_seconds: float
```

```python
# atrox/queue/service.py — public interface

class JobQueue:
    def __init__(self, settings: Settings, nmap: NmapWrapper, nuclei: NucleiWrapper): ...
    async def start(self) -> None:          # spawn workers + pool
    async def shutdown(self) -> None:       # cancel workers, shutdown pool
    async def submit(self, job_type: JobType, params: dict) -> Job: ...
    def get_job(self, job_id: UUID) -> Job | None: ...
    def list_jobs(self, status: JobStatus | None = None) -> list[Job]: ...
    @property
    def metrics(self) -> QueueMetrics: ...
```

```python
# atrox/api/jobs.py — endpoints

POST /api/jobs/submit      -> JobSubmitResponse (job_id + status)
GET  /api/jobs/{job_id}    -> Job
GET  /api/jobs             -> list[Job] (optional ?status= filter)
GET  /api/jobs/metrics     -> QueueMetrics
```

## Testing Strategy

| Layer | What to Test | Approach |
|-------|-------------|----------|
| Unit | Job model state transitions | Direct model construction, verify field defaults and serialization |
| Unit | `JobQueue.submit` creates job, puts in queue | Inject mock scanner wrappers; assert `_jobs` dict populated, `_queue.qsize()` incremented |
| Unit | Worker processes job to completion | Mock scanner returns canned result; await brief worker cycle; verify status=done |
| Unit | Worker handles scanner failure | Mock scanner raises; verify status=failed, error populated |
| Unit | `parse_nmap_xml` / `parse_nuclei_jsonl` module-level | Reuse existing test fixtures (`nmap_samples.py`, `nuclei_samples.py`); verify identical output to current tests |
| Unit | Metrics computation | Submit N jobs, complete some, fail some; verify metric counts |
| Unit | Queue full rejection | Set `maxsize=1`, submit 2; verify second returns 503 |
| Concurrency | 10+ parallel jobs | Submit 10 jobs with mock scanners (short sleep); verify all reach done; verify semaphore limits active count |
| Lifecycle | Startup/shutdown | Create `JobQueue`, call `start()`, submit a job, call `shutdown()`; verify workers cancelled, pool shut down |
| API | Submit endpoint | `TestClient` with `dependency_overrides`; POST submit, verify 202 + job_id |
| API | Poll endpoint | Submit then GET by job_id; verify job JSON |
| API | Metrics endpoint | Submit + complete jobs; GET metrics; verify counts |

## Migration / Rollout

No migration required. All changes are additive:
- New `atrox/queue/` package, new `atrox/api/jobs.py` router
- Existing `/api/discovery/scan` and `/api/vulnscan/scan` remain untouched
- Parse function extraction preserves backward compatibility (instance methods delegate to module-level functions)
- New config settings have defaults; no `.env` changes required

## Open Questions

- [ ] Should `parse_workers` default to `min(2, os.cpu_count() or 1)` to avoid over-allocating on single-core containers?
- [ ] Should the parse-offload size threshold be configurable or hardcoded (proposal suggests N bytes)?
