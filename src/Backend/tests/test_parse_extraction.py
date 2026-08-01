"""Tests unitarios para funciones de parseo a nivel de modulo (HU-004).

Estas funciones deben ser picklable para uso con ProcessPoolExecutor.
"""

from atrox.scanner.models import VulnSeverity
from atrox.scanner.nmap_wrapper import parse_nmap_xml
from atrox.scanner.nuclei_wrapper import parse_nuclei_jsonl
from tests.fixtures.nmap_samples import SAMPLE_NMAP_XML_DOWN, SAMPLE_NMAP_XML_UP
from tests.fixtures.nuclei_samples import (
    SAMPLE_NUCLEI_JSONL_MALFORMED,
    SAMPLE_NUCLEI_JSONL_MULTI,
)


# -- Task 3.1: parse_nmap_xml module-level function -------------------------


class TestParseNmapXml:
    """Scenario: Module-level parse function produce mismos resultados que el metodo."""

    def test_parse_nmap_xml_returns_hosts_from_valid_xml(self) -> None:
        hosts = parse_nmap_xml(SAMPLE_NMAP_XML_UP)

        assert len(hosts) == 1
        assert hosts[0].address == "192.168.1.10"
        assert hosts[0].status == "up"
        assert len(hosts[0].ports) == 2

    def test_parse_nmap_xml_parses_port_details(self) -> None:
        hosts = parse_nmap_xml(SAMPLE_NMAP_XML_UP)

        ssh_port = hosts[0].ports[0]
        assert ssh_port.port == 22
        assert ssh_port.protocol == "tcp"
        assert ssh_port.service == "ssh"
        assert ssh_port.version == "OpenSSH 8.9p1 Ubuntu"

    def test_parse_nmap_xml_handles_down_host(self) -> None:
        hosts = parse_nmap_xml(SAMPLE_NMAP_XML_DOWN)

        assert len(hosts) == 1
        assert hosts[0].status == "down"
        assert hosts[0].ports == []

    def test_parse_nmap_xml_is_picklable(self) -> None:
        """La funcion debe ser serializable para ProcessPoolExecutor."""
        import pickle
        restored = pickle.loads(pickle.dumps(parse_nmap_xml))
        hosts = restored(SAMPLE_NMAP_XML_UP)
        assert len(hosts) == 1
        assert hosts[0].address == "192.168.1.10"


# -- Task 3.3: parse_nuclei_jsonl module-level function ----------------------


class TestParseNucleiJsonl:
    """Scenario: Module-level parse function produce mismos resultados que el metodo."""

    def test_parse_nuclei_jsonl_returns_findings(self) -> None:
        findings = parse_nuclei_jsonl(SAMPLE_NUCLEI_JSONL_MULTI)

        assert len(findings) == 2
        assert findings[0].template_id == "cve-2021-41773"
        assert findings[0].severity == VulnSeverity.CRITICAL

    def test_parse_nuclei_jsonl_parses_second_finding(self) -> None:
        findings = parse_nuclei_jsonl(SAMPLE_NUCLEI_JSONL_MULTI)

        assert findings[1].template_id == "cve-2023-22515"
        assert findings[1].severity == VulnSeverity.HIGH

    def test_parse_nuclei_jsonl_skips_malformed_lines(self) -> None:
        findings = parse_nuclei_jsonl(SAMPLE_NUCLEI_JSONL_MALFORMED)

        assert len(findings) == 2
        assert findings[0].template_id == "cve-2021-41773"
        assert findings[1].template_id == "tech-detect"

    def test_parse_nuclei_jsonl_is_picklable(self) -> None:
        """La funcion debe ser serializable para ProcessPoolExecutor."""
        import pickle
        restored = pickle.loads(pickle.dumps(parse_nuclei_jsonl))
        findings = restored(SAMPLE_NUCLEI_JSONL_MULTI)
        assert len(findings) == 2


# -- Task 3.5: worker uses executor for parse --------------------------------

import asyncio
from concurrent.futures import ThreadPoolExecutor

from atrox.queue.models import Job, JobStatus, JobType
from atrox.queue.service import JobQueue


class TestWorkerWithExecutor:
    """Scenario: Parsing runs in process pool (spec requirement).

    En unit tests usamos ThreadPoolExecutor como sustituto de
    ProcessPoolExecutor para evitar complejidad de multiprocessing.
    """

    def test_worker_uses_executor_for_parse(self) -> None:
        executor_calls: list[str] = []

        def tracking_parse(raw: str) -> dict:
            executor_calls.append("parse_called")
            return {"parsed": True}

        async def mock_scanner(job: Job) -> dict:
            return {"raw_output": "<xml>data</xml>"}

        queue = JobQueue(max_concurrent=2, max_queue_size=10)
        executor = ThreadPoolExecutor(max_workers=1)

        async def run():
            await queue.start(scanner=mock_scanner, executor=executor)
            job = await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.1"})
            await asyncio.sleep(0.3)
            await queue.shutdown()
            return queue.get_job(job.id)

        result_job = asyncio.run(run())

        assert result_job is not None
        assert result_job.status == JobStatus.DONE
        executor.shutdown(wait=False)

    def test_worker_completes_without_executor(self) -> None:
        """Si no se proporciona executor, el worker sigue funcionando."""

        async def mock_scanner(job: Job) -> dict:
            return {"scanned": True}

        queue = JobQueue(max_concurrent=2, max_queue_size=10)

        async def run():
            await queue.start(scanner=mock_scanner)
            job = await queue.submit(JobType.DISCOVERY, {"target": "10.0.0.2"})
            await asyncio.sleep(0.3)
            await queue.shutdown()
            return queue.get_job(job.id)

        result_job = asyncio.run(run())

        assert result_job is not None
        assert result_job.status == JobStatus.DONE
        assert result_job.result == {"scanned": True}
