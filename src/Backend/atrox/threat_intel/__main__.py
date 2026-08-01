"""Ejecución manual de la sincronización NVD (HU-005 DoD).

Uso:
    python -m atrox.threat_intel [--force-full]

Sin argumentos sincroniza el delta desde la última sincronización exitosa;
`--force-full` ignora el estado previo y descarga todo el catálogo.
El código de salida es 0 si la sincronización fue exitosa y 1 si falló.
"""

import argparse
import asyncio

from atrox.threat_intel.models import CveSyncStatusEnum
from atrox.threat_intel.service import build_nvd_sync_service


async def _run(force_full: bool) -> int:
    service = build_nvd_sync_service()
    status = await service.sync_once(force_full=force_full)
    print(status.model_dump_json(indent=2))
    return 0 if status.status == CveSyncStatusEnum.OK else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Sincroniza el catálogo de CVEs con NVD")
    parser.add_argument(
        "--force-full",
        action="store_true",
        help="Ignora la última sincronización y descarga el catálogo completo",
    )
    args = parser.parse_args()
    return asyncio.run(_run(force_full=args.force_full))


if __name__ == "__main__":
    raise SystemExit(main())
