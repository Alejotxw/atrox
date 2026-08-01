import ipaddress
import re

FQDN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def validate_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("El objetivo no puede estar vacío")

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if FQDN_PATTERN.match(value):
        return value

    raise ValueError(f"Objetivo inválido: debe ser una IP o FQDN válido ({value!r})")


def validate_port_range(port_range: str) -> str:
    value = port_range.strip()
    if not value:
        raise ValueError("El rango de puertos no puede estar vacío")

    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start, end = int(start_str), int(end_str)
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError(f"Rango de puertos inválido: {part}")
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"Puerto inválido: {port}")

    return value
