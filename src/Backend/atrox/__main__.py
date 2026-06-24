import uvicorn

from atrox.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "atrox.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
