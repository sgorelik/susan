"""Susan entrypoint: load env, then expose the FastAPI app from app.routes."""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

from app.routes import app  # noqa: E402

__all__ = ["app"]
