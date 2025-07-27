from pathlib import Path

import uvicorn as uvicorn
from fastapi import FastAPI
from ms_core import setup_app

from app.settings import db_url

application = FastAPI(
    title="QSRequests",
)

setup_app(application, db_url, Path("app") / "routers", ["app.models"])


if __name__ == "__main__":
    uvicorn.run("main:application", port=8000, reload=True)
