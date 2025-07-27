from pathlib import Path

import uvicorn as uvicorn
from fastapi import FastAPI
from ms_core import setup_app

from app.dependencies import configure_auth
from app.settings import db_url, usersms_url, logger

application = FastAPI(
    title="QSRequests",
)

configure_auth(usersms_url, logger=logger)
tortoise_conf = setup_app(application, db_url, Path("app") / "routers", ["app.models"])


if __name__ == "__main__":
    uvicorn.run("main:application", port=8000, reload=True)
