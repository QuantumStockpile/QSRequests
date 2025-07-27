import logging
import os

logger = logging.getLogger("uvicorn.error")

db_url = os.environ["DB_URL"]
usersms_url = os.environ["USERSMS_URL"]
