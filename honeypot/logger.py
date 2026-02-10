"""Logging helpers for the honeypot."""

import json
import logging
import os
from datetime import datetime, timezone

LOG_PATH_DEFAULT = "/app/logs/honeypot.log"

def _utc_ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def create_logger(log_path: str = LOG_PATH_DEFAULT) -> logging.Logger:
    # raise NotImplementedError("Implement logging setup for your honeypot")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    logger = logging.getLogger("Honeypot")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Avoid duplicate handlers if reloaded
    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(message)s")
    fh = logging.FileHandler(log_path)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


def log_event(logger: logging.Logger, event: dict):
    event.setdefault("ts", _utc_ts())
    logger.info(json.dumps(event, separators=(",", ":"), ensure_ascii=False))

