import logging
import sys

FORMAT_LOG: str = (
    "%(asctime)s %(levelname)-5s ::: %(thread)d %(filename)-18s"
    " %(funcName)-18s:%(lineno)-5s :::  %(message)s"
)
FORMAT_DATE: str = "%Y-%m-%d %H:%M:%S"
FORMATTER: logging.Formatter = logging.Formatter(FORMAT_LOG, FORMAT_DATE)


def console_handler() -> logging.Handler:
    console: logging.Handler = logging.StreamHandler(sys.stdout)
    console.setFormatter(FORMATTER)
    return console


def get_logger(name: str) -> logging.Logger:
    logger: logging.Logger = logging.getLogger(name)
    if not logger.hasHandlers():
        logger.addHandler(console_handler())
    return logger
