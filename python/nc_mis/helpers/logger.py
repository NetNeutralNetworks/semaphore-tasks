import logging
import pathlib
import sys
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("nc-mis")


def logger():
    pathlib.Path("./logs").mkdir(parents=True, exist_ok=True)

    logger.setLevel(level=logging.DEBUG)
    formatter = logging.Formatter(
        fmt="%(asctime)s(File:%(name)s, Line:%(lineno)d, %(funcName)s) - %(levelname)s - %(process)s: %(message)s",
        datefmt="%m/%d/%Y %H:%M:%S %p",
    )
    rothandler = RotatingFileHandler(
        "./logs/nc-mis.log", maxBytes=100000, backupCount=5
    )
    rothandler.setFormatter(formatter)
    logger.addHandler(rothandler)
    logger.addHandler(logging.StreamHandler(sys.stdout))

    return logger
