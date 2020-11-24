import sys
import logging

FORMAT = '%(asctime)s | %(levelname)-7s %(id)-20s %(name)s.%(modulename)-14s %(funcname)-26s: %(message)s'

MAGIC_LEVEL_MAP = {
    "i" : logging.INFO,
    "d" : logging.DEBUG,
    "e" : logging.ERROR,
    "w" : logging.WARNING,
}
class Logger(logging.Logger):
    """Overwrites log formatting"""
    def __init__(self, name, level):
        super(Logger, self).__init__(name)
        formatter = logging.Formatter(FORMAT, '%Y-%m-%d %H:%M:%S')
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)

        self = logging.getLogger(name)
        self.addHandler(stream_handler)
        self.setLevel(level)