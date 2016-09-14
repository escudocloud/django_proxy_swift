#!/usr/bin/env python
from config import *
import logging 
from logging.config import dictConfig

logging_config = {
    'version' : 1,
    'formatters' : {
        'f': {'format': '%(asctime)s [%(levelname)s] %(message)s',
              'datefmt': '%Y/%m/%d %H:%M:%S'}
        },
    'handlers' : {
        'h': {'class': 'logging.FileHandler',
              'formatter': 'f',
              'filename': '%s/log' % PATH,
              'level': logging.DEBUG}
        },
    'root' : {
        'handlers': ['h'],
        'level': logging.DEBUG,
        },
}


dictConfig(logging_config)
logger = logging.getLogger()
