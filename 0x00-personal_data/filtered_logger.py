#!/usr/bin/env python3
'''Masks sensitive data'''
import re
import logging
from typing import List


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    '''Use regex to mask specified fields'''
    for i in fields:
        message = re.sub(f'{i}=.*?{separator}',
                         f'{i}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    '''Returns a logger object to the INFO level'''
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(List(PII_FIELDS)))

    logger.addHandler(handler)

    return logger


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        '''Filters data in the incoming log records uisng filter_datum'''
        record.msg = filter_datum(self.fields, self.REDACTION,
                                  record.getMessage(), self.SEPARATOR)

        return super(RedactingFormatter, self).format(record)
