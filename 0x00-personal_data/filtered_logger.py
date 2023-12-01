#!/usr/bin/env python3
'''Masks sensitive data'''
import re
import logging
import mysql.connector
from os import environ
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
    handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))

    logger.addHandler(handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    '''Returns a mysql database connector'''
    username = environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    password = environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    host = environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = environ.get("PERSONAL_DATA_DB_NAME")

    conn = mysql.connector.connection.MySQLConnection(user=username,
                                                      password=password,
                                                      host=host,
                                                      database=db_name)

    return conn


def main():
    """Connects to a secure db, retrieves all rows in the users tables and
    displays filtered data"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    fields = [i[0] for i in cursor.description]

    logger = get_logger()

    for row in cursor:
        filtered_row = [filter_datum([field], '***', str(value), ';') for field, value in zip(fields, row)]
        str_row = ''.join(f'{f}={r}; ' for r, f in zip(filtered_row, fields))
        logger.info(str_row.strip())

    cursor.close()
    db.close()


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


if __name__ == '__main__':
    main()
