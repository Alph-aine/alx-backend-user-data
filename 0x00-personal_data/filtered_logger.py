#!/usr/bin/env python3
'''Masks sensitive data'''
import re


def filter_datum(fields, redaction, message, separator):
    '''Use regex to mask specified fields'''
    for i in fields:
        message = re.sub(f'{i}=.*?{separator}',
                         f'{i}={redaction}{separator}', message)
    return message
