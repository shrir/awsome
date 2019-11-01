#!/usr/bin/env python
# coding: utf-8

from setuptools import setup, find_packages


setup(
    name='awsome',
    version='1.0',
    packages=find_packages('.'),
    author='Shrirang Bhate',
    description='simple script to quickly spin up EC2 instances',
    install_requires=['gevent', 'boto3', 'paramiko'],
    include_package_data=True,
    python_requires='>=3.*',
    entry_points={
        'console_scripts': ['awsome=awsome']
    }
)
