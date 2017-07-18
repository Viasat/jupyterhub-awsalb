# Copyright (c) ViaSat, Inc.
# Distributed under the terms of the BSD-3-Clause

from setuptools import setup

setup(
    name='jupyterhub-awsalb',
    version='0.1.0',
    description='AWS Application Load Balancer Proxy for Jupyterhub',
    author='Tony Kinsley',
    author_email='anthony.kinsley@viasat.com',
    license='Apache 2.0',
    tests_require=[
        'unittest2',
    ],
    test_suite='unittest2.collector',
    packages=['awsalb'],
    install_requires=[
        'jupyterhub',
        'boto3',
    ]
)
