"""
A Jupyterhub Proxy plugin to use AWS Application Load Balancer to proxy to spawned notebook servers.
"""

from __future__ import print_function

import boto3

from jupyterhub.proxy import Proxy

class AwsAlb(Proxy):

    def __init__(self, *args, **kwargs):
        self.should_start = False

        super().__init__(*args, **kwargs)
        self.client = boto3.client('elbv2')

    def get_all_routes(self):
        raise NotImplementedError()

    def add_route(self, routespec, target, data):
        raise NotImplementedError()

    def delete_route(self):
        raise NotImplementedError()
