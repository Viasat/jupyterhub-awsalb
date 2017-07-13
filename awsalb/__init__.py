"""
A Jupyterhub Proxy plugin to use AWS Application Load Balancer to proxy to spawned notebook servers.
"""

from __future__ import print_function

import ipaddress

import hvac
import boto3

from urllib.parse import quote, urlparse

from ec2-metadata import ec2_metadata
from tornado.ioloop import PeriodicCallback
from tornado.locks import Lock
from traitlets import (
    Any, Bool, Instance, Integer, Unicode,
    default,
)
from jupyterhub.proxy import Proxy
# from jupyterhub.traitlets import Command


class AwsAlb(Proxy):
    """Proxy implementation using an AWS Application Load Balancer.

    This implementation optionally will authenticate to AWS using STS tokens
    retrieved from a Hashicorp Vault instance. Otherwise it uses boto3 and all
    the standard auth mechs apply. To use vault set::
        c.AwsAlb.use_vault = True
        c.AwsAlb.vault_token = <token>
        c.AwsAlb.vault_url = <url>
        c.AwsAlb.vault_path = <aws/sts/role>

    Using Vault allows us to get around the lack of support in botocore for
    refreshing STS tokens (which definitely would be better). See
    https://github.com/boto/botocore/issues/761 for more details.

    The implementation uses tags on the proxy to store data associated with
    each route. By default this tag is called jupyterhub
    """

    should_start = False

    # TODO: Remove need for Vault but still support STS tokens.
    use_vault = Bool(False, help="Use hashicorp vault to get AWS STS tokens.", config=True)
    vault_url = Unicode(help="The URL to access Hashicorp Vault.", config=True)
    vault_token = Unicode(help="The Hashicorp Vault auth token.", config=True)
    vault_path = Unicode(help="The path to request STS tokens from Vault.", config=True)

    alb_name = Unicode(help="The name of the Application Load Balancer.", config=True)
    alb_target_protocol = Unicode(
        help="Do the spawned instances listen on HTTP or HTTPS. Defaults to HTTPS", config=True)
    alb_vpcid = Unicode(help="The VPC identifier the spawned instances get spawned in.", config=True)
    alb_hub_tag = Unicode(help="The tag to use to store data for this hub.", config=True)

    simple_db_domain = Unicode(help="SimpleDB domain to store metadata in.", config=True)
    s3_bucket = Unicode(help="S3 bucket to store metadata about routes in.", config=True)
    s3_prefix = Unicode(help="Prefix to store objects in S3 bucket at.", config=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.meta_data_lock = {}
        self.priority_lock = Lock()

        if self.use_vault:
            self.vault = hvac.Client(url=self.vault_url,
                                     token=self.vault_token)
            try:
                token = self.vault.lookup_token()
            except hvac.exceptions.Forbidden:
                self.log.error('Failed to login to Vault. INVALID TOKEN.')
                raise
            self.renew_vault_token()

            # renew 20 mins before token expires
            period = token['data']['creation_ttl'] - 1200 * 1000
            pc = PeriodicCallback(self._renew_vault, period)
            pc.start()

            sts = self.update_aws_session_vault()
            period = sts['lease_duration'] - 60 * 10 * 1000
            pc = PeriodicCallback(self.update_aws_session_vault, period)
            pc.start()
        else:
            self._aws = boto3.session.Session()

    def _renew_vault(self):
        self.vault.renew_token()

    def update_aws_session_vault(self):
        token = self.vault.read(self.vault_path)
        self._aws = boto3.session.Session(
            aws_access_key_id=token['data']['access_key'],
            aws_secret_access_key=token['data']['secret_key'],
            aws_session_token=token['data']['security_token'])
        return token

    @property
    def alb_arn(self):
        if hasattr(self, '_alb_arn') and self._alb_arn != '':
            return self._alb_arn

        client = self._aws.client('elbv2')
        lbs = client.describe_load_balancers()
        for lb in lbs['LoadBalancers']:
            if lb['LoadBalancerName'] == self.alb_name:
                self._alb_arn = lb['LoadBalancerArn']
                return self._alb_arn
        raise RuntimeError("Could not find an Application Load Balancer named %s.", self.alb_name)

    @property
    def listener_arn(self):
        if hasattr(self, '_listener_arn') and self._listener_arn != '':
            return self._listener_arn

        client = self._aws.client('elbv2')
        listeners = client.describe_listeners(LoadBalancerArn=self.alb_arn)
        try:
            return listeners[0]['ListenerArn']
        except IndexError:
            raise RuntimeError("Could not find a Listener associated with the ALB %s.", self.alb_name)

    def get_instance_id(self, target):
        url = urlparse(target)
        try:
            ipaddress.Ipv4Address(url.hostname)
        except ipaddress.AddressValueError:
            raise RuntimeError('Target was not specified as an IPv4 address.')

        # assume ipaddress is private_ipv4
        client = self._aws.client('ec2')
        resp = client.describe_instances(
            Filters=[{'Name': 'private-ip-address', 'Values': [ url.hostname ]}],
        )

        try:
            return resp['Reservations'][0]['Instances'][0]['InstanceId']
        except (IndexError, KeyError):
            raise RuntimeError('Failed to find the instance with private-ip-address=%s: %s' % (url.hostname, str(resp)))

    @gen.coroutine
    def next_priority(self):
        if hasattr(self, '_next_priority'):
            return self._next_priority

        client = self._aws.client('elbv2')
        rules = client.describe_rules(ListenerArn=self.listerner_arn)
        self._next_priority = len(rules['Rules']) + 1
        return self._next_priority

    @gen.coroutine
    def get_all_routes(self):
        s3 = self._aws.client('s3')
        resp = s3.list_objects_v2(Bucket=self.s3_bucket, Prefix=self.s3_prefix)

        all_routes = {}
        for route in resp['Contents']:
            routespec = route['Key'].replace(self.s3_prefix, '')
            all_routes[routespec] = self.get_route(routespec)
        return all_routes

    @gen.coroutine
    def get_route(self, routespec):
        s3 = self._aws.client('s3')
        resp = s3.get_object(
            Bucket=self.s3_bucket, os.path.join(self.s3_prefix, routespec))
        try:
            return resp['Body'].read()
        except KeyError:
            self.log.warning('No route was found for %s.' % routespec)
            return {}

    @gen.coroutine
    def add_route(self, routespec, target, data):
        path = self.validate_routespec(routespec)

        # We use a uuid for the target group name because
        # target group names have a limit of 32 alphanumeric charaters.
        # routespec is close enough to a url
        target_group_name = uuid.uuid5(uuid.NAMESPACE_URL, routespec)

        # need to extract the target port from target
        target_url = urlparse(target)

        elbv2 = self._aws.client('elbv2')

        # Create Target Group
        target_group = elbv2.create_target_group(
            Name=target_group_name,
            Protocol=target_url.scheme,
            Port=target_url.port,
            VpcId=self.vpcid,
            HealthCheckPath="/api/status")

        try:
            tg_arn = target_group['TargetGroups'][0]['TargetGroupArn']
        except IndexError:
            raise RuntimeError('Failed to create the target group: %s, routespec: %s.' % target_group_name, routespec)
        except KeyError:
            raise RuntimeError('Failed to retreive TargetGroupArn from response. %s.' % str(target_group))

        # Add target to target group
        instance_id = self.get_instance_id(target)
        target = elbv2.register_target(
            TargetGroupArn=tg_arn,
            Targets=[{'Id': instance_id}]
        )

        # Add rule to listener
        if self.host_routing:
            host = routespec.split('/')[0]
            condition = {'Field': 'host-header', 'Values': [host]}
        else:
            condition = {'Field': 'path-pattern', 'Values': [routespec]}
        rule = elbv2.create_rule(
            ListenerArn=self.listener_arn,
            Conditions=[condition],
            Priority=self.next_priority,
            Actions=[{'Type': 'forward', 'TargetGroupArn': tg_arn}]
        )

        # Save metadata to S3
        data.update({'jupyterhub-route': True})
        resp = self._aws.client('s3').put_object(
            Body=json.dumps(data).encode(),
            Bucket=self.s3_bucket,
            Key=os.path.join(self.s3_prefix, routespec)
        )

    @gen.coroutine
    def delete_route(self, routespec):
        elbv2 = self._aws.client('elbv2')

        tg_name = uuid.uuid5(uuid.NAMESPACE_URL, routespec)
        tg_desc = elbv2.describe_target_groups(LoadBalancerArn=self.alb_arn,
                                               Names=[tg_name])
        tg_arn = tg_desc['TargetGroups'][0]['TargetGroupArn']

        rules = elbv2.describe_rules(ListenerArn=self.listener_arn)
        rule_arn = ''
        for rule in rules['Rules']:
            for action in rule['Actions']:
                if action.get('TargetGroupArn') == tg_arn:
                    rule_arn = rule['RuleArn']

        elbv2.delete_rule(RuleArn=rule_arn)
        elbv2.delete_target_group(TargetGroupArn=tg_arn)

        self._aws.client('s3').delete_object(Bucket=self.s3_bucket,
                                             Key=os.path.join(self.s3_prefix, routespec))
