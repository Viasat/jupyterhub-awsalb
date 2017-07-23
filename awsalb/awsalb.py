"""
A Jupyterhub Proxy plugin to use AWS Application Load Balancer to proxy to spawned notebook servers.
"""

# Copyright (c) ViaSat, Inc.
# Distributed under the terms of the BSD-3-Clause License

from __future__ import print_function

import json
import uuid
import ipaddress

import hvac
import boto3

from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

from tornado import gen
from tornado.concurrent import run_on_executor
from tornado.ioloop import PeriodicCallback, IOLoop
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

from botocore.exceptions import ClientError

from traitlets import Bool, Integer, Unicode, List

from jupyterhub.proxy import Proxy
# from jupyterhub.traitlets import Command


MAX_PRIORITY = 50000


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

    # TODO: Remove need for Vault but still support STS tokens.
    use_vault = Bool(False, help="Use hashicorp vault to get AWS STS tokens.", config=True)
    vault_url = Unicode(help="The URL to access Hashicorp Vault.", config=True)
    vault_token = Unicode(help="The Hashicorp Vault auth token.", config=True)
    vault_path = Unicode(help="The path to request STS tokens from Vault.", config=True)

    alb_name = Unicode(help="The name of the Application Load Balancer.", config=True)
    alb_target_protocol = Unicode(
        "HTTP", help="Do the spawned instances listen on HTTP or HTTPS.", config=True)
    alb_region = Unicode(help="The region the hub is located in.", config=True)
    alb_cert_arn = Unicode(help="The certificat ARN if starting an HTTPS listener.", config=True)
    alb_listener_protocol = Unicode("HTTP", help="The protocol the listener listens on. HTTP|HTTPS", config=True)
    alb_listener_port = Integer(80, help="The port the listener listens on.", config=True)
    alb_scheme = Unicode("internal", help="The scheme for the ALB. Valid options = internal|internet-facing", config=True)
    alb_tags = List(help="Set of tags to apply to ALB on creation.", config=True)
    alb_security_groups = List(help="The security groups to assign to the created ALB.", config=True)
    alb_subnets = List(Help="The subnets to assign to the created ALB.", config=True)
    alb_ipaddress_type = Unicode("ipv4", help="The IpAddressType for the created ALB.", config=True)

    tg_healthcheck_interval = Integer(30, help="Interval for ALB to run its health check.", config=True)
    tg_healthcheck_timeout = Integer(5, help="Timeout for ALB to fail its health check.", config=True)
    tg_healthy_threshold = Integer(
        5, help="Number of health checks that need to pass before target is considered health.", config=True)
    tg_unhealthy_threshold = Integer(
        2, help="Number of health checks that need to fail before target is considered unhealth.", config=True)

    s3_bucket = Unicode(help="S3 bucket to store metadata about routes in.", config=True)
    s3_prefix = Unicode(help="Prefix to store objects in S3 bucket at.", config=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.executor = ThreadPoolExecutor(max_workers=8)

        if self.s3_prefix[0] == '/':
            self.s3_prefix = self.s3_prefix[1:]
        if self.s3_prefix[-1] == '/':
            self.s3_prefix = self.s3_prefix[:-1]

        if self.use_vault:
            self.vault = hvac.Client(url=self.vault_url,
                                     token=self.vault_token)
            try:
                token = self.vault.lookup_token()
            except hvac.exceptions.Forbidden:
                self.log.error('Failed to login to Vault. INVALID TOKEN.')
                raise
            self._renew_vault_token()

            # renew 20 mins before token expires
            period = (token['data']['creation_ttl'] - 1200) * 1000
            pc = PeriodicCallback(self._renew_vault_token, period)
            pc.start()

            sts = self._update_aws_session_vault()
            period = (sts['lease_duration'] - 60 * 10) * 1000
            pc = PeriodicCallback(self._update_aws_session_vault, period)
            pc.start()
        else:
            self._aws = boto3.session.Session()

    def _renew_vault_token(self):
        self.vault.renew_token()

    def _update_aws_session_vault(self):
        token = self.vault.read(self.vault_path)
        self._aws = boto3.session.Session(
            region_name=self.alb_region,
            aws_access_key_id=token['data']['access_key'],
            aws_secret_access_key=token['data']['secret_key'],
            aws_session_token=token['data']['security_token'])
        return token

    # Turn sync code into async.
    # Idea from https://github.com/jupyterhub/kubespawner/blob/b6883cbc68eba4b9d69aa86066739b73732ed970/kubespawner/proxy.py#L67
    @run_on_executor
    def asynchronize(self, method, *args, **kwargs):
        return method(*args, **kwargs)

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

    @gen.coroutine
    def get_instance_id(self, target):
        url = urlparse(target)
        try:
            ipaddress.ip_address(url.hostname)
        except ValueError:
            raise RuntimeError('Target was not specified as an IPv4 address.')

        # assume ipaddress is private_ipv4
        client = self._aws.client('ec2')
        resp = yield self.asynchronize(
            client.describe_instances,
            Filters=[{'Name': 'private-ip-address', 'Values': [url.hostname]}],
        )

        try:
            return resp['Reservations'][0]['Instances'][0]['InstanceId']
        except (IndexError, KeyError):
            raise RuntimeError('Failed to find the instance with private-ip-address=%s: %s' % (url.hostname, str(resp)))

    @property
    def max_rules(self):
        if hasattr(self, '_max_rules'):
            return self._max_rules

        client = self._aws.client('elbv2')
        resp = client.describe_account_limits()
        for limit in resp['Limits']:
            if limit['Name'] == 'rules-per-application-load-balancer':
                self._max_rules = int(limit['Max'])
        return self._max_rules

    @gen.coroutine
    def start(self):
        client = self._aws.client('elbv2')

        # First check if load balancer exists
        lbs = client.describe_load_balancers()
        should_create_alb = True
        for lb in lbs['LoadBalancers']:
            if lb['LoadBalancerName'] == self.alb_name:
                self._alb_arn = lb['LoadBalancerArn']
                self.vpcid = lb['VpcId']
                should_create_alb = False
                self.log.info('Found existing ALB with ARN: %s', self.alb_arn)

        if should_create_alb:
            resp = client.create_load_balancer(
                Name=self.alb_name, Subnets=self.alb_subnets, SecurityGroups=self.alb_security_groups,
                Scheme=self.alb_scheme, Tags=self.alb_tags, IpAddressType=self.alb_ipaddress_type
            )

            alb_found = False
            for lb in resp['LoadBalancers']:
                if lb['LoadBalancerName'] == self.alb_name:
                    alb_found = True
                    self._alb_arn = lb['LoadBalancerArn']
                    self.vpcid = lb['VpcId']
                    self.log.info('Created new ALB with ARN: %s', self.alb_arn)

            if not alb_found:
                raise RuntimeError('FAILED to create ALB: %s' % json.dumps(resp))

        tg_name = uuid.uuid5(uuid.NAMESPACE_URL, self.alb_name + '/').hex
        tg_arn = yield self._create_target_group(tg_name, 'HTTP', self.hub.port, self.vpcid, '/hub/api')

        should_create_listener = True
        listeners = client.describe_listeners(LoadBalancerArn=self.alb_arn)
        for lner in listeners['Listeners']:
            if lner['Protocol'] == self.alb_listener_protocol and lner['Port'] == self.alb_listener_port:
                self._listener_arn = lner['ListenerArn']
                should_create_listener = False
                self.log.info('Found existing Listener with ARN: %s', self.listener_arn)

        # lookup our instance-id
        httpclient = AsyncHTTPClient()
        req = HTTPRequest('http://169.254.169.254/latest/meta-data/instance-id', method='GET')
        resp = yield httpclient.fetch(req)
        instance_id = resp.body.decode('utf8')
        self.log.info('Registering target %s to Target Group %s', instance_id, tg_arn)
        client.register_targets(TargetGroupArn=tg_arn, Targets=[{'Id': instance_id}])

        if should_create_listener:
            create_listener_args = {
                'LoadBalancerArn': self.alb_arn,
                'Protocol': self.alb_listener_protocol,
                'Port': self.alb_listener_port,
                'DefaultActions': [{'Type': 'forward', 'TargetGroupArn': tg_arn}]
            }
            if self.alb_cert_arn:
                create_listener_args.update({
                    'Certificates': [{'CertificateArn': self.alb_cert_arn}],
                })
            listeners = client.create_listener(**create_listener_args)
            listener_found = False
            for lner in listeners['Listeners']:
                if lner['LoadBalancerArn'] == self.alb_arn:
                    self._listener_arn = lner['ListenerArn']
                    listener_found = True
                    self.log.info('Created new Listener with ARN: %s', self.listener_arn)
            if not listener_found:
                raise RuntimeError('Failed to create listener on ALB: %s', json.dumps(listeners))

    @gen.coroutine
    def stop(self):
        routes = yield self.get_all_routes()
        for routespec in routes:
            self.delete_route(routespec)

        client = self._aws.client('elbv2')
        client.delete_load_balancer(LoadBalancerArn=self.alb_arn)

        try:
            self._aws.client('s3').delete_object(
                Bucket=self.s3_bucket,
                Key=self.s3_prefix + '/' + 'metadata'
            )
        except ClientError as err:
            if err.response['Error']['Code'] != 'NoSuchKey':
                raise

    @gen.coroutine
    def get_all_routes(self):
        s3 = self._aws.client('s3')
        resp = yield self.asynchronize(s3.list_objects_v2, Bucket=self.s3_bucket, Prefix=self.s3_prefix)

        all_routes = {}
        if resp['KeyCount'] > 0:
            for route in resp['Contents']:
                self.log.info('Got route with key %s', route['Key'])
                routespec = route['Key'].replace(self.s3_prefix, '')
                if routespec[0] != '/':
                    routespec = '/' + routespec
                if routespec.endswith('metadata'):
                    routespec = routespec[:-8]
                all_routes[routespec] = yield self.get_route(routespec)
        self.log.debug('Got all routes: %s', json.dumps(all_routes))
        return all_routes

    @gen.coroutine
    def get_route(self, routespec):
        if self.host_routing:
            routespec = '/' + routespec

        s3 = self._aws.client('s3')
        try:
            resp = yield self.asynchronize(
                s3.get_object,
                Bucket=self.s3_bucket,
                Key=self.s3_prefix + routespec + 'metadata'
            )
            return json.load(resp['Body'])
        except ClientError as err:
            if err.response['Error']['Code'] != 'NoSuchKey':
                raise
            self.log.warning('No route was found for "%s".' % routespec)
            return {}

    @gen.coroutine
    def _create_target_group(self, tg_name, proto, port, vpcid, hc_path):
        client = self._aws.client('elbv2')

        tg_arn = None
        # First check if target group exists
        try:
            tgs = yield self.asynchronize(client.describe_target_groups, Names=[tg_name])
            for tg in tgs['TargetGroups']:
                if tg['TargetGroupName'] == tg_name:
                    tg_arn = tg['TargetGroupArn']
                    self.log.info('Found existing TargetGroup with ARN: %s', tg_arn)
                    return tg_arn
        except ClientError as err:
            if err.response['Error']['Code'] != 'TargetGroupNotFound':
                raise

        tgs = yield self.asynchronize(
            client.create_target_group,
            Name=tg_name,
            Protocol=proto,
            Port=port,
            VpcId=self.vpcid,
            HealthCheckPath=hc_path,
            HealthCheckIntervalSeconds=self.tg_healthcheck_interval,
            HealthCheckTimeoutSeconds=self.tg_healthcheck_timeout,
            HealthyThresholdCount=self.tg_healthy_threshold,
            UnhealthyThresholdCount=self.tg_unhealthy_threshold,
        )

        for tg in tgs['TargetGroups']:
            if tg['TargetGroupName'] == tg_name:
                tg_arn = tg['TargetGroupArn']
                self.log.info('Created new TargetGroup %s with ARN: %s', tg_name, tg_arn)
                return tg_arn

        raise RuntimeError('Failed to create target group %s: %s', tg_name, json.dumps(tgs))

    def add_hub_route(self, hub):
        """Add the default route for the Hub"""
        self.log.info("Adding default route for Hub: / => %s", hub.host)
        return self.add_route('/', self.hub.host, {'hub': True}, hc_path='/hub/api')

    @gen.coroutine
    def add_route(self, routespec, target, data, hc_path='/'):
        self.validate_routespec(routespec)
        metadata = {'routespec': routespec, 'target': target, 'data': data}
        self.log.info('add_route routespec=%s target=%s data=%s', routespec, target, json.dumps(data))

        # We use a uuid for the target group name because
        # target group names have a limit of 32 alphanumeric charaters.
        # routespec is close enough to a url
        tg_name = uuid.uuid5(uuid.NAMESPACE_URL, self.alb_name + routespec).hex
        # need to extract the target port from target
        target_url = urlparse(target)

        if data.get('user'):
            hc_path = '/user/%s/api' % data['user']

        tg_arn = yield self._create_target_group(tg_name,
                                                 target_url.scheme.upper(),
                                                 target_url.port,
                                                 self.vpcid,
                                                 hc_path)

        client = self._aws.client('elbv2')

        # Add target to target group
        instance_id = yield self.get_instance_id(target)

        # See if there are existing targets in target group,
        # and deregister them if they do not match.
        targets = yield self.asynchronize(client.describe_target_health, TargetGroupArn=tg_arn)
        for target in targets['TargetHealthDescriptions']:
            if (target['Target']['Id'] != instance_id or
                    target['Target']['Port'] != target_url.port):
                yield self.asynchronize(
                    client.deregister_targets,
                    TargetGroupArn=tg_arn,
                    Targets=[target['Target']]
                )

        target = yield self.asynchronize(
            client.register_targets,
            TargetGroupArn=tg_arn,
            Targets=[{'Id': instance_id, 'Port': target_url.port}]
        )

        # Add rule to listener
        if self.host_routing:
            host = routespec.split('/')[0]
            condition = {'Field': 'host-header', 'Values': [host]}
        else:
            condition = {'Field': 'path-pattern', 'Values': [routespec + '*']}
        self.log.info('Adding rule to route to %s based on condition %s.', tg_arn, json.dumps(condition))

        min_priority = MAX_PRIORITY + 1
        rules = yield self.asynchronize(client.describe_rules, ListenerArn=self.listener_arn)
        exists = False
        for rule in rules['Rules']:
            try:
                priority = int(rule['Priority'])
                if priority < min_priority:
                    min_priority = priority
            except ValueError:
                # if the priority cannot be cast to an int it is
                # likely the default priority
                pass
            for action in rule['Actions']:
                self.log.debug('Checking Rule forwarding to %s', action['TargetGroupArn'])
                if action['TargetGroupArn'] == tg_arn:
                    exists = True
                    for cond in rule['Conditions']:
                        for path in cond['Values']:
                            self.log.debug('Checking existing condition path "%s" == "%s"', path, ','.join(condition['Values']))
                            self.log.debug('Checking existing condition path "%s" == "%s"', type(path), type(condition['Values'][0]))
                            if path not in condition['Values']:
                                self.log.debug('Modifying rule %s', rule['RuleArn'])
                                yield self.asynchronize(
                                    client.modify_rule,
                                    RuleArn=rule['RuleArn'],
                                    Conditions=[condition],
                                    Actions=rule['Actions']
                                )
                            else:
                                self.log.debug('Rule %s already matches.', rule['RuleArn'])

        if not exists:
            yield self.asynchronize(
                client.create_rule,
                ListenerArn=self.listener_arn,
                Conditions=[condition],
                Priority=min_priority - 1,
                Actions=[{'Type': 'forward', 'TargetGroupArn': tg_arn}]
            )

        # Save metadata to S3

        metadata.update({'jupyterhub-route': True})
        yield self.asynchronize(
            self._aws.client('s3').put_object,
            Body=json.dumps(metadata).encode('utf8'),
            Bucket=self.s3_bucket,
            Key=self.s3_prefix + routespec + 'metadata'
        )

        # Need to wait for target to be healthy.
        starttime = IOLoop.current().time()
        while IOLoop.current().time() < starttime + (self.tg_healthcheck_interval * self.tg_healthy_threshold * 2):
            targets = yield self.asynchronize(client.describe_target_health, TargetGroupArn=tg_arn)
            for target in targets['TargetHealthDescriptions']:
                target_state = target['TargetHealth']['State']
                if target_state == 'healthy':
                    return
                elif target_state == 'initial':
                    self.log.debug('Route to routespec %s initializing. %s', routespec, target['TargetHealth']['Reason'])
                    yield gen.sleep(30)
                elif target_state == 'unhealthy':
                    self.log.error('Route to routespec %s failed. Target is unhealth: %s', routespec, target['TargetHealth']['Reason'])

    @gen.coroutine
    def delete_route(self, routespec):
        client = self._aws.client('elbv2')

        tg_name = uuid.uuid5(uuid.NAMESPACE_URL, self.alb_name + '/' + routespec).hex
        tg_arn = None
        try:
            tg_desc = yield self.asynchronize(client.describe_target_groups, Names=[tg_name])
            tg_arn = tg_desc['TargetGroups'][0]['TargetGroupArn']
        except ClientError as err:
            if err.response['Error']['Code'] != 'TargetGroupNotFound':
                raise

        rules = yield self.asynchronize(client.describe_rules, ListenerArn=self.listener_arn)
        rule_arn = ''
        for rule in rules['Rules']:
            for action in rule['Actions']:
                if action.get('TargetGroupArn') == tg_arn:
                    rule_arn = rule['RuleArn']
                    self.log.info('Deleting rule for routespec %s and route arn %s', routespec, rule_arn)
                    yield self.asynchronize(client.delete_rule, RuleArn=rule['RuleArn'])

        if tg_arn:
            self.log.info('Deleting target group routespec=%s tg_arn=%s', routespec, tg_arn)
            yield self.asynchronize(client.delete_target_group, TargetGroupArn=tg_arn)

        try:
            yield self.asynchronize(
                self._aws.client('s3').delete_object,
                Bucket=self.s3_bucket,
                Key=self.s3_prefix + routespec + 'metadata'
            )
        except ClientError as err:
            if err.response['Error']['Code'] != 'NoSuchKey':
                raise
