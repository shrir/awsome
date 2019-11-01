from gevent import monkey; monkey.patch_all()
import gevent

import os
import time
import boto3
import pprint
import getpass
import logging
import paramiko
import datetime
import functools

from argparse import ArgumentParser

from config import inst_def_globals
from config import instances


ec2 = boto3.resource('ec2')
logger = logging.getLogger('awsome')
greenlets = []


def list_instances(args):
    try:
        lines = []
        for inst in ec2.instances.all():
            lines.append(', '.join(['%s: %s' % (
                p, functools.reduce(
                    dict.__getitem__,
                    p.split('.')[1:],
                    getattr(inst, p.split('.', 1)[0]))) for p in args.props]))

        if args.out_file:
            with open(args.out_file, 'a') as out_file:
                out_file.writelines('%s\n' % l for l in lines)
        else:
            [print(line) for line in lines]
    except Exception as ex:
        msg = f"Failed tp list instances: {ex}"
        print(msg)
        logger.error(msg)


def describe_instances(args):
    try:
        lines = []

        if args.instance_ids:
            resp = ec2.meta.client.describe_instances(
                InstanceIds=args.instance_ids)
        elif args.tags:
            filters = [{
                'Name': f'tag:{t.split(":", 1)[0]}',
                'Values': [t.split(':', 1)[1]]}
                    for t in args.tags ]

            resp = ec2.meta.client.describe_instances(Filters=filters)
        else:
            resp = ec2.meta.client.describe_instances()

        for r in resp['Reservations']:
            for i in r['Instances']:
                lines.append(i)

        pp = pprint.PrettyPrinter(width=41, compact=True)

        if args.out_file:
            with open(args.out_file, 'a') as out_file:
                [pprint.pprint(l, stream=out_file) for l in lines]
        else:
            [pp.pprint(line) for line in lines]
    except Exception as ex:
        msg = f"Failed tp describe instances: {ex}"
        print(msg)
        logger.error(msg)


def execute_post_actions(
        host, port, username, actions, password=None, keyfile=None):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if password:
            ssh.connect(host, port=port, username=username, password=password)

        if keyfile:
            try:
                key = paramiko.RSAKey.from_private_key_file(keyfile)
            except paramiko.PasswordRequiredException:
                try:
                    key = paramiko.RSAKey.from_private_key_file(
                        keyfile, password)
                except paramiko.PasswordRequiredException:
                    password = getpass.getpass('RSA key password: ')
                    key = paramiko.RSAKey.from_private_key_file(
                        keyfile, password)

            ssh.connect(host, port=port, username=username, pkey=key)

        for action in actions:
            start = datetime.datetime.now()
            stdin, stdout, stderr = ssh.exec_command(action)
            end = datetime.datetime.now()
            resp = ''.join(stdout.readlines())
            out = f'[{start} - {host}:{port}] {action}\n' \
                f'[{end} - {host}:{port}] {resp}'

            if args.out_dir:
                with open(os.path.join('/tmp', host + '.out'), 'a') as out_file:
                    out_file.write(out)
            else:
                print(out)

    except Exception as ex:
        msg = f'Failed to execute post actions on {host}: {ex}'
        print(msg)
        logger.error(msg)


def _instance_reachable(**kwargs):
    try:
        instance_status = ec2.meta.client.describe_instance_status(
            **kwargs).get(
                'InstanceStatuses', [])[0].get(
                    'InstanceStatus', {}).get(
                        'Status', 'not_ok')
        system_status = ec2.meta.client.describe_instance_status(
            **kwargs).get(
                'InstanceStatuses', [])[0].get(
                    'SystemStatus', {}).get(
                        'Status', 'not_ok')

        return instance_status == 'ok' and system_status == 'ok'
    except (IndexError, KeyError) as err:
        pass
    except Exception as ex:
        msg = f'Failed to check if the instance(s) {kwargs} is reachable: {ex}'
        print(msg)
        logger.error(msg)

    return False


def _post_process_instance(name, inst_id, actions):
    try:
        # Wait for the instance to come up
        while not _instance_reachable(InstanceIds=[inst_id]):
            time.sleep(30)

        msg = f'Instance {name} - {inst_id} is fully up'
        logger.debug(msg)
        print(msg)

        # Fetch latest instance attributes
        inst = ec2.Instance(inst_id)

        execute_post_actions(
            inst.public_ip_address,
            22,
            instances.get(name, {}).get('username', 'root'),
            actions,
            password=instances.get(name, {}).get('password'),
            keyfile=os.path.expanduser(
                instances.get(name, {}).get('keyfile', '~/.ssh/id_rsa')))
    except Exception as ex:
        msg = f'Failed to post process instance {name} - {inst_id}: {ex}'
        print(msg)
        logger.error(msg)


def _create_instances(name, inst):
    try:
        # Extract instance definition
        inst_def = inst.get('definition', {})

        # Combine with global props
        combined_inst_def = {**inst_def_globals, **inst_def}

        # Create new EC2 instance
        instances = ec2.create_instances(**combined_inst_def)

        actions = inst.get('post_actions')
        if not actions:
            return

        # Execute post actions for created instances
        for inst in instances:
            msg = f'Instance {name} is created as {inst.id}'
            logger.debug(msg)
            print(msg)
            g = gevent.spawn(_post_process_instance, inst.id, actions)
            greenlets.append(g)

    except Exception as ex:
        msg = f'Failed to create instance {name}: {ex}'
        print(msg)
        logger.error(msg)


def create_instances(args):
    for name, inst in instances.items():
        try:
            g = gevent.spawn(_create_instances, name, inst)
            greenlets.append(g)
        except Exception as ex:
            msg = f'Failed to create instance {name}: {ex}'
            print(msg)
            logger.error(msg)


def start_instances(args):
    try:
        res = ec2.instances.filter(InstanceIds=args.instances).start()
        if not res:
            raise Exception("Cannot interpret response from aws")

        lines = []
        for r in res[0].get('StartingInstances', []):
            line = f'Instance: {r.get("InstanceId")}, '\
                f'Current State: {r.get("CurrentState", {}).get("Name")}, '\
                f'Previous State: {r.get("PreviousState", {}).get("Name")}'
            lines.append(line)

        if args.out_file:
            with open(args.out_file, 'a') as out_file:
                out_file.writelines('%s\n' % l for l in lines)
        else:
            [print(line) for line in lines]
    except Exception as ex:
        msg = f'Failed to start instances: {ex}'
        print(msg)
        logger.error(msg)


def stop_instances(args):
    try:
        res = ec2.instances.filter(InstanceIds=args.instances).stop()
        if not res:
            raise Exception("Cannot interpret response from aws")

        lines = []
        for r in res[0].get('StoppingInstances', []):
            line = f'Instance: {r.get("InstanceId")}, '\
                f'Current State: {r.get("CurrentState", {}).get("Name")}, '\
                f'Previous State: {r.get("PreviousState", {}).get("Name")}'
            lines.append(line)

        if args.out_file:
            with open(args.out_file, 'a') as out_file:
                out_file.writelines('%s\n' % l for l in lines)
        else:
            [print(line) for line in lines]
    except Exception as ex:
        msg = f'Failed to stop instances: {ex}'
        print(msg)
        logger.error(msg)


def reboot_instances(args):
    try:
        ec2.instances.filter(InstanceIds=args.instances).reboot()
    except Exception as ex:
        msg = f'Failed to reboot instances: {ex}'
        print(msg)
        logger.error(msg)


def terminate_instances(args):
    try:
        res = ec2.instances.filter(InstanceIds=args.instances).terminate()
        if not res:
            raise Exception("Cannot interpret response from aws")

        lines = []
        for r in res[0].get('TerminatingInstances', []):
            line = f'Instance: {r.get("InstanceId")}, '\
                f'Current State: {r.get("CurrentState", {}).get("Name")}, '\
                f'Previous State: {r.get("PreviousState", {}).get("Name")}'
            lines.append(line)

        if args.out_file:
            with open(args.out_file, 'a') as out_file:
                out_file.writelines('%s\n' % l for l in lines)
        else:
            [print(line) for line in lines]
    except Exception as ex:
        msg = f'Failed to terminate instances: {ex}'
        print(msg)
        logger.error(msg)


parser = ArgumentParser(description='awsome')
parser.add_argument(
    '-f', '--log-file',
    dest='log_file',
    default='/dev/null',
    help='Log file')

parser.add_argument(
    '-l', '--log-level',
    dest='log_level',
    default='INFO',
    help='Log level(DEBUG | INFO | WARNING | ERROR | CRITICAL)')

parser.add_argument(
    '-w', '--output-file',
    dest='out_file',
    help='Output file')

subparsers = parser.add_subparsers()

parser_list = subparsers.add_parser('list')
parser_list.add_argument(
    'props',
    nargs='*',
    default=['id', 'state'],
    help='Instance parameters')
parser_list.set_defaults(func=list_instances)

parser_describe = subparsers.add_parser('describe')
parser_describe.add_argument(
    '-i', '--instances-ids',
    nargs='+',
    dest='instance_ids',
    help='Instance ids',
    metavar='INSTANCE_ID')
parser_describe.add_argument(
    '-t', '--tags',
    nargs='+',
    dest='tags',
    help='Tag key value pairs',
    metavar='KEY:VALUE')
parser_describe.set_defaults(func=describe_instances)

parser_create = subparsers.add_parser('create')
parser_create.set_defaults(func=create_instances)

parser_start = subparsers.add_parser('start')
parser_start.add_argument(
    'instances',
    nargs='+',
    help='Instance ids',
    metavar='INSTANCE_ID')
parser_start.set_defaults(func=start_instances)

parser_stop = subparsers.add_parser('stop')
parser_stop.add_argument(
    'instances',
    nargs='+',
    help='Instance ids',
    metavar='INSTANCE_ID')
parser_stop.set_defaults(func=stop_instances)

parser_reboot = subparsers.add_parser('reboot')
parser_reboot.add_argument(
    'instances',
    nargs='+',
    help='Instance ids',
    metavar='INSTANCE_ID')
parser_reboot.set_defaults(func=reboot_instances)

parser_terminate = subparsers.add_parser('terminate')
parser_terminate.add_argument(
    'instances',
    nargs='+',
    help='Instance ids',
    metavar='INSTANCE_ID')
parser_terminate.set_defaults(func=terminate_instances)

args = parser.parse_args()

logging.basicConfig(
    level=getattr(logging, args.log_level, 'INFO'),
    filename=args.log_file,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s')

paramiko.util.log_to_file(args.log_file, level=args.log_level)

if args.out_file:
    with open(args.out_file, 'a') as out_file:
        now = datetime.datetime.now()
        out_file.write(f'======= {now} ======= {args.func.__name__} =======\n')

if getattr(args, 'func', None):
    args.func(args)

gevent.joinall(greenlets)
