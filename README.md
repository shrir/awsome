# awsome: simple script to quickly spin up EC2 instances

## Prerequisites
[AWS CLI Interface](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)

## Usage
```
python3 -m awsome -h
usage: awsome.py [-h] [-f LOG_FILE] [-l LOG_LEVEL] [-w OUT_FILE]
                 {list,describe,create,start,stop,reboot,terminate} ...

awsome

positional arguments:
  {list,describe,create,start,stop,reboot,terminate}

optional arguments:
  -h, --help            show this help message and exit
  -f LOG_FILE, --log-file LOG_FILE
                        Log file
  -l LOG_LEVEL, --log-level LOG_LEVEL
                        Log level(DEBUG | INFO | WARNING | ERROR | CRITICAL)
  -w OUT_FILE, --output-file OUT_FILE
                        Output file
```

## Examples

### List Instances

List specified properties of all instances:
`python3 -m awsome list id state.Name`

### Describe Instances

Describe instances matching given instance ids or tags:
`python3 -m awsome describe -t Node:server`

### Create Instances

Create instances as described in the `config.py` and run commands
`python3 -m awsome create`

#### Instance definitions

Instance definitions for `create` command can be configured in `config.py`

Instance definitions are described in `definition` section of each instance in `instances` dictionary.
All the instances defined here inherit from `inst_def_globals`, hence the common configuration shared
by all the instances can be defined here once.

`post_actions` are a list of command that will be executed after the instance is initialized and reachable over SSH. 

```
inst_def_globals = {
    "ImageId": "ami-02724d1f",
    "InstanceType": "t2.micro",
    "KeyName": "ssh_acess",
    "SecurityGroupIds": ["sg-3a6d5858"],
    "Placement": {
        "AvailabilityZone": "eu-central-1a"
    }
}

instances = {
    "client_instance": {
        "definition": {
            "MinCount": 1,
            "MaxCount": 1,
            "TagSpecifications": [{
                "ResourceType": "instance",
                "Tags": [{
                    "Key": "Node",
                    "Value": "client"
                }]
            }]
        },
        "username": "admin",
        "keyfile": "~/.ssh/aws/ssh_acess.pem",
        "post_actions": [
            "apt-get update",
            "apt-get install vim"
        ]
    }
}
```
Note: A list of supported instance definition options can be found in [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RunInstances.html). 

### Start Instances

Start instances by instance ids
`python3 -m awsome start i-08bae47dadb036151 i-08baf47dabb031351`

### Stop Instances

Stop instances by instance ids
`python3 -m awsome stop i-08bae47dadb036151 i-08baf47dabb031351`

### Reboot Instances

Reboot instances by instance ids
`python3 -m awsome reboot i-08bae47dadb036151 i-08baf47dabb031351`

### Terminate Instances

Terminate instances by instance ids
`python3 -m awsome terminate i-08bae47dadb036151 i-08baf47dabb031351`
