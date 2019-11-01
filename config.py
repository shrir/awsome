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
        "keyfile": "~/.ssh/aws_personal/ssh_acess.pem",
        "post_actions": [
            "apt-get update",
            "apt-get install vim"
        ]
    },
    "server_instance": {
        "definition": {
            "MinCount": 1,
            "MaxCount": 1,
            "TagSpecifications": [{
                "ResourceType": "instance",
                "Tags": [{
                    "Key": "Node",
                    "Value": "server"
                }]
            }]
        },
        "username": "admin",
        "keyfile": "~/.ssh/aws_personal/ssh_acess.pem",
        "post_actions": [
            "apt-get update",
            "apt-get install vim"
        ]
    }
}
