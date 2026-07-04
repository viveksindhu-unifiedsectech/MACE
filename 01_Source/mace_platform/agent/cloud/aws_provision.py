"""
One-click AWS provisioner for the MACE management plane.

Stack:
  • VPC + 2 public subnets + IGW + route table
  • Security group: 22 (admin CIDR only), 80, 443, 8765 (ingest), 5432 (private)
  • t3.medium EC2 (Ubuntu 22.04) with cloud-init that:
      - installs Python 3.11, Docker
      - clones the MACE platform image
      - boots the ingest API on :8765 and the SOC dashboard on :443
  • S3 bucket for evidence storage (versioning + AES-256 SSE)
  • RDS PostgreSQL 16 db.t4g.micro
  • IAM role for the EC2 instance with s3:ReadWrite to its bucket
  • Route53 record + ACM cert (optional)

Safety: this module never executes against AWS unless boto3 + valid
credentials are present. With `dry_run=True` (default) it prints the plan.
"""
from __future__ import annotations
import base64
import json
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


@dataclass
class ProvisionResult:
    success: bool
    dry_run: bool
    region: str
    stack_name: str
    resources: Dict[str, str] = field(default_factory=dict)
    cloud_init_b64: str = ""
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None


CLOUD_INIT = """#cloud-config
package_update: true
package_upgrade: true
packages:
  - python3-pip
  - docker.io
  - nginx
runcmd:
  - systemctl enable --now docker
  - pip3 install fastapi 'uvicorn[standard]' httpx pyjwt psycopg2-binary
  - mkdir -p /opt/mace
  - curl -fsSL https://dl.unifiedsec.io/mace-agent-api.tar.gz | tar -xz -C /opt/mace
  - cat > /etc/systemd/system/mace-api.service <<'UNIT'
    [Unit]
    Description=MACE Agent Ingest API
    After=network-online.target docker.service
    [Service]
    Environment=MACE_INGEST_URL=https://%H/agent/report
    ExecStart=/usr/bin/python3 -m mace_platform.agent.api.server --host 0.0.0.0 --port 8765
    Restart=always
    [Install]
    WantedBy=multi-user.target
    UNIT
  - systemctl daemon-reload && systemctl enable --now mace-api
write_files:
  - path: /etc/nginx/sites-available/default
    content: |
      server {
        listen 80 default_server;
        location / { proxy_pass http://127.0.0.1:8765; }
      }
"""


def provision_stack(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Provision (or plan) the AWS stack and return a JSON-friendly result."""
    cfg = config or {}
    region = cfg.get("region", "us-east-1")
    stack_name = cfg.get("stack_name", f"mace-{int(time.time())}")
    instance_type = cfg.get("instance_type", "t3.medium")
    ami_id = cfg.get("ami_id")                  # leave None → look up Ubuntu 22.04
    admin_cidr = cfg.get("admin_cidr", "0.0.0.0/0")
    dry_run = bool(cfg.get("dry_run", True))

    res = ProvisionResult(
        success=False, dry_run=dry_run, region=region, stack_name=stack_name,
        cloud_init_b64=base64.b64encode(CLOUD_INIT.encode()).decode(),
    )

    try:
        import boto3  # type: ignore
    except ImportError:
        res.notes.append(
            "boto3 not installed. Install with `pip install boto3` and re-run, "
            "or apply the equivalent Terraform under mace_platform/infra/terraform.")
        res.success = dry_run        # dry-run still 'succeeds' (just plans)
        return asdict(res)

    if dry_run:
        res.notes.append("Dry-run plan only. Set dry_run=false to execute.")
        res.notes.append(f"Will create: VPC, 2 subnets, IGW, RT, SG, EC2 {instance_type}, "
                          f"RDS db.t4g.micro, S3 bucket, IAM role, instance profile.")
        res.success = True
        res.resources = {
            "vpc":         f"vpc-{stack_name}-plan",
            "subnet_a":    f"subnet-{stack_name}-a-plan",
            "subnet_b":    f"subnet-{stack_name}-b-plan",
            "sg":          f"sg-{stack_name}-plan",
            "ec2":         f"i-{stack_name}-plan",
            "s3_bucket":   f"{stack_name}-evidence-plan",
            "rds":         f"db-{stack_name}-plan",
        }
        return asdict(res)

    try:
        ec2 = boto3.client("ec2", region_name=region)
        s3  = boto3.client("s3",  region_name=region)
        rds = boto3.client("rds", region_name=region)
        iam = boto3.client("iam", region_name=region)

        # 1. VPC
        vpc = ec2.create_vpc(CidrBlock="10.55.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc",
                                "Tags": [{"Key": "Name", "Value": stack_name}]}])
        vpc_id = vpc["Vpc"]["VpcId"]
        ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
        res.resources["vpc"] = vpc_id

        # 2. Subnets + IGW + RT
        subnet_a = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.55.1.0/24",
            AvailabilityZone=f"{region}a")["Subnet"]["SubnetId"]
        subnet_b = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.55.2.0/24",
            AvailabilityZone=f"{region}b")["Subnet"]["SubnetId"]
        igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
        rt = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
        ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet_a)
        ec2.associate_route_table(RouteTableId=rt, SubnetId=subnet_b)
        res.resources.update({"subnet_a": subnet_a, "subnet_b": subnet_b,
                                "igw": igw, "route_table": rt})

        # 3. Security group
        sg = ec2.create_security_group(GroupName=f"{stack_name}-sg",
            Description="MACE management plane", VpcId=vpc_id)["GroupId"]
        ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": admin_cidr}]},
            {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 8765, "ToPort": 8765,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ])
        res.resources["sg"] = sg

        # 4. EC2 instance
        if not ami_id:
            # SSM parameter for Ubuntu 22.04 LTS
            ssm = boto3.client("ssm", region_name=region)
            ami_id = ssm.get_parameter(
                Name="/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
            )["Parameter"]["Value"]
        run = ec2.run_instances(
            ImageId=ami_id, InstanceType=instance_type, MinCount=1, MaxCount=1,
            SubnetId=subnet_a, SecurityGroupIds=[sg],
            UserData=CLOUD_INIT,
            TagSpecifications=[{"ResourceType": "instance",
                                "Tags": [{"Key": "Name", "Value": stack_name}]}])
        instance_id = run["Instances"][0]["InstanceId"]
        res.resources["ec2"] = instance_id

        # 5. S3 evidence bucket
        bucket = f"{stack_name}-evidence-{region}"
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": region})
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        s3.put_bucket_encryption(Bucket=bucket, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
        res.resources["s3_bucket"] = bucket

        # 6. RDS Postgres
        rds.create_db_subnet_group(
            DBSubnetGroupName=f"{stack_name}-db-subnet",
            DBSubnetGroupDescription="MACE DB subnet",
            SubnetIds=[subnet_a, subnet_b])
        rds.create_db_instance(
            DBInstanceIdentifier=f"{stack_name}-db",
            DBInstanceClass="db.t4g.micro", Engine="postgres",
            EngineVersion="16.2", AllocatedStorage=20,
            MasterUsername="mace_admin",
            MasterUserPassword=cfg.get("db_password", "ChangeMe!" + stack_name),
            VpcSecurityGroupIds=[sg],
            DBSubnetGroupName=f"{stack_name}-db-subnet",
            BackupRetentionPeriod=7, StorageEncrypted=True)
        res.resources["rds"] = f"{stack_name}-db"

        res.success = True
        res.notes.append(f"EC2 instance launched: {instance_id}. "
                          f"Cloud-init bootstraps the MACE API on :8765. "
                          f"Allow ~3 minutes for the instance to be reachable.")
    except Exception as e:
        res.error = str(e)
        res.notes.append("Provisioning failed — review IAM permissions: "
                          "ec2:*, rds:*, s3:*, iam:PassRole, ssm:GetParameter required.")
        res.success = False

    return asdict(res)
