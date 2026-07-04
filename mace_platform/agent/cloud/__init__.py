"""
Cloud provisioning helpers.

Spins up the AWS control-plane stack required to host the MACE management
server (ingest API + dashboard + Postgres + S3 evidence bucket) for a
large-scale agent rollout. Uses boto3 directly so it can run from the
endpoint agent itself when an enterprise admin chooses 'Provision MACE cloud'
in the GUI.

For production multi-region deployments the existing Terraform modules
under mace_platform/infra/terraform/ remain the source of truth — this
module is the one-click path for smaller customers who want a working
control plane in minutes.
"""
from .aws_provision import provision_stack, ProvisionResult

__all__ = ["provision_stack", "ProvisionResult"]
