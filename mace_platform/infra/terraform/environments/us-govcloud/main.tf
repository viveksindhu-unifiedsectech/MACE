##############################################################################
# MACE Platform - US GovCloud Environment (AWS us-gov-west-1)
# FedRAMP High + FIPS 140-2 + CMMC Level 2/3
# Requires separate AWS GovCloud account.
##############################################################################
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "mace-terraform-state-govcloud"
    key            = "us-govcloud/terraform.tfstate"
    region         = "us-gov-west-1"
    encrypt        = true
    dynamodb_table = "mace-terraform-locks-govcloud"
  }
}

provider "aws" {
  region = "us-gov-west-1"
  default_tags {
    tags = {
      Project             = "UnifiedSec-MACE"
      Environment         = "production-govcloud"
      Region              = "us-gov-west-1"
      DataResidency       = "US-GOV"
      Jurisdiction        = "US"
      ComplianceFramework = "FedRAMP-High,CMMC-L3,FIPS-140-2"
      ManagedBy           = "Terraform"
      DataClassification  = "CUI"
    }
  }
}

locals {
  name        = "mace-govcloud-prod"
  environment = "production-govcloud"
  region      = "us-gov-west-1"
  azs         = ["us-gov-west-1a", "us-gov-west-1b", "us-gov-west-1c"]
}

module "vpc" {
  source             = "../../modules/vpc"
  name               = local.name
  cidr               = "10.10.0.0/16"
  azs                = local.azs
  private_subnets    = ["10.10.1.0/24", "10.10.2.0/24", "10.10.3.0/24"]
  public_subnets     = ["10.10.101.0/24", "10.10.102.0/24", "10.10.103.0/24"]
  database_subnets   = ["10.10.201.0/24", "10.10.202.0/24", "10.10.203.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = false
  environment        = local.environment
}

module "eks" {
  source              = "../../modules/eks"
  cluster_name        = "${local.name}-eks"
  cluster_version     = "1.29"
  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  environment         = local.environment
  region              = local.region
  node_instance_types = ["m5.2xlarge"]
  node_min_size       = 3
  node_max_size       = 15
  node_desired_size   = 5
  enable_spot         = false  # GovCloud: on-demand only for compliance
}

module "rds" {
  source                  = "../../modules/rds"
  identifier              = "${local.name}-postgres"
  vpc_id                  = module.vpc.vpc_id
  db_subnet_group_name    = module.vpc.db_subnet_group_name
  allowed_security_groups = []
  db_password             = var.db_password
  instance_class          = "db.r6g.2xlarge"
  allocated_storage       = 200
  max_storage             = 1000
  multi_az                = true
  deletion_protection     = true
  backup_retention        = 35  # FedRAMP High: 35-day PITR
  environment             = local.environment
  jurisdiction            = "US"
}

module "redis" {
  source                  = "../../modules/redis"
  name                    = "${local.name}-redis"
  vpc_id                  = module.vpc.vpc_id
  cache_subnet_group_name = module.vpc.cache_subnet_group
  allowed_security_groups = []
  node_type               = "cache.r7g.xlarge"
  num_cache_nodes         = 3
  auth_token              = var.redis_auth_token
  environment             = local.environment
}

module "waf" {
  source      = "../../modules/waf"
  name        = local.name
  environment = local.environment
  rate_limit  = 10000
}

module "s3_evidence" {
  source           = "../../modules/s3"
  bucket_prefix    = local.name
  environment      = local.environment
  jurisdiction     = "US"
  account_id       = data.aws_caller_identity.current.account_id
  kms_key_arn      = aws_kms_key.govcloud.arn
  retention_years  = 7
}

resource "aws_kms_key" "govcloud" {
  description             = "${local.name} GovCloud master key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags = { FIPSAlgorithm = "AES-256-GCM", FedRAMPControl = "SC-28" }
}

resource "aws_kms_alias" "govcloud" {
  name          = "alias/${local.name}-master"
  target_key_id = aws_kms_key.govcloud.key_id
}

resource "aws_cloudtrail" "govcloud" {
  name                          = "${local.name}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.govcloud.arn
  tags = { FedRAMPControl = "AU-2,AU-3,AU-12" }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${local.name}-cloudtrail-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect="Allow", Principal={Service="cloudtrail.amazonaws.com"},
        Action="s3:PutObject", Resource="${aws_s3_bucket.cloudtrail.arn}/AWSLogs/*",
        Condition={StringEquals={"s3:x-amz-acl"="bucket-owner-full-control"}} },
      { Effect="Allow", Principal={Service="cloudtrail.amazonaws.com"},
        Action="s3:GetBucketAcl", Resource=aws_s3_bucket.cloudtrail.arn },
    ]
  })
}

data "aws_caller_identity" "current" {}

variable "db_password"      { type = string; sensitive = true }
variable "redis_auth_token" { type = string; sensitive = true }

output "eks_cluster_name"     { value = module.eks.cluster_name }
output "rds_endpoint"         { value = module.rds.endpoint }
output "redis_endpoint"       { value = module.redis.primary_endpoint }
output "vpc_id"               { value = module.vpc.vpc_id }
output "evidence_bucket_name" { value = module.s3_evidence.evidence_bucket_name }
output "kms_key_arn"          { value = aws_kms_key.govcloud.arn }
