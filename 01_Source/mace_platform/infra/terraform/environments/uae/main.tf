##############################################################################
# MACE Platform — UAE Environment (AWS me-central-1)
# Data residency: UAE (NESA IAS 2023, NCA ECC-1:2018, aeCERT)
# All data stays within UAE sovereign cloud boundary.
##############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "mace-terraform-state-uae"
    key            = "uae/terraform.tfstate"
    region         = "me-central-1"
    encrypt        = true
    dynamodb_table = "mace-terraform-locks-uae"
  }
}

provider "aws" {
  region = "me-central-1"
  default_tags {
    tags = {
      Project            = "UnifiedSec-MACE"
      Environment        = "production"
      Region             = "me-central-1"
      DataResidency      = "AE"
      Jurisdiction       = "UAE"
      ComplianceFramework = "NESA-IAS-2023,NCA-ECC,aeCERT"
      ManagedBy          = "Terraform"
    }
  }
}

locals {
  name        = "mace-uae-prod"
  environment = "production"
  region      = "me-central-1"
  azs         = ["me-central-1a", "me-central-1b"]
}

module "vpc" {
  source = "../../modules/vpc"
  name               = local.name
  cidr               = "10.2.0.0/16"
  azs                = local.azs
  private_subnets    = ["10.2.1.0/24", "10.2.2.0/24"]
  public_subnets     = ["10.2.101.0/24", "10.2.102.0/24"]
  database_subnets   = ["10.2.201.0/24", "10.2.202.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = true  # UAE: cost-optimize (2 AZ region)
  environment        = local.environment
}

module "eks" {
  source = "../../modules/eks"
  cluster_name        = "${local.name}-eks"
  cluster_version     = "1.29"
  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  environment         = local.environment
  region              = local.region
  node_instance_types = ["m5.xlarge", "m5a.xlarge"]
  node_min_size       = 2
  node_max_size       = 8
  node_desired_size   = 3
  enable_spot         = true
}

module "rds" {
  source = "../../modules/rds"
  identifier              = "${local.name}-postgres"
  vpc_id                  = module.vpc.vpc_id
  db_subnet_group_name    = module.vpc.db_subnet_group_name
  allowed_security_groups = []
  db_password             = var.db_password
  instance_class          = "db.r6g.xlarge"
  allocated_storage       = 100
  multi_az                = true
  backup_retention        = 7
  environment             = local.environment
  jurisdiction            = "AE"
}

module "redis" {
  source = "../../modules/redis"
  name                    = "${local.name}-redis"
  vpc_id                  = module.vpc.vpc_id
  cache_subnet_group_name = module.vpc.cache_subnet_group
  allowed_security_groups = []
  node_type               = "cache.r7g.large"
  num_cache_nodes         = 2
  auth_token              = var.redis_auth_token
  environment             = local.environment
}

module "waf" {
  source = "../../modules/waf"
  name        = local.name
  environment = local.environment
  rate_limit  = 10000
}

variable "db_password"      { type = string; sensitive = true }
variable "redis_auth_token" { type = string; sensitive = true }

output "eks_cluster_name" { value = module.eks.cluster_name }
output "rds_endpoint"     { value = module.rds.endpoint }
output "redis_endpoint"   { value = module.redis.primary_endpoint }
output "vpc_id"           { value = module.vpc.vpc_id }
