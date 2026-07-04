##############################################################################
# MACE Platform — EU Environment (AWS eu-west-1 / Azure West Europe)
# Data residency: EU (GDPR Art.33, NIS2, DORA)
# NOTE: For Azure deployment, use azurerm provider instead.
##############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket  = "mace-terraform-state-eu"
    key     = "eu/terraform.tfstate"
    region  = "eu-west-1"
    encrypt = true
  }
}

provider "aws" {
  region = "eu-west-1"
  default_tags {
    tags = {
      Project             = "UnifiedSec-MACE"
      Environment         = "production"
      Region              = "eu-west-1"
      DataResidency       = "EU"
      Jurisdiction        = "EU"
      ComplianceFramework = "GDPR,NIS2,DORA"
      GDPRDataController  = "UnifiedSec Technologies"
      ManagedBy           = "Terraform"
    }
  }
}

locals {
  name = "mace-eu-prod"
  azs  = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
}

module "vpc" {
  source             = "../../modules/vpc"
  name               = local.name
  cidr               = "10.3.0.0/16"
  azs                = local.azs
  private_subnets    = ["10.3.1.0/24", "10.3.2.0/24", "10.3.3.0/24"]
  public_subnets     = ["10.3.101.0/24", "10.3.102.0/24", "10.3.103.0/24"]
  database_subnets   = ["10.3.201.0/24", "10.3.202.0/24", "10.3.203.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = false
  environment        = "production"
}

module "eks" {
  source              = "../../modules/eks"
  cluster_name        = "${local.name}-eks"
  cluster_version     = "1.29"
  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  environment         = "production"
  region              = "eu-west-1"
  node_instance_types = ["m5.xlarge"]
  node_min_size       = 2
  node_max_size       = 10
  node_desired_size   = 3
  enable_spot         = true
}

module "rds" {
  source                  = "../../modules/rds"
  identifier              = "${local.name}-postgres"
  vpc_id                  = module.vpc.vpc_id
  db_subnet_group_name    = module.vpc.db_subnet_group_name
  allowed_security_groups = []
  db_password             = var.db_password
  instance_class          = "db.r6g.large"
  backup_retention        = 30   # GDPR: longer retention
  environment             = "production"
  jurisdiction            = "EU"
}

module "redis" {
  source                  = "../../modules/redis"
  name                    = "${local.name}-redis"
  vpc_id                  = module.vpc.vpc_id
  cache_subnet_group_name = module.vpc.cache_subnet_group
  allowed_security_groups = []
  node_type               = "cache.r7g.large"
  num_cache_nodes         = 2
  auth_token              = var.redis_auth_token
  environment             = "production"
}

module "waf" {
  source      = "../../modules/waf"
  name        = local.name
  environment = "production"
  rate_limit  = 10000
}

variable "db_password"      { type = string; sensitive = true }
variable "redis_auth_token" { type = string; sensitive = true }

output "eks_cluster_name" { value = module.eks.cluster_name }
output "rds_endpoint"     { value = module.rds.endpoint }
