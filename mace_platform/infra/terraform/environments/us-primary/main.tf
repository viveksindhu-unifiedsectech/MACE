##############################################################################
# MACE Platform — US Primary Environment (AWS us-east-1)
# Commercial tier: AWS us-east-1
# FedRAMP tier: AWS us-gov-west-1 (separate state, same modules)
##############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  backend "s3" {
    bucket         = "mace-terraform-state-us"
    key            = "us-primary/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "mace-terraform-locks"
  }
}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      Project            = "UnifiedSec-MACE"
      Environment        = "production"
      Region             = "us-east-1"
      DataResidency      = "US"
      Jurisdiction       = "US"
      Patent             = "IN/2026/UNISEC/MACE-001"
      ManagedBy          = "Terraform"
    }
  }
}

locals {
  name        = "mace-us-prod"
  environment = "production"
  region      = "us-east-1"
  azs         = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

# ── VPC ──────────────────────────────────────────────────────────────────────
module "vpc" {
  source = "../../modules/vpc"

  name               = local.name
  cidr               = "10.0.0.0/16"
  azs                = local.azs
  private_subnets    = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  database_subnets   = ["10.0.201.0/24", "10.0.202.0/24", "10.0.203.0/24"]
  enable_nat_gateway = true
  single_nat_gateway = false  # HA: one NAT per AZ
  environment        = local.environment
}

# ── EKS ──────────────────────────────────────────────────────────────────────
module "eks" {
  source = "../../modules/eks"

  cluster_name        = "${local.name}-eks"
  cluster_version     = "1.29"
  vpc_id              = module.vpc.vpc_id
  subnet_ids          = module.vpc.private_subnet_ids
  environment         = local.environment
  region              = local.region
  node_instance_types = ["m5.2xlarge", "m5a.2xlarge"]
  node_min_size       = 3
  node_max_size       = 15
  node_desired_size   = 5
  enable_spot         = true
}

# ── RDS ───────────────────────────────────────────────────────────────────────
module "rds" {
  source = "../../modules/rds"

  identifier              = "${local.name}-postgres"
  vpc_id                  = module.vpc.vpc_id
  db_subnet_group_name    = module.vpc.db_subnet_group_name
  allowed_security_groups = [module.eks.node_role_arn]
  db_password             = var.db_password
  instance_class          = "db.r6g.2xlarge"
  allocated_storage       = 200
  max_storage             = 1000
  multi_az                = true
  backup_retention        = 35      # 35 days for FedRAMP
  environment             = local.environment
  jurisdiction            = "US"
}

# ── Redis ─────────────────────────────────────────────────────────────────────
module "redis" {
  source = "../../modules/redis"

  name                    = "${local.name}-redis"
  vpc_id                  = module.vpc.vpc_id
  cache_subnet_group_name = module.vpc.cache_subnet_group
  allowed_security_groups = []
  node_type               = "cache.r7g.xlarge"
  num_cache_nodes         = 3
  auth_token              = var.redis_auth_token
  environment             = local.environment
}

# ── WAF ───────────────────────────────────────────────────────────────────────
module "waf" {
  source = "../../modules/waf"

  name        = local.name
  environment = local.environment
  rate_limit  = 15000
}

# ── ECR Repositories ──────────────────────────────────────────────────────────
resource "aws_ecr_repository" "mace_api" {
  name                 = "mace-api"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
  tags = { Name = "mace-api" }
}

resource "aws_ecr_repository" "soc_frontend" {
  name                 = "mace-soc-frontend"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "KMS"; kms_key = aws_kms_key.ecr.arn }
}

resource "aws_ecr_repository" "admin_frontend" {
  name                 = "mace-admin-frontend"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "KMS"; kms_key = aws_kms_key.ecr.arn }
}

resource "aws_kms_key" "ecr" {
  description         = "MACE ECR encryption"
  enable_key_rotation = true
}

# ── S3 Buckets ────────────────────────────────────────────────────────────────
resource "aws_s3_bucket" "evidence" {
  bucket = "mace-evidence-us-prod-${data.aws_caller_identity.current.account_id}"
  tags   = { Purpose = "Regulatory evidence storage" }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ecr.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Route 53 + ACM ────────────────────────────────────────────────────────────
data "aws_route53_zone" "main" {
  name = "unifiedsec.com"
}

resource "aws_acm_certificate" "mace" {
  domain_name               = "app.unifiedsec.com"
  subject_alternative_names = ["api.unifiedsec.com", "admin.unifiedsec.com", "*.unifiedsec.com"]
  validation_method         = "DNS"
  lifecycle { create_before_destroy = true }
}

data "aws_caller_identity" "current" {}

variable "db_password"      { type = string; sensitive = true }
variable "redis_auth_token" { type = string; sensitive = true }

output "eks_cluster_name"    { value = module.eks.cluster_name }
output "eks_endpoint"        { value = module.eks.cluster_endpoint }
output "rds_endpoint"        { value = module.rds.endpoint }
output "redis_endpoint"      { value = module.redis.primary_endpoint }
output "vpc_id"              { value = module.vpc.vpc_id }
output "waf_arn"             { value = module.waf.web_acl_arn }
output "ecr_api_url"         { value = aws_ecr_repository.mace_api.repository_url }
output "evidence_bucket"     { value = aws_s3_bucket.evidence.id }
