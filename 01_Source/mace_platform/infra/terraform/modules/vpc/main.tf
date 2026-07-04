##############################################################################
# MACE Platform — VPC Module
# Creates multi-AZ VPC with public/private/database subnets, NAT gateways,
# VPC endpoints for S3 and ECR (reduces NAT traffic costs).
##############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "name"               { type = string }
variable "cidr"               { default = "10.0.0.0/16" }
variable "azs"                { type = list(string) }
variable "private_subnets"    { type = list(string) }
variable "public_subnets"     { type = list(string) }
variable "database_subnets"   { type = list(string) }
variable "enable_nat_gateway" { default = true }
variable "single_nat_gateway" { default = false }
variable "environment"        { type = string }
variable "tags"               { default = {} }

locals {
  common_tags = merge({
    Project     = "UnifiedSec-MACE"
    Environment = var.environment
    ManagedBy   = "Terraform"
    Patent      = "IN/2026/UNISEC/MACE-001"
  }, var.tags)
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = merge(local.common_tags, { Name = "${var.name}-vpc" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.common_tags, { Name = "${var.name}-igw" })
}

# Public subnets
resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = var.azs[count.index % length(var.azs)]
  map_public_ip_on_launch = true
  tags = merge(local.common_tags, {
    Name                     = "${var.name}-public-${count.index + 1}"
    "kubernetes.io/role/elb" = "1"
  })
}

# Private subnets (EKS worker nodes)
resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = var.azs[count.index % length(var.azs)]
  tags = merge(local.common_tags, {
    Name                              = "${var.name}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

# Database subnets (RDS, ElastiCache — isolated tier)
resource "aws_subnet" "database" {
  count             = length(var.database_subnets)
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.database_subnets[count.index]
  availability_zone = var.azs[count.index % length(var.azs)]
  tags = merge(local.common_tags, {
    Name = "${var.name}-database-${count.index + 1}"
  })
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name}-db-subnet-group"
  subnet_ids = aws_subnet.database[*].id
  tags       = local.common_tags
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "${var.name}-cache-subnet-group"
  subnet_ids = aws_subnet.database[*].id
}

# Elastic IPs for NAT gateways
resource "aws_eip" "nat" {
  count  = var.single_nat_gateway ? 1 : length(var.public_subnets)
  domain = "vpc"
  tags   = merge(local.common_tags, { Name = "${var.name}-nat-eip-${count.index + 1}" })
}

resource "aws_nat_gateway" "this" {
  count         = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.public_subnets)) : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(local.common_tags, { Name = "${var.name}-nat-${count.index + 1}" })
  depends_on    = [aws_internet_gateway.this]
}

# Route tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = merge(local.common_tags, { Name = "${var.name}-public-rt" })
}

resource "aws_route_table" "private" {
  count  = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(var.private_subnets)) : 1
  vpc_id = aws_vpc.this.id
  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = var.single_nat_gateway ? aws_nat_gateway.this[0].id : aws_nat_gateway.this[count.index].id
    }
  }
  tags = merge(local.common_tags, { Name = "${var.name}-private-rt-${count.index + 1}" })
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = var.single_nat_gateway ? aws_route_table.private[0].id : aws_route_table.private[count.index].id
}

# VPC Endpoints (S3, ECR — avoid NAT costs for container pulls)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(aws_route_table.private[*].id, [aws_route_table.public.id])
  tags              = merge(local.common_tags, { Name = "${var.name}-s3-endpoint" })
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
  tags                = merge(local.common_tags, { Name = "${var.name}-ecr-api-endpoint" })
}

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${var.name}-vpc-endpoints-"
  vpc_id      = aws_vpc.this.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.cidr]
  }
  tags = merge(local.common_tags, { Name = "${var.name}-vpc-endpoints-sg" })
}

data "aws_region" "current" {}

output "vpc_id"                { value = aws_vpc.this.id }
output "public_subnet_ids"     { value = aws_subnet.public[*].id }
output "private_subnet_ids"    { value = aws_subnet.private[*].id }
output "database_subnet_ids"   { value = aws_subnet.database[*].id }
output "db_subnet_group_name"  { value = aws_db_subnet_group.this.name }
output "cache_subnet_group"    { value = aws_elasticache_subnet_group.this.name }
output "nat_gateway_ips"       { value = aws_eip.nat[*].public_ip }
