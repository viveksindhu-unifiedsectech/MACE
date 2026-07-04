##############################################################################
# MACE Platform — ElastiCache Redis Module
# Redis cluster for: JWT cache, rate limiting, Celery broker, pub/sub
# Cluster mode disabled (single shard) — adequate for MACE workloads.
# Auth token + TLS enforced.
##############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "name"                     { type = string }
variable "vpc_id"                   { type = string }
variable "cache_subnet_group_name"  { type = string }
variable "allowed_security_groups"  { type = list(string) }
variable "node_type"                { default = "cache.r7g.large" }
variable "num_cache_nodes"          { default = 2 }
variable "auth_token"               { type = string; sensitive = true }
variable "environment"              { type = string }
variable "tags"                     { default = {} }

locals {
  common_tags = merge({
    Project     = "UnifiedSec-MACE"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }, var.tags)
}

resource "aws_kms_key" "redis" {
  description             = "${var.name} Redis encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_security_group" "redis" {
  name_prefix = "${var.name}-redis-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
  }

  tags = merge(local.common_tags, { Name = "${var.name}-redis-sg" })
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = var.name
  description          = "MACE Platform Redis — ${var.environment}"

  node_type            = var.node_type
  num_cache_clusters   = var.num_cache_nodes
  port                 = 6379

  subnet_group_name    = var.cache_subnet_group_name
  security_group_ids   = [aws_security_group.redis.id]

  auth_token                = var.auth_token
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.redis.arn

  automatic_failover_enabled = var.num_cache_nodes > 1
  multi_az_enabled           = var.num_cache_nodes > 1

  snapshot_retention_limit = 3
  snapshot_window          = "03:00-04:00"
  maintenance_window       = "Mon:04:00-Mon:05:00"

  parameter_group_name = "default.redis7"
  engine_version       = "7.0"

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "redis" {
  name              = "/mace/${var.environment}/redis"
  retention_in_days = 30
  tags              = local.common_tags
}

output "primary_endpoint" { value = aws_elasticache_replication_group.this.primary_endpoint_address }
output "port"             { value = 6379 }
output "security_group"   { value = aws_security_group.redis.id }
