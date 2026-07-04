##############################################################################
# MACE Platform — RDS PostgreSQL Module
# Multi-AZ Aurora PostgreSQL with:
#   - Encryption at rest (KMS), TLS in-transit
#   - Automated backups + PITR
#   - Performance Insights enabled
#   - Data residency tags for compliance (GDPR, DPDP, NESA)
##############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "identifier"           { type = string }
variable "vpc_id"               { type = string }
variable "db_subnet_group_name" { type = string }
variable "allowed_security_groups" { type = list(string) }
variable "db_name"              { default = "mace_platform" }
variable "db_username"          { default = "mace" }
variable "db_password"          { type = string; sensitive = true }
variable "engine_version"       { default = "15.4" }
variable "instance_class"       { default = "db.r6g.large" }
variable "allocated_storage"    { default = 100 }
variable "max_storage"          { default = 500 }
variable "multi_az"             { default = true }
variable "deletion_protection"  { default = true }
variable "backup_retention"     { default = 7 }
variable "environment"          { type = string }
variable "jurisdiction"         { default = "US" }
variable "tags"                 { default = {} }

locals {
  common_tags = merge({
    Project              = "UnifiedSec-MACE"
    Environment          = var.environment
    ManagedBy            = "Terraform"
    DataResidency        = var.jurisdiction
    DataClassification   = "Confidential"
    ComplianceFrameworks = "SOC2,FedRAMP,GDPR"
  }, var.tags)
}

resource "aws_kms_key" "rds" {
  description             = "${var.identifier} RDS encryption key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.identifier}-rds-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.identifier}-rds-sg" })
}

resource "aws_db_parameter_group" "this" {
  name_prefix = "${var.identifier}-"
  family      = "postgres15"

  parameter {
    name  = "log_statement"
    value = "ddl"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"  # Log queries > 1s
  }
  parameter {
    name  = "ssl"
    value = "1"
  }
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = local.common_tags
}

resource "aws_db_instance" "this" {
  identifier     = var.identifier
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn

  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.this.name

  multi_az               = var.multi_az
  publicly_accessible    = false
  deletion_protection    = var.deletion_protection

  backup_retention_period   = var.backup_retention
  backup_window             = "03:00-04:00"
  maintenance_window        = "Mon:04:00-Mon:05:00"
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot     = true

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = aws_kms_key.rds.arn

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  skip_final_snapshot = false
  final_snapshot_identifier = "${var.identifier}-final-snapshot"

  tags = local.common_tags
}

resource "aws_iam_role" "rds_monitoring" {
  name = "${var.identifier}-rds-monitoring"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  role       = aws_iam_role.rds_monitoring.name
}

output "endpoint"       { value = aws_db_instance.this.endpoint }
output "port"           { value = aws_db_instance.this.port }
output "db_name"        { value = aws_db_instance.this.db_name }
output "security_group" { value = aws_security_group.rds.id }
output "kms_key_arn"    { value = aws_kms_key.rds.arn }
