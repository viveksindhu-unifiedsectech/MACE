##############################################################################
# MACE Platform - S3 Evidence Storage Module
# Encrypted, versioned, deny-delete evidence bucket for regulatory records.
##############################################################################
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
variable "bucket_prefix"     { type = string }
variable "environment"       { type = string }
variable "jurisdiction"      { default = "US" }
variable "account_id"        { type = string }
variable "kms_key_arn"       { type = string }
variable "retention_years"   { default = 7 }
variable "tags"              { default = {} }

locals {
  common_tags = merge({
    Project="UnifiedSec-MACE", Environment=var.environment,
    ManagedBy="Terraform", DataResidency=var.jurisdiction,
    DataClassification="Confidential", RetentionYears=tostring(var.retention_years)
  }, var.tags)
  retention_days = var.retention_years * 365
}

resource "aws_s3_bucket" "evidence" {
  bucket = "${var.bucket_prefix}-evidence-${var.environment}-${var.account_id}"
  tags   = merge(local.common_tags, { Purpose = "Regulatory evidence records" })
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
      kms_master_key_id = var.kms_key_arn
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

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id = "evidence-lifecycle"
    status = "Enabled"
    filter { prefix = "" }
    transition { days = 90;  storage_class = "STANDARD_IA" }
    transition { days = 365; storage_class = "GLACIER" }
    expiration { days = local.retention_days }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["${aws_s3_bucket.evidence.arn}", "${aws_s3_bucket.evidence.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyDelete"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource  = "${aws_s3_bucket.evidence.arn}/*"
        Condition = {
          StringNotEquals = { "aws:PrincipalArn" = "arn:aws:iam::${var.account_id}:root" }
        }
      },
    ]
  })
}

resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.bucket_prefix}-evidence-logs-${var.environment}-${var.account_id}"
  tags   = merge(local.common_tags, { Purpose = "S3 access logs" })
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "evidence-access-logs/"
}

output "evidence_bucket_name" { value = aws_s3_bucket.evidence.id }
output "evidence_bucket_arn"  { value = aws_s3_bucket.evidence.arn }
output "logs_bucket_name"     { value = aws_s3_bucket.access_logs.id }
