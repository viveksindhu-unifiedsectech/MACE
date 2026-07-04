##############################################################################
# MACE Secure Files — KMS + S3 + least-privilege IAM
#
# Provisions the cloud-security backbone for the Secure Files feature:
#   * a dedicated KMS key that wraps every per-file data key (envelope crypto)
#   * a hardened S3 bucket (block-public, SSE-KMS, versioning) for ciphertext
#   * an IAM policy granting the MACE app ONLY the KMS+S3 actions it needs
#
# Wire the outputs into the app as:
#   MACE_KMS_ENABLED=true
#   MACE_KMS_KEY_ID   = <kms_key_arn output>
#   S3_BUCKET         = <bucket_name output>
##############################################################################
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "name_prefix"   { type = string  default = "mace" }
variable "environment"   { type = string  default = "prod" }
variable "jurisdiction"  { type = string  default = "US" }
variable "account_id"    { type = string }
variable "app_role_arn"  { type = string  description = "IAM role/user ARN the MACE app runs as" }
variable "tags"          { type = map(string) default = {} }

locals {
  common_tags = merge({
    Project = "UnifiedSec-MACE", Feature = "SecureFiles",
    Environment = var.environment, ManagedBy = "Terraform",
    DataResidency = var.jurisdiction, DataClassification = "Restricted"
  }, var.tags)
}

# ── KMS key that wraps per-file data encryption keys ────────────────────────
resource "aws_kms_key" "files" {
  description             = "MACE Secure Files — envelope key wrapping (${var.environment})"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

resource "aws_kms_alias" "files" {
  name          = "alias/${var.name_prefix}-files-${var.environment}"
  target_key_id = aws_kms_key.files.key_id
}

# ── S3 bucket for encrypted file blobs ──────────────────────────────────────
resource "aws_s3_bucket" "files" {
  bucket = "${var.name_prefix}-secure-files-${var.environment}-${var.account_id}"
  tags   = merge(local.common_tags, { Purpose = "Encrypted file objects" })
}

resource "aws_s3_bucket_versioning" "files" {
  bucket = aws_s3_bucket.files.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "files" {
  bucket = aws_s3_bucket.files.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.files.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "files" {
  bucket                  = aws_s3_bucket.files.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enforce TLS-only + KMS-only writes.
resource "aws_s3_bucket_policy" "files" {
  bucket = aws_s3_bucket.files.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "DenyInsecureTransport", Effect = "Deny", Principal = "*",
        Action = "s3:*", Resource = [aws_s3_bucket.files.arn, "${aws_s3_bucket.files.arn}/*"],
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid = "DenyUnEncryptedPuts", Effect = "Deny", Principal = "*",
        Action = "s3:PutObject", Resource = "${aws_s3_bucket.files.arn}/*",
        Condition = { StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
      }
    ]
  })
}

# ── Least-privilege IAM policy for the MACE app ─────────────────────────────
resource "aws_iam_policy" "secure_files" {
  name   = "${var.name_prefix}-secure-files-${var.environment}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "FileObjectAccess", Effect = "Allow",
        Action = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:ListBucket"],
        Resource = [aws_s3_bucket.files.arn, "${aws_s3_bucket.files.arn}/*"]
      },
      {
        Sid = "EnvelopeKeyWrap", Effect = "Allow",
        Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
        Resource = aws_kms_key.files.arn
      }
    ]
  })
  tags = local.common_tags
}

output "kms_key_arn"    { value = aws_kms_key.files.arn }
output "kms_key_alias"  { value = aws_kms_alias.files.name }
output "bucket_name"    { value = aws_s3_bucket.files.id }
output "iam_policy_arn" { value = aws_iam_policy.secure_files.arn }
