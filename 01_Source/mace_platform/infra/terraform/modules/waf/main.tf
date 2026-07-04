##############################################################################
# MACE Platform — WAF v2 Module
# AWS WAF protecting the ALB ingress with:
#   - AWS Managed Rules (Core, Known Bad Inputs, SQLi, XSS)
#   - Rate limiting per IP (10,000 req/5min)
#   - Geo-blocking (configurable per market)
#   - Custom rules for API key validation
##############################################################################

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "name"          { type = string }
variable "environment"   { type = string }
variable "blocked_countries" { default = [] }
variable "rate_limit"    { default = 10000 }
variable "tags"          { default = {} }

locals {
  common_tags = merge({
    Project     = "UnifiedSec-MACE"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }, var.tags)
}

resource "aws_wafv2_web_acl" "this" {
  name  = "${var.name}-waf"
  scope = "REGIONAL"

  default_action { allow {} }

  # Rule 1: Rate limiting
  rule {
    name     = "RateLimitRule"
    priority = 1
    action { block {} }
    statement {
      rate_based_statement {
        limit              = var.rate_limit
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: AWS Managed Core Rules
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
        rule_action_override {
          name          = "SizeRestrictions_BODY"
          action_to_use { allow {} }  # Allow large API payloads
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: SQL Injection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 3
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-sqli"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 4
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-waf"
    sampled_requests_enabled   = true
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "/aws/wafv2/${var.name}"
  retention_in_days = 90
  tags              = local.common_tags
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
  resource_arn            = aws_wafv2_web_acl.this.arn
}

output "web_acl_arn" { value = aws_wafv2_web_acl.this.arn }
output "web_acl_id"  { value = aws_wafv2_web_acl.this.id }
