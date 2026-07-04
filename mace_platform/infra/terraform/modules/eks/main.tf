##############################################################################
# MACE Platform — EKS Module
# Managed Kubernetes with:
#   - Managed node groups (spot + on-demand mix for cost savings)
#   - IRSA (IAM Roles for Service Accounts) for pod-level AWS permissions
#   - aws-load-balancer-controller for ALB ingress
#   - cluster-autoscaler for automatic scaling
#   - OIDC provider for secure secret access
##############################################################################

terraform {
  required_providers {
    aws       = { source = "hashicorp/aws",       version = "~> 5.0" }
    tls       = { source = "hashicorp/tls",       version = "~> 4.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.0" }
  }
}

variable "cluster_name"      { type = string }
variable "cluster_version"   { default = "1.29" }
variable "vpc_id"            { type = string }
variable "subnet_ids"        { type = list(string) }
variable "environment"       { type = string }
variable "region"            { type = string }
variable "node_instance_types" { default = ["m5.xlarge", "m5a.xlarge"] }
variable "node_min_size"     { default = 2 }
variable "node_max_size"     { default = 10 }
variable "node_desired_size" { default = 3 }
variable "enable_spot"       { default = true }
variable "tags"              { default = {} }

locals {
  common_tags = merge({
    Project     = "UnifiedSec-MACE"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }, var.tags)
}

# EKS Cluster IAM Role
resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "cluster_vpc_resource" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}

# Security group for EKS cluster
resource "aws_security_group" "cluster" {
  name_prefix = "${var.cluster_name}-cluster-"
  vpc_id      = var.vpc_id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.common_tags, { Name = "${var.cluster_name}-cluster-sg" })
}

# EKS Cluster
resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = var.cluster_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]  # Restrict to office IPs in production
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks.arn
    }
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  tags = local.common_tags
  depends_on = [
    aws_iam_role_policy_attachment.cluster_policy,
    aws_iam_role_policy_attachment.cluster_vpc_resource,
  ]
}

# KMS key for EKS secrets encryption
resource "aws_kms_key" "eks" {
  description             = "${var.cluster_name} EKS secrets encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  tags                    = local.common_tags
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

# OIDC Provider for IRSA
data "tls_certificate" "eks" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  tags            = local.common_tags
}

# Node Group IAM Role
resource "aws_iam_role" "nodes" {
  name = "${var.cluster_name}-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "nodes_worker"   { policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy";       role = aws_iam_role.nodes.name }
resource "aws_iam_role_policy_attachment" "nodes_cni"      { policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy";             role = aws_iam_role.nodes.name }
resource "aws_iam_role_policy_attachment" "nodes_ecr"      { policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"; role = aws_iam_role.nodes.name }
resource "aws_iam_role_policy_attachment" "nodes_ssm"      { policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore";      role = aws_iam_role.nodes.name }

# On-demand node group (system/critical workloads)
resource "aws_eks_node_group" "on_demand" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-on-demand"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = var.subnet_ids
  instance_types  = var.node_instance_types
  capacity_type   = "ON_DEMAND"

  scaling_config {
    min_size     = var.node_min_size
    max_size     = var.node_max_size
    desired_size = var.node_desired_size
  }

  update_config { max_unavailable = 1 }

  labels = {
    "workload-type" = "on-demand"
    "mace-env"      = var.environment
  }

  taint { key = "dedicated"; value = "system"; effect = "NO_SCHEDULE" }
  tags = local.common_tags
  depends_on = [
    aws_iam_role_policy_attachment.nodes_worker,
    aws_iam_role_policy_attachment.nodes_cni,
    aws_iam_role_policy_attachment.nodes_ecr,
  ]
}

# Spot node group (celery workers — fault-tolerant)
resource "aws_eks_node_group" "spot" {
  count           = var.enable_spot ? 1 : 0
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-spot"
  node_role_arn   = aws_iam_role.nodes.arn
  subnet_ids      = var.subnet_ids
  instance_types  = ["m5.xlarge", "m5a.xlarge", "m4.xlarge", "m5d.xlarge"]
  capacity_type   = "SPOT"

  scaling_config {
    min_size     = 1
    max_size     = 20
    desired_size = 2
  }

  labels = {
    "workload-type" = "spot"
    "mace-env"      = var.environment
  }

  tags = merge(local.common_tags, { "k8s.io/cluster-autoscaler/enabled" = "true" })
  depends_on = [aws_iam_role_policy_attachment.nodes_worker]
}

# IRSA for cluster-autoscaler
resource "aws_iam_role" "cluster_autoscaler" {
  name = "${var.cluster_name}-cluster-autoscaler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
      Condition = {
        StringEquals = {
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:cluster-autoscaler"
          "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy" "cluster_autoscaler" {
  name = "cluster-autoscaler"
  role = aws_iam_role.cluster_autoscaler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = [
        "autoscaling:DescribeAutoScalingGroups", "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:DescribeLaunchConfigurations", "autoscaling:DescribeTags",
        "autoscaling:SetDesiredCapacity", "autoscaling:TerminateInstanceInAutoScalingGroup",
        "ec2:DescribeLaunchTemplateVersions"
      ]
      Resource = "*"
    }]
  })
}

output "cluster_name"               { value = aws_eks_cluster.this.name }
output "cluster_endpoint"           { value = aws_eks_cluster.this.endpoint }
output "cluster_ca_certificate"     { value = aws_eks_cluster.this.certificate_authority[0].data }
output "cluster_oidc_issuer_url"    { value = aws_eks_cluster.this.identity[0].oidc[0].issuer }
output "oidc_provider_arn"          { value = aws_iam_openid_connect_provider.eks.arn }
output "node_role_arn"              { value = aws_iam_role.nodes.arn }
output "cluster_autoscaler_role_arn" { value = aws_iam_role.cluster_autoscaler.arn }
