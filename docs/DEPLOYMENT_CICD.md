# MACE — CI/CD Deploy to AWS (Docker → ECR → EKS)

The workflow `.github/workflows/deploy-aws.yml` builds MACE's container images,
pushes them to **Amazon ECR**, and rolls them out to **EKS** with Helm — on every
push to `main` (code changes) or manually from the Actions tab.

## What it does
1. Builds `mace-api` (backend), `soc-frontend`, `admin-frontend` images.
2. Creates the ECR repos if missing, pushes images tagged with the commit SHA + `latest`.
3. `helm upgrade --install` each chart onto your EKS cluster with the new image.

## One-time setup (what to configure)

Auth uses **GitHub OIDC** — no long-lived AWS keys stored in GitHub.

### 1. AWS side (I can generate the Terraform if you want)
- An **OIDC provider** for `token.actions.githubusercontent.com`.
- An **IAM role** the workflow assumes, trusting your repo
  (`repo:viveksindhu-unifiedsectech/MACE:*`), with permissions for **ECR push**,
  **EKS describe**, and deploy rights (mapped into the cluster's `aws-auth` /
  an EKS access entry).
- An **EKS cluster** (the Terraform in `mace_platform/infra/terraform/modules/eks`).

### 2. GitHub side — set these in the repo (Settings → Secrets and variables → Actions)

| Kind | Name | Example |
|---|---|---|
| **Secret** | `AWS_DEPLOY_ROLE_ARN` | `arn:aws:iam::123456789:role/mace-github-deploy` |
| Variable | `AWS_REGION` | `us-east-1` |
| Variable | `ECR_REGISTRY` | `123456789.dkr.ecr.us-east-1.amazonaws.com` |
| Variable | `EKS_CLUSTER_NAME` | `mace-prod` |
| Variable | `K8S_NAMESPACE` | `mace` |

### 3. Land the workflow file itself
GitHub only accepts `.github/workflows/*` from a token with **`workflow`** scope.
Add it once via the GitHub web UI (**Add file → Create new file →**
`.github/workflows/deploy-aws.yml`), or push with a workflow-scoped token.

## What I need from you to wire this up end-to-end
- Confirm you want me to generate the **OIDC + IAM role Terraform** (I'll produce it).
- The **EKS cluster name + region** once it exists (or say "create it" and I'll
  add the cluster Terraform).
- Then set the 4 variables + 1 secret above, and the first push to `main` deploys.

Until EKS exists, you can still run everything locally with `docker compose up`
(see the root README) — same images, same code.
