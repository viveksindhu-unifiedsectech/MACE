# MACE — AWS Infrastructure Setup Guide
**For Vivek Sindhu · UnifiedSec Technologies · 2026-05-28**

This is the **exact shopping list** of AWS resources to stand up the
MACE management plane, plus the step-by-step on how to create each one
yourself (Claude cannot create them for you because it would need your
billing info + identity verification with Amazon).

Total monthly cost when running 24/7: **~$65/month** for the minimum
config below; **~$280/month** for the recommended production config.

---

## 1. AWS account preparation (one-time, ~30 min)

1. Go to https://aws.amazon.com → "Create an AWS Account".
2. Sign up with a corporate email (e.g. `aws-billing@unifiedsec.io`),
   not a personal Gmail.
3. Provide a credit card + phone-verify.
4. Choose **Business** support — Basic is free, Developer is $29/month
   (worth it for response times once you have customers).
5. Enable **MFA on the root user** immediately (Settings → Security
   credentials → Multi-factor authentication). Use a hardware key
   (YubiKey 5C, $50) if you can.
6. Create an **IAM user** for daily use:
   - Name: `vivek-admin`
   - Group: `Administrators` (attach `AdministratorAccess` managed policy)
   - Enable MFA on this user too.
   - Never use the root account after this.
7. **Lock down billing**:
   - Billing → Preferences → enable "Receive PDF invoice by email" + cost alerts.
   - Create a CloudWatch billing alarm at $100, $250, $500.

**Cost protection**: set a hard spending cap by enabling AWS Budgets.

---

## 2. CLI bootstrap on your laptop

```bash
# 1. Install AWS CLI v2
brew install awscli      # macOS
# or:  https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

# 2. Create an access key for vivek-admin in IAM
#    IAM → Users → vivek-admin → Security credentials → Create access key → CLI
# 3. Configure:
aws configure
#    AWS Access Key ID:     <paste>
#    AWS Secret Access Key: <paste>
#    Default region:        us-east-1
#    Default output format: json

# 4. Verify
aws sts get-caller-identity
#    → returns your account ID
```

---

## 3. What the bootstrap script provisions

When you run `python -m mace_platform.agent.cloud.bootstrap --apply` it
creates the resources below. You can also create them manually in the
AWS console using the values to the right — the bootstrap is just a
convenience wrapper.

### 3.1 VPC + networking
| Resource | Value | Console path |
|---|---|---|
| VPC          | CIDR 10.55.0.0/16          | VPC → Your VPCs → Create |
| Subnet A     | 10.55.1.0/24 in us-east-1a | VPC → Subnets → Create  |
| Subnet B     | 10.55.2.0/24 in us-east-1b | VPC → Subnets → Create  |
| Internet GW  | attach to VPC              | VPC → Internet Gateways |
| Route table  | 0.0.0.0/0 → IGW            | VPC → Route Tables      |

### 3.2 Security group
| Port | Protocol | Source | Use |
|---|---|---|---|
| 22   | TCP | Your-IP/32 only (NOT 0.0.0.0/0) | Admin SSH |
| 80   | TCP | 0.0.0.0/0 | Public HTTP (redirects to 443) |
| 443  | TCP | 0.0.0.0/0 | Public HTTPS (dashboard + Macey) |
| 8765 | TCP | 0.0.0.0/0 | Agent ingest API |
| 5432 | TCP | sg-self    | RDS access from EC2 only |

### 3.3 EC2 instance (the control-plane host)
| Setting | Minimum | Recommended |
|---|---|---|
| Instance type | `t3.medium` ($0.0416/h) | `t3.large` ($0.0832/h) |
| AMI           | Ubuntu 22.04 LTS HVM | Same |
| EBS root      | 30 GB gp3 ($2.40/mo) | 100 GB gp3 ($8/mo) |
| Auto-recovery | Enable               | Enable |
| User data     | Cloud-init from `cloud/aws_provision.py` | Same |

The cloud-init installs Docker, Python, the MACE API service, nginx, then
boots the ingest API on :8765 + dashboard on :80/:443.

### 3.4 RDS PostgreSQL
| Setting | Minimum | Recommended |
|---|---|---|
| Engine        | PostgreSQL 16 | PostgreSQL 16 |
| Instance class| `db.t4g.micro` ($0.016/h) | `db.t4g.small` ($0.032/h) |
| Storage       | 20 GB gp3 ($2.30/mo)      | 100 GB gp3 ($11.50/mo) |
| Multi-AZ      | No                        | Yes (~2× cost) |
| Backups       | 7 days retention          | 30 days retention |
| Encryption    | KMS (AWS-managed)         | KMS (customer-managed key) |
| Username      | `mace_admin` | Same |
| Password      | from `~/.mace-agent/admin.credentials.json` (db_password field) | Same |

### 3.5 S3 evidence bucket
| Setting | Value |
|---|---|
| Bucket name | `mace-evidence-<account-id>-<region>` |
| Versioning  | Enabled |
| Encryption  | SSE-S3 (AES-256) — upgrade to SSE-KMS at scale |
| Public access block | All four switches on |
| Lifecycle   | Transition to Glacier after 90 days, expire after 7 years |
| Object lock | Compliance mode (required for UREA chain-of-custody) |

### 3.6 KMS keys
- One symmetric KMS key per customer tenant (used by RDS + S3 SSE-KMS).
- Enable automatic annual rotation.

### 3.7 Route 53 + ACM (optional, recommended)
| Resource | Value |
|---|---|
| Hosted zone | `unifiedsec.io` (already owned, see GTM playbook §7) |
| A record    | `mace.unifiedsec.io` → EC2 Elastic IP |
| ACM cert    | DNS-validated cert for `mace.unifiedsec.io` |
| ALB         | optional but recommended at scale |

### 3.8 IAM roles
- `mace-ec2-role` attached to the EC2 instance with policies:
  - `AmazonSSMManagedInstanceCore`
  - inline policy: `s3:PutObject`, `s3:GetObject` on the evidence bucket
  - inline policy: `secretsmanager:GetSecretValue` for the DB password
- `mace-agent-write` for endpoint agents authenticating to the ingest
  API via API-key (the api_key in `admin.credentials.json`).

### 3.9 Secrets Manager
- Store the DB password + Macey API key + admin password from
  `~/.mace-agent/admin.credentials.json` in Secrets Manager.
- Reference them from the EC2 user-data via SSM Parameter Store ARNs.

### 3.10 CloudWatch
- Log group `/aws/mace/api` for the API server stdout.
- Log group `/aws/mace/agent-ingest` for ingest events.
- Dashboard with: API 5xx count, ingest rate, RDS CPU, RDS connections,
  EC2 CPU, S3 evidence-bucket size.

---

## 4. Cost summary

| Component | Min config | Recommended | Notes |
|---|---|---|---|
| EC2 t3.medium       | $30/mo  | $60/mo (t3.large) | |
| EBS 30 GB gp3       | $2.40   | $8 (100 GB)       | |
| RDS db.t4g.micro    | $11.50  | $23 (small)       | |
| RDS 20 GB gp3       | $2.30   | $11.50 (100 GB)   | |
| S3 evidence storage | $0.50   | $5 (200 GB)       | |
| Route 53            | $0.50   | $0.50             | |
| KMS                 | $1      | $3                | per-tenant keys |
| Data transfer       | $5      | $20               | |
| CloudWatch          | $5      | $15               | |
| **Total**           | **≈ $58/mo** | **≈ $145/mo**   | |

For investor demos: stick to the minimum. Tear down with
`bootstrap.py --destroy` between sessions to keep cost under $5/mo.

---

## 5. Where each set of secrets lives

| Secret | Where Claude generated it | Where it goes in AWS |
|---|---|---|
| Admin username    | `~/.mace-agent/admin.credentials.json` → `admin_username` | Dashboard login + IAM tag |
| Admin password    | same → `admin_password`    | bcrypt-hashed in RDS users table |
| DB password       | same → `db_password`       | RDS `master_user_password` + Secrets Manager |
| API secret key    | same → `api_secret_key`    | EC2 env `MACE_API_SECRET_KEY` |
| Macey API key     | same → `macey_api_key`     | EC2 env `MACE_MACEY_API_KEY` |
| S3 signing key    | same → `s3_signing_key`    | EC2 env `MACE_S3_SIGNING_KEY` |

The credentials JSON is `chmod 0600`. Move it into 1Password / Bitwarden
once you confirm everything works; don't leave a flat-file secret on
your laptop long-term.

---

## 6. Hardening checklist (do this before customers see it)

- [ ] **Move from EC2-only to Application Load Balancer + auto-scaling group**
  so you can survive instance loss without intervention.
- [ ] **Enable GuardDuty** ($3.50/account/month) — AWS-native threat detection
  on the management-plane account.
- [ ] **Enable CloudTrail** (free for one trail) — every API call is logged
  to a separate immutable S3 bucket.
- [ ] **Enable AWS Config** — drift detection on every resource.
- [ ] **Enable Inspector** — automatic CVE scans of EC2 (eats your own dog food).
- [ ] **WAF** in front of ALB — block scrapers + bots before they hit
  the dashboard.
- [ ] **Shield Standard** is free; **Shield Advanced** ($3k/month) only
  once you have F500 customers.
- [ ] **Backups**: AWS Backup Vault for RDS + EBS snapshots; test
  restore once a month.
- [ ] **SOC 2 evidence trail**: AWS Audit Manager pulls evidence
  automatically for the auditor.

---

## 7. Multi-region (for India / UAE customers)

Once you sign customers in those jurisdictions, replicate this stack in:
- **ap-south-1 (Mumbai)** — data-residency for India DPDP + CERT-In.
- **me-central-1 (UAE)** — data-residency for UAE NESA.
- **eu-west-1 (Ireland)** — GDPR Article 32 + EU-data-stays-in-EU.
- **us-gov-west-1** — required for FedRAMP Moderate + DoD CMMC L2/L3.

The Terraform modules in `mace_platform/infra/terraform/environments/`
already cover these regions; copy the example/ directory, set vars per
region, run `terraform apply`.

---

## 8. Why I'm doing it this way and not "just create it for me"

I (Claude) cannot create an AWS account on your behalf because:

1. AWS will not accept account creation without identity-verification of
   the signer (i.e. you).
2. The credit card on file must be yours.
3. AWS Root user MFA must be tied to a physical device under your
   control.
4. The IRS / India GST / VAT relationship is between AWS and your
   *company*, not a third party.

What I have done:
- Generated all of the admin credentials you need.
- Written the exact CLI + bootstrap that, when you run it with your
  access keys configured, creates everything in a single command.
- Provided a manual fallback (this document) so you can do it through
  the console if you prefer.

---

## 8.5 Everything else you need (beyond AWS core)

The list below is your **full third-party + SaaS shopping cart** to run
MACE as a real company. Each entry has the role it fills, a recommended
vendor (and a free alternative), and the realistic monthly cost.

### A. Data + storage + observability

| Need | Why | Recommended | Free alt | Cost |
|---|---|---|---|---|
| Object storage for evidence | UREA chain-of-custody | AWS S3 + Object Lock | MinIO self-host | $0.023 / GB-month |
| Time-series telemetry | Per-agent metrics | AWS Timestream | Prometheus + Thanos | $25-50/mo |
| Log aggregation | Daemon + audit logs | **Splunk Cloud Platform** Workload Pricing | Loki + Grafana | $1,800/mo @ 25 GB/day |
| SIEM | Customer-facing log search | Splunk ES *(or)* Microsoft Sentinel | Wazuh (open source) | Splunk ES adds $4k/mo |
| Distributed tracing | API latency + Macey calls | Datadog APM | OpenTelemetry + Jaeger | $31/host/mo |
| Error tracking | App-level bugs | Sentry | Self-hosted Sentry | $26/mo (10k events) |
| Uptime monitoring | Public probes | UptimeRobot Pro / BetterStack | Self-hosted Healthchecks | $9/mo |
| Cost monitoring | AWS spend | Vantage / CloudHealth | AWS Cost Explorer | $0 to start |

### B. Identity & access

| Need | Recommended | Cost |
|---|---|---|
| Workforce SSO | Okta Workforce Identity (Workforce $2/user/mo) or Microsoft Entra ID ($6/user) | $2-6/user |
| Customer SSO  | Auth0 (now Okta) — B2B Essentials ($240/mo for 500 MAU) | $240/mo+ |
| MFA           | Bundled in Okta / Entra; otherwise Duo Security ($3/user) | $3/user |
| Secret manager| AWS Secrets Manager ($0.40/secret/mo) + 1Password Business ($8/user) | low |
| PKI / code signing | DigiCert KeyLocker + ACM private CA | $300/mo+ |

### C. Messaging, comms, customer-facing

| Need | Recommended | Cost |
|---|---|---|
| Transactional email | AWS SES ($0.10 per 1k emails) or Postmark ($15/mo) | $15/mo |
| Operational chat    | Slack Business+ ($15/user/mo) | $30-150/mo small team |
| Customer chat / docs | Intercom Starter ($74/mo) or Plain | $74/mo |
| Status page         | Statuspage by Atlassian ($29/mo) | $29/mo |
| Phone / SMS         | Twilio (pay-as-you-go) | $20-50/mo |
| Calendar booking    | Calendly Teams ($16/user) | $16/user |

### D. Sales + CRM

| Need | Recommended | Cost |
|---|---|---|
| CRM         | HubSpot Sales Hub Pro ($90/user/mo) or Pipedrive | $90/user |
| Outreach    | Apollo.io Basic ($49/user) or Outreach.io | $49/user |
| LinkedIn    | Sales Navigator Core ($99/user) | $99/user |
| Lead enrichment | ZoomInfo (call for pricing) or LeadIQ | $500-2k/mo |

### E. Finance + ops

| Need | Recommended | Cost |
|---|---|---|
| Bank        | Mercury or Brex | free with deposits |
| Bookkeeping | Pilot.com ($499/mo) | $499/mo |
| Tax + state filings | Anrok (sales tax) + Burkland | $200-600/mo |
| Equity mgmt | Carta Launch ($0 < $10M raised, then $2-6k/year) | $0-500/mo |
| Insurance — E&O / Cyber | Vouch or Embroker | $250-600/mo |
| Insurance — D&O | Vouch | $200-400/mo |
| Payroll / HR | Gusto Plus ($80/mo + $12/employee) or Deel for international | $200-400/mo |
| Stripe / billing | Stripe Standard 2.9% + 30¢ per transaction | usage-based |

### F. Development infrastructure

| Need | Recommended | Cost |
|---|---|---|
| Source control     | GitHub Team ($4/user) → Enterprise once 5+ engineers | $4-21/user |
| CI/CD              | GitHub Actions (2,000 free min) → AWS CodeBuild for bigger jobs | low |
| Container registry | Amazon ECR ($0.10 / GB) | low |
| Secrets in CI      | GitHub Actions secrets + OIDC role on AWS | free |
| Vulnerability scanning of your *own* code | Snyk Team ($25/dev/mo) or Semgrep Cloud | $25/dev |
| Pre-prod cluster   | AWS EKS ($73/mo per cluster) | $73/mo |
| Container security | AWS Inspector (built-in) | low |

### G. Compliance + audit tooling

| Need | Recommended | Cost |
|---|---|---|
| Continuous-controls automation | Drata Foundation ($7,500/year) or Vanta Core ($14k/year) | $7-14k/yr |
| Pen-test (annual) | NetSPI / Cobalt.io | $20-40k once |
| SOC 2 Type II auditor | Insight Assurance, Prescient Assurance, Strike Graph audit | $20-40k Year 1 |
| ISO 27001 auditor | A-LIGN or Schellman | $25-50k Year 1 |
| FedRAMP 3PAO | Schellman or Coalfire | $250-500k (don't pay until you have a federal sponsor) |

### H. Threat intelligence (paid feeds you should consider)

| Vendor | Tier | Why |
|---|---|---|
| **Recorded Future** Threat Intelligence Cloud | Enterprise ($60k/year) | broadest commercial dataset |
| **Mandiant Advantage** | Threat Intelligence Sub ($45k/year) | nation-state focus |
| **Anomali ThreatStream** | Enterprise | aggregator of aggregators |
| **Flashpoint** | Intelligence | deep + dark web |
| **DomainTools Iris** | Investigator | passive DNS + WHOIS |

For pre-revenue: **stick to the free feeds** (CISA KEV, abuse.ch, OTX,
MISP). Add a commercial feed only when one of your design partners
asks "where does your IOC list come from?".

### I. Marketing + brand

| Need | Recommended | Cost |
|---|---|---|
| Domain registrar | Cloudflare Registrar | wholesale ($9/yr per .io) |
| DNS + CDN        | Cloudflare Pro ($25/mo) | $25/mo |
| Website host     | Vercel Hobby (free) → Pro ($20/mo) | $20/mo |
| Landing-page kit | Framer / Webflow ($30/mo) | $30/mo |
| Logo + design    | Fiverr Pro one-time | $500 |
| Analytics        | Plausible Analytics ($9/mo) (privacy-first) | $9/mo |
| Email marketing  | Loops.so or Customer.io | $50-150/mo |

### J. Recommended Day-0 monthly run-rate (pre-funding)

| Category | Monthly |
|---|---|
| AWS minimum            | $58  |
| Domain + DNS + email   | $20  |
| GitHub Team (1 user)   | $4   |
| Pilot bookkeeping      | $499 |
| HubSpot Free + LI Sales Navigator | $99 |
| Stripe / Mercury / Carta Launch | $0 |
| Cloudflare Pro         | $25  |
| Slack Business+        | $15  |
| Vouch E&O insurance    | $250 |
| Vanta Essentials       | $580 (or skip until raise) |
| **Total**              | **≈ $1,550/month** |

### K. Day-0 monthly run-rate post $5M raise

| Category | Monthly |
|---|---|
| Cloud (multi-region) | $1,400 |
| Splunk Cloud         | $1,800 |
| Threat-intel feeds   | $5,000 |
| Compliance automation (Drata / Vanta full tier) | $1,200 |
| Salaries (8 FTE incl. founder) | ~$80,000 |
| HubSpot Pro + LinkedIn + Apollo | $1,500 |
| Insurance (E&O + cyber + D&O) | $1,000 |
| Office co-working WeWork x 4 desks | $1,000 |
| Misc software stack             | $1,500 |
| **Total**            | **≈ $94k/mo (= $1.13M/yr burn)** |

That leaves $3.8M of an $5M raise for sales/marketing experiments,
travel, conferences, legal, and contingency — i.e. enough to run for
~3 years if you keep burn at the recommended pace.

---

## 9. Pre-flight checklist (do this before bootstrap --apply)

- [ ] AWS account created, MFA on root + IAM user.
- [ ] `aws configure` set with vivek-admin keys, region `us-east-1`.
- [ ] `aws sts get-caller-identity` returns your account ID.
- [ ] `pip install boto3` succeeds.
- [ ] `~/.mace-agent/admin.credentials.json` exists (created by the
      bootstrap dry-run).
- [ ] You've decided on a domain (`mace.unifiedsec.io`) and have
      bought the .io registration if not already.
- [ ] You understand the ~$65/month ongoing cost and have a budget
      alert set at $100.

Once all boxes are checked, run:

```bash
python -m mace_platform.agent.cloud.bootstrap --apply --region us-east-1 --admin-cidr <your-public-ip>/32
```

…and the entire stack will be live in 4-6 minutes.

— UnifiedSec Technologies · 2026-05-28
