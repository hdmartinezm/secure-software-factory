# EFEX Secure Software Factory - Production Cost Estimation

## Executive Summary

| Scenario | Monthly Cost | Annual Cost | Notes |
|----------|--------------|-------------|-------|
| **OSS-First (Recommended)** | $850 - $1,200 | $10,200 - $14,400 | Current implementation |
| **Hybrid (OSS + Managed)** | $2,500 - $4,000 | $30,000 - $48,000 | Enhanced features |
| **Full Managed** | $8,000 - $15,000 | $96,000 - $180,000 | Enterprise suite |

**Recommendation:** Start with OSS-First, migrate to Hybrid as team scales beyond 50 engineers.

---

## 1. Current Stack Cost Analysis (OSS-First)

### 1.1 Security Tools - License Costs

| Tool | Type | Cost | Notes |
|------|------|------|-------|
| gitleaks | OSS | **$0** | MIT License |
| Semgrep | OSS (Community) | **$0** | LGPL-2.1 |
| Trivy | OSS | **$0** | Apache-2.0 |
| Checkov | OSS | **$0** | Apache-2.0 |
| Conftest/OPA | OSS | **$0** | Apache-2.0 |
| Syft | OSS | **$0** | Apache-2.0 |
| cosign/Sigstore | OSS | **$0** | Apache-2.0 |
| Hadolint | OSS | **$0** | GPL-3.0 |
| **Subtotal Tools** | | **$0/month** | |

### 1.2 CI/CD Infrastructure - GitHub

| Resource | Tier | Cost | Calculation |
|----------|------|------|-------------|
| GitHub Team | 25 users | $100/month | $4/user/month |
| GitHub Actions | Included minutes | $0 | 3,000 min/month included |
| Actions Overage | ~2,000 min/month | $16/month | $0.008/min Linux |
| Large Runners | Optional | $0 | Not required for current scale |
| **Subtotal GitHub** | | **$116/month** | |

**Actions Minutes Calculation:**
```
Per pipeline run: ~5 minutes (all jobs parallel)
Runs per day: ~30 (5 teams × 6 deploys)
Monthly runs: 900
Monthly minutes: 4,500 minutes
Included: 3,000 minutes
Overage: 1,500 minutes × $0.008 = $12
Buffer (33%): $16/month
```

### 1.3 AWS Infrastructure for Security

| Resource | Configuration | Monthly Cost | Notes |
|----------|---------------|--------------|-------|
| S3 (SARIF/SBOM storage) | 10GB, IA after 30d | $2 | Evidence retention |
| CloudWatch Logs | 50GB ingestion | $25 | Pipeline + app logs |
| KMS | 2 keys, 10K requests | $3 | Encryption keys |
| ECR | 50GB storage | $5 | Container images |
| Secrets Manager | 10 secrets | $4 | API keys, tokens |
| **Subtotal AWS Security** | | **$39/month** | |

### 1.4 Monitoring & Alerting

| Resource | Configuration | Monthly Cost | Notes |
|----------|---------------|--------------|-------|
| GitHub Security Alerts | Included | $0 | Dependabot, code scanning |
| PagerDuty (optional) | Free tier | $0 | 5 users, basic alerts |
| Slack notifications | Free | $0 | Webhook integration |
| **Subtotal Monitoring** | | **$0/month** | |

### 1.5 Personnel Time (Opportunity Cost)

| Activity | Hours/Month | Loaded Rate | Monthly Cost |
|----------|-------------|-------------|--------------|
| Policy maintenance | 8 hrs | $100/hr | $800 |
| False positive triage | 4 hrs | $80/hr | $320 |
| Tool updates | 2 hrs | $80/hr | $160 |
| Incident response | 2 hrs | $100/hr | $200 |
| **Subtotal Personnel** | 16 hrs | | **$1,480/month** |

### 1.6 OSS-First Total

| Category | Monthly | Annual |
|----------|---------|--------|
| Tool Licenses | $0 | $0 |
| GitHub | $116 | $1,392 |
| AWS Security | $39 | $468 |
| Monitoring | $0 | $0 |
| Personnel | $1,480 | $17,760 |
| **Infrastructure Only** | **$155** | **$1,860** |
| **Including Personnel** | **$1,635** | **$19,620** |

---

## 2. Hybrid Stack Cost Analysis (OSS + Managed)

### 2.1 When to Consider Hybrid

| Trigger | Threshold | Recommended Addition |
|---------|-----------|---------------------|
| Team size | >30 engineers | Snyk for prioritization |
| Compliance audit frequency | >2/year | SonarQube for reports |
| Container deployments | >50/day | Harbor for registry |
| Incident response time | >4 hours | PagerDuty Business |

### 2.2 Hybrid Tool Costs

| Tool | Replaces | Cost | Value Add |
|------|----------|------|-----------|
| **Snyk** (Team) | Trivy (SCA only) | $522/month | Fix PRs, priority scores |
| Semgrep (Team) | Semgrep OSS | $400/month | Custom rules UI, metrics |
| GitHub Advanced Security | Multiple | $588/month | Native integration |
| SonarQube Developer | Semgrep (partial) | $150/month | Technical debt, coverage |
| **Subtotal Managed** | | **$1,660/month** | |

### 2.3 Hybrid Total

| Category | Monthly | Annual |
|----------|---------|--------|
| OSS Tools | $0 | $0 |
| Managed Tools | $1,660 | $19,920 |
| GitHub | $116 | $1,392 |
| AWS Security | $50 | $600 |
| Personnel (reduced) | $740 | $8,880 |
| **Total** | **$2,566** | **$30,792** |

**Personnel Reduction:** Managed tools reduce triage and maintenance time by ~50%.

---

## 3. Full Managed Stack Cost Analysis

### 3.1 Enterprise Tool Costs

| Tool | Capability | Monthly Cost | Notes |
|------|------------|--------------|-------|
| **Snyk Enterprise** | SAST+SCA+Container+IaC | $2,500 | Unlimited tests |
| **GitHub Enterprise** | GHAS + Support | $1,575 | $21/user × 75 (growth) |
| **Wiz** or **Orca** | Cloud Security | $3,000 | CSPM + CWPP |
| **HashiCorp Vault** | Secrets (managed) | $1,200 | Enterprise features |
| **Datadog** | Monitoring + SIEM | $2,000 | APM + Security |
| **PagerDuty Business** | Incident management | $500 | 25 users |
| **Subtotal Enterprise** | | **$10,775/month** | |

### 3.2 Full Managed Total

| Category | Monthly | Annual |
|----------|---------|--------|
| Enterprise Tools | $10,775 | $129,300 |
| AWS Security (enhanced) | $200 | $2,400 |
| Personnel (minimal) | $500 | $6,000 |
| **Total** | **$11,475** | **$137,700** |

---

## 4. Detailed Cost Comparison

### 4.1 Cost per Developer per Month

| Scenario | 25 Devs | 50 Devs | 100 Devs |
|----------|---------|---------|----------|
| OSS-First | $6.20 | $3.10 | $1.55 |
| Hybrid | $102.64 | $51.32 | $25.66 |
| Full Managed | $459.00 | $229.50 | $114.75 |

**Note:** OSS-First scales excellently; managed tools have per-seat licensing.

### 4.2 Cost per Pipeline Run

| Scenario | Cost/Run | Runs/Month | Total |
|----------|----------|------------|-------|
| OSS-First | $0.02 | 900 | $18 |
| Hybrid | $0.05 | 900 | $45 |
| Full Managed | $0.15 | 900 | $135 |

### 4.3 Feature Comparison

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        FEATURE COMPARISON BY TIER                          │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  FEATURE                    OSS-FIRST    HYBRID      FULL MANAGED         │
│  ───────────────────────    ─────────    ──────      ────────────         │
│                                                                            │
│  Secret Detection           ✅ gitleaks  ✅ gitleaks  ✅ Snyk/GHAS         │
│  SAST                       ✅ Semgrep   ✅ Semgrep   ✅ Snyk Code         │
│  SCA                        ✅ Trivy     ✅ Snyk      ✅ Snyk              │
│  IaC Scanning               ✅ Checkov   ✅ Checkov   ✅ Snyk IaC          │
│  Container Scanning         ✅ Trivy     ✅ Snyk      ✅ Snyk Container    │
│  SBOM Generation            ✅ Syft      ✅ Syft      ✅ Native            │
│  Artifact Signing           ✅ cosign    ✅ cosign    ✅ Sigstore          │
│                                                                            │
│  Auto-fix PRs               ❌           ✅ Snyk      ✅ Snyk              │
│  Priority Scoring           ⚠️ Manual    ✅ Snyk      ✅ Snyk              │
│  Reachability Analysis      ❌           ✅ Snyk      ✅ Snyk              │
│  License Compliance         ⚠️ Basic     ✅ Full      ✅ Full              │
│  Custom Rules UI            ❌           ✅ Semgrep   ✅ Yes               │
│  Compliance Reports         ⚠️ Manual    ✅ Auto      ✅ Auto              │
│  SLA Support                ❌           ⚠️ Limited   ✅ 24/7              │
│  SSO/SAML                   ❌           ⚠️ Partial   ✅ Full              │
│  Audit Logs                 ✅ GitHub    ✅ GitHub    ✅ Centralized       │
│  SIEM Integration           ⚠️ Manual    ⚠️ Webhook   ✅ Native            │
│                                                                            │
│  ✅ = Included  ⚠️ = Partial/Manual  ❌ = Not Available                    │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. AWS Infrastructure Detailed Breakdown

### 5.1 Security-Related AWS Costs

| Service | Resource | Quantity | Unit Cost | Monthly |
|---------|----------|----------|-----------|---------|
| **S3** | | | | |
| | SARIF storage | 5 GB | $0.023/GB | $0.12 |
| | SBOM storage | 2 GB | $0.023/GB | $0.05 |
| | Requests | 100K | $0.0004/1K | $0.04 |
| | Transfer out | 10 GB | $0.09/GB | $0.90 |
| **CloudWatch** | | | | |
| | Log ingestion | 50 GB | $0.50/GB | $25.00 |
| | Log storage | 100 GB | $0.03/GB | $3.00 |
| | Metrics | 50 custom | $0.30/metric | $15.00 |
| **KMS** | | | | |
| | Keys | 2 | $1.00/key | $2.00 |
| | Requests | 10K | $0.03/10K | $0.03 |
| **ECR** | | | | |
| | Storage | 50 GB | $0.10/GB | $5.00 |
| | Transfer | 20 GB | $0.09/GB | $1.80 |
| **Secrets Manager** | | | | |
| | Secrets | 10 | $0.40/secret | $4.00 |
| | API calls | 50K | $0.05/10K | $0.25 |
| **Security Hub** | | | | |
| | Findings | 5K | $0.0010/finding | $5.00 |
| | | | **Subtotal** | **$62.19** |

### 5.2 Optional Security Enhancements

| Service | Purpose | Monthly Cost |
|---------|---------|--------------|
| GuardDuty | Threat detection | $35 (per account) |
| Inspector | Vulnerability scanning | $25 |
| Macie | S3 data classification | $50 |
| Config | Compliance rules | $20 |
| **Total Optional** | | **$130** |

---

## 6. GitHub Actions Cost Deep Dive

### 6.1 Minutes Consumption by Job

| Job | Duration | Runs/Day | Monthly Minutes |
|-----|----------|----------|-----------------|
| secrets-scan | 0.5 min | 30 | 450 |
| sast-scan | 1.5 min | 30 | 1,350 |
| sca-scan | 1.0 min | 30 | 900 |
| iac-scan | 1.5 min | 30 | 1,350 |
| container-scan | 2.0 min | 30 | 1,800 |
| sbom-and-sign | 1.0 min | 15 | 450 |
| **Total** | | | **6,300 min** |

### 6.2 Cost Scenarios

| Scenario | Included | Overage | Cost |
|----------|----------|---------|------|
| GitHub Free | 2,000 min | 4,300 min | $34.40 |
| GitHub Team | 3,000 min | 3,300 min | $26.40 + $100 |
| GitHub Enterprise | 50,000 min | 0 | $0 (included) |

### 6.3 Optimization Opportunities

| Optimization | Savings | Implementation |
|--------------|---------|----------------|
| Parallel jobs | 40% time | Already implemented |
| Job caching | 20% time | Add cache actions |
| Skip on docs-only | 10% runs | Path filters |
| Self-hosted runners | 80% cost | Infrastructure needed |

---

## 7. ROI Analysis

### 7.1 Cost of Security Incidents (Avoided)

| Incident Type | Probability | Impact | Expected Loss |
|---------------|-------------|--------|---------------|
| Data breach (KYC) | 5%/year | $500,000 | $25,000/year |
| CNBV fine | 10%/year | $200,000 | $20,000/year |
| Ransomware | 3%/year | $300,000 | $9,000/year |
| Supply chain attack | 2%/year | $400,000 | $8,000/year |
| **Total Expected Loss** | | | **$62,000/year** |

### 7.2 ROI Calculation (OSS-First)

```
Annual Investment:        $1,860 (infrastructure)
                       + $17,760 (personnel)
                       = $19,620

Expected Loss Avoided:    $62,000

Net Benefit:             $62,000 - $19,620 = $42,380

ROI:                     $42,380 / $19,620 = 216%
```

### 7.3 Break-Even Analysis

| Scenario | Annual Cost | Break-Even Incidents |
|----------|-------------|---------------------|
| OSS-First | $19,620 | 0.04 major incidents |
| Hybrid | $30,792 | 0.06 major incidents |
| Full Managed | $137,700 | 0.28 major incidents |

**Interpretation:** OSS-First pays for itself if it prevents just 4% of a major incident annually.

---

## 8. Scaling Projections

### 8.1 Cost at Scale

| Team Size | OSS-First | Hybrid | Full Managed |
|-----------|-----------|--------|--------------|
| 25 devs | $155/mo | $2,566/mo | $11,475/mo |
| 50 devs | $175/mo | $4,000/mo | $18,000/mo |
| 100 devs | $220/mo | $6,500/mo | $30,000/mo |
| 200 devs | $300/mo | $11,000/mo | $55,000/mo |

### 8.2 Recommended Migration Path

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     RECOMMENDED SCALING PATH                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  PHASE 1: OSS-FIRST (Current)                                          │
│  ─────────────────────────────                                          │
│  Team: 10-30 engineers                                                  │
│  Cost: ~$155/month infrastructure                                       │
│  Tools: gitleaks, Semgrep, Trivy, Checkov, Syft, cosign                │
│                                                                         │
│                         │                                               │
│                         ▼                                               │
│                                                                         │
│  PHASE 2: OSS + SNYK (Year 2)                                          │
│  ────────────────────────────                                           │
│  Trigger: >30 engineers OR compliance audit                            │
│  Add: Snyk Team ($522/mo) for auto-fix PRs                             │
│  Cost: ~$700/month infrastructure                                       │
│  Benefit: 50% reduction in remediation time                            │
│                                                                         │
│                         │                                               │
│                         ▼                                               │
│                                                                         │
│  PHASE 3: HYBRID (Year 3+)                                             │
│  ────────────────────────                                               │
│  Trigger: >50 engineers OR SOC 2 Type II audit                         │
│  Add: GitHub Advanced Security, SonarQube                              │
│  Cost: ~$2,500/month infrastructure                                    │
│  Benefit: Native integration, compliance dashboards                    │
│                                                                         │
│                         │                                               │
│                         ▼                                               │
│                                                                         │
│  PHASE 4: ENTERPRISE (Scale)                                           │
│  ───────────────────────────                                            │
│  Trigger: >100 engineers OR multiple products                          │
│  Add: Wiz/Orca for CSPM, dedicated security team                       │
│  Cost: ~$10,000/month infrastructure                                   │
│  Benefit: Full visibility, 24/7 support                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 9. Budget Template

### 9.1 Year 1 Budget (OSS-First)

| Category | Q1 | Q2 | Q3 | Q4 | Annual |
|----------|----|----|----|----|--------|
| GitHub Team | $300 | $300 | $300 | $300 | $1,200 |
| AWS Security | $120 | $120 | $150 | $150 | $540 |
| Training | $500 | $0 | $0 | $500 | $1,000 |
| Contingency | $100 | $100 | $100 | $100 | $400 |
| **Total** | **$1,020** | **$520** | **$550** | **$1,050** | **$3,140** |

### 9.2 Year 2 Budget (OSS + Snyk)

| Category | Q1 | Q2 | Q3 | Q4 | Annual |
|----------|----|----|----|----|--------|
| GitHub Team | $300 | $300 | $300 | $300 | $1,200 |
| Snyk Team | $1,566 | $1,566 | $1,566 | $1,566 | $6,264 |
| AWS Security | $200 | $200 | $200 | $200 | $800 |
| Training | $300 | $0 | $0 | $300 | $600 |
| Contingency | $200 | $200 | $200 | $200 | $800 |
| **Total** | **$2,566** | **$2,266** | **$2,266** | **$2,566** | **$9,664** |

---

## 10. Recommendations

### 10.1 Immediate Actions (Month 1)

| Action | Cost | Impact |
|--------|------|--------|
| Implement OSS stack | $0 | Baseline security |
| Enable GitHub Security | $0 (included) | Dependabot alerts |
| Configure AWS logging | $25/mo | Audit trail |

### 10.2 Short-Term (Months 2-6)

| Action | Cost | Impact |
|--------|------|--------|
| Add job caching | $0 | 20% faster pipelines |
| Custom Semgrep rules | $0 | EFEX-specific detection |
| SBOM attestations | $0 | Supply chain compliance |

### 10.3 Medium-Term (Months 6-12)

| Action | Cost | Impact |
|--------|------|--------|
| Evaluate Snyk | $522/mo | Auto-fix PRs |
| Security Hub integration | $5/mo | Centralized findings |
| Quarterly penetration test | $5,000/quarter | Validation |

---

## Appendix A: Vendor Pricing References

| Vendor | Pricing Page | Date Checked |
|--------|--------------|--------------|
| GitHub | github.com/pricing | Jan 2024 |
| Snyk | snyk.io/plans | Jan 2024 |
| AWS | aws.amazon.com/pricing | Jan 2024 |
| Semgrep | semgrep.dev/pricing | Jan 2024 |
| SonarQube | sonarsource.com/plans | Jan 2024 |

## Appendix B: Assumptions

1. **Team size:** 25 engineers (5 SWAT teams × 5 members)
2. **Deployment frequency:** 6 deploys/day/team = 30 total
3. **Repository size:** Medium (~50MB)
4. **Container size:** ~500MB
5. **Log retention:** 90 days
6. **SBOM retention:** 1 year
7. **AWS region:** us-east-1
8. **Currency:** USD
9. **Pricing date:** January 2024

---

**Document Owner:** Platform Security Team
**Last Updated:** 2024-01-15
**Review Frequency:** Quarterly
