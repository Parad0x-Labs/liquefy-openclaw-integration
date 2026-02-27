# Commercial Licensing (BUSL-1.1)

Liquefy is licensed under the **Business Source License 1.1 (BUSL-1.1)**.

This file summarizes commercial usage for operators and procurement teams.
For legally binding terms, see the repository `LICENSE` file.

## Why companies license Liquefy

Running autonomous AI agents without audit trails, secret redaction, and policy enforcement is a compliance liability. A single leaked API key, an unmonitored agent loop burning $50K in API credits, or a missing audit trail during a regulatory review can cost orders of magnitude more than a software license.

Liquefy is compliance insurance: tamper-proof audit chains, automatic secret redaction, active kill switches, and bit-perfect recovery — so your security team can prove exactly what every agent did, and your finance team never gets a surprise bill.

## License model

- **Governing license:** BUSL-1.1
- **Licensor:** Parad0x Labs
- **Change Date:** 2028-02-22
- **Change License:** GPL-2.0-or-later

## Usage policy

- **Free use (including production)** is permitted under the Additional Use Grant for:
  - personal/private non-commercial projects,
  - nonprofit organizations (mission use, not primarily for the benefit of a for-profit entity),
  - academic, educational, and research use (schools, universities, public research institutions),
  - open-source projects that do not sell, license for a fee, or commercially offer access to Liquefy itself or Liquefy-powered functionality.
- **Commercial / for-profit use** requires a separate commercial agreement with Parad0x Labs.

## What counts as commercial use

The following activities **require a commercial license** (non-exhaustive):

| Activity | Example |
|----------|---------|
| **Internal business use** | Running Liquefy on corporate machines, CI/CD runners, or cloud instances for any business purpose (a 30-Day Evaluation License is available for initial testing — see below) |
| **SaaS / hosted / managed service** | Offering Liquefy-powered compression, auditing, or vault functionality as part of a paid or ad-supported service |
| **Embedded / bundled product** | Shipping Liquefy (or substantial portions) inside a commercial product, platform, or appliance |
| **Monetized wrapper** | Building a paid product, managed offering, or "open-source" project that commercially resells access to Liquefy functionality |
| **Consulting / agency work** | Using Liquefy on behalf of a paying client, or delivering Liquefy-powered outputs as a service |
| **Corporate internal tooling** | Using Liquefy for internal DevOps, security, compliance, or observability within a for-profit company |

**The test is simple:** if a for-profit entity benefits from Liquefy's operation, a commercial license is required.

- **Decode-only recovery** (`decompress`/`verify`): intended to remain available without production lock-in. You can always read your own data.

## Examples (non-legal, for operator guidance)

**Free** (no commercial license required):

- Personal homelab / side project
- University lab compressing research traces
- School IT class using Liquefy in coursework
- Nonprofit internal observability archive workflows

**Commercial license required:**

- Startup using Liquefy internally (including pre-revenue)
- Enterprise running Liquefy on corporate CI/CD or cloud infra
- Cloud provider / AI platform packaging Liquefy into an offering
- OSS project selling hosted/API access to Liquefy-powered functionality
- Agency or contractor using Liquefy on behalf of a paying client
- Commercial product embedding Liquefy as part of its pipeline

## 30-Day Evaluation License

Commercial entities may use Liquefy under a **30-Day Evaluation License** for the purpose of technical evaluation, proof-of-concept testing, and integration validation — without purchasing a commercial license.

**Terms:**

- **Duration:** 30 calendar days from first use within the organization.
- **Scope:** Non-production, evaluation-only. Testing on staging environments, developer machines, and CI/CD test pipelines is permitted.
- **Not permitted:** Production workloads, customer-facing deployments, or processing live business data during the evaluation period.
- **No registration required:** The evaluation license is automatic. No key, no phone-home, no approval needed to start testing.
- **After 30 days:** Continued use of any kind — including non-production — requires a purchased Commercial License. Organizations must either purchase a license or remove Liquefy from all systems.

**Getting started with your evaluation:**

We recommend scheduling a brief kickoff call so we can ensure your team has the optimal configuration for your environment. Email `hello@parad0xlabs.com` with subject `Liquefy Evaluation — [Company Name]` and we'll get you set up.

## Commercial tiers

| Tier | What you get | Best for |
|------|-------------|----------|
| **Standard** | Commercial use rights, access to all features, community support (GitHub Issues) | Small teams and startups |
| **Professional** | Standard + 48-hour email support, deployment guidance, priority bug fixes | Mid-size companies running agents in production |
| **Enterprise** | Professional + SLA-backed response times, dedicated onboarding, custom integration support, volume pricing | Large organizations with compliance requirements |

All tiers include the full Liquefy feature set. The difference is support response time and deployment assistance.

## Contact

For commercial terms, enterprise deployment approvals, and pricing:

- **Email:** `hello@parad0xlabs.com`
- **Subject line:** `Liquefy Commercial License — [Company Name]`

---
If this summary conflicts with `LICENSE`, the `LICENSE` file prevails.
