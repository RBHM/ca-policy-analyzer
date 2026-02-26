# CA Policy Analyzer

> Analyze your Entra ID Conditional Access policies for best practices, FOCI token-sharing risks, and known CA bypasses.

![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js) ![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript) ![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-38bdf8?logo=tailwindcss)

## What It Does

CA Policy Analyzer connects to your Entra ID tenant via Microsoft Graph and:

1. **Reads all Conditional Access policies** including users, apps, conditions, and grant/session controls
2. **Checks for best-practice violations** using research from [Fabian Bader](https://cloudbrothers.info/en/conditional-access-bypasses/) and [EntraScopes.com](https://entrascopes.com)
3. **Detects FOCI risks** — if a policy excludes one FOCI app, ALL 45+ family members can share tokens
4. **Flags known CA bypasses** including CA-immune resources, Device Registration Service bypass, resource exclusion scope leaks, and more
5. **Generates a Security Posture Score** (0-100) with severity-ranked findings and actionable recommendations
6. **Visualizes each policy** showing the flow: Users → Conditions → Apps → Grant Controls

## Key Checks

| Category | What It Detects |
|---|---|
| **FOCI Token Sharing** | Excluded apps that belong to the Family of Client IDs — tokens interchangeable across 45+ Microsoft apps |
| **Resource Exclusion Bypass** | Excluding ANY app from "All cloud apps" leaks Azure AD Graph & MS Graph basic scopes |
| **CA-Immune Resources** | 6 Microsoft resources completely excluded from CA enforcement (always notApplied) |
| **Device Registration Bypass** | Device Registration Service ignores location and device compliance — only MFA works |
| **Swiss Cheese Model** | Grant controls using OR instead of AND, missing MFA baseline layer |
| **Legacy Authentication** | Legacy auth clients targeted but not blocked |
| **Known CA Bypass Apps** | Apps with documented CA bypass capabilities (Azure CLI, PowerShell, AAD Connect, etc.) |
| **Tenant-Wide Gaps** | Missing MFA-for-all, no legacy auth block, no break-glass accounts |

## Getting Started

### Prerequisites

- Node.js 18+
- An Entra ID tenant with Conditional Access policies
- An app registration with delegated permissions:
  - Policy.Read.All
  - Application.Read.All
  - Directory.Read.All

### Setup

```bash
git clone https://github.com/YOUR_USERNAME/ca-policy-analyzer.git
cd ca-policy-analyzer
npm install
cp .env.example .env.local
# Edit .env.local with your app registration Client ID
npm run dev
```

Open http://localhost:3000, click **Connect Tenant**, sign in, then click **Run Analysis**.

### App Registration

1. Go to Entra ID → App Registrations
2. New registration → Name: "CA Policy Analyzer" → Accounts in any organizational directory
3. Redirect URI → Single-page application → http://localhost:3000
4. API permissions → Add → Microsoft Graph (Delegated): Policy.Read.All, Application.Read.All, Directory.Read.All
5. Grant admin consent
6. Copy Application (client) ID into .env.local

## Architecture

```
src/
├── app/            # Next.js App Router pages
├── components/     # React components (auth, dashboard, policy list, findings)
├── data/           # FOCI database (45 apps) + CA bypass database
└── lib/            # MSAL config, Graph client, analyzer engine (13 checks)
```

## Research Credits

- **Fabian Bader** — Conditional Access bypasses (TROOPERS25)
- **Dirk-jan Mollema & Fabian Bader** — EntraScopes.com
- **Secureworks** — Family of Client IDs Research

## License

MIT
