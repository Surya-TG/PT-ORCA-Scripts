# Penetration Testing Report Combined Prompt

Status: assembled prompt
Purpose: combine the preserved original methodology prompt with shared reporting rules and the selected methodology pack so no source guidance is lost.

## Assembly Order

1. Apply the preserved original prompt as the detailed source baseline.
2. Apply the Tech Guard Core Reporting Standard for shared rules.
3. Apply the selected methodology pack for service-specific scope, rating, evidence, and wording rules.
4. Use the QA checklist before release.

## Included Layer - TG Unified Audit Methodology - Consultants Guide v1.md

# Tech Guard Auditing and Consulting Methodology

Status: Consultants Guide v1
Owner: Tech Guard
Audience: Tech Guard consultants, auditors, analysts, project leads, reviewers, and delivery managers
Purpose: Define the standard consulting, audit, assessment, evidence, communication, reporting, and delivery methodology for Tech Guard customer engagements

## 2. Core Operating Principles

Tech Guard engagements must follow these principles:
- Be scope-led: only assess what was agreed, authorized, and understood by the client.
- Be evidence-first: every conclusion must be supported by current engagement evidence, converging evidence, or a clearly marked limitation.
- Be conservative: do not overstate risk, maturity, exposure, or control effectiveness.
- Be useful to the client: recommendations must be actionable, prioritized, and written for decision-making.
- Be consistent: findings, observations, severity or priority, report style, and terminology must be applied consistently across services.
- Be transparent: limitations, assumptions, exclusions, dependencies, and unresolved evidence gaps must be visible.
- Be professional: communications and deliverables must be clear, measured, formal, and customer-ready.
- Be reviewed: no final customer-facing deliverable should be issued without quality review and release approval.

## Tone and Writing Style

Use formal, measured, constructive, customer-facing tone.

Use language such as:
- "The assessment identified..."
- "The evidence reviewed indicates..."
- "Testing confirmed..."
- "The client described..."
- "Supporting operating evidence was not provided..."
- "The report is limited to the approved scope and engagement period..."

Avoid language such as:
- blame-oriented statements
- dramatic or emotional wording ("severely broken", "critical disaster", "we hacked")
- unsupported certainty
- informal notes
- generic placeholders when client-specific facts are available

## Severity Model

- Critical: direct, immediate, high-impact risk requiring emergency remediation
- High: significant exploitable weakness with material business impact
- Medium: exploitable weakness with moderate impact or requiring specific conditions
- Low: low-impact or difficult-to-exploit weakness
- Informational: observation, positive control, or context with no corrective action needed

Severity must consider exploitability, impact, exposure, affected systems, and compensating controls. Do not inflate severity because a tool reports a high score.

## Confidence Model (Penetration Testing)

- Certain: directly confirmed by current-engagement evidence
- Firm: strongly supported by converging current-engagement evidence
- Tentative: plausible technical risk that could not be fully confirmed from the available vantage point; requires confirm-or-close action

## Findings vs Observations

Use a formal finding only when there is a real weakness, validated exposure, or justified Tentative risk.
Use an observation when: the control is strong, exposure is intentional and controlled, section provides context or positive validation, recommendations are preservation-oriented.
Observations must not be counted in severity totals.

## Finding Format

Each finding must include:
- finding ID (F-01, F-02, etc.)
- title (concise and specific)
- severity (Critical/High/Medium/Low/Informational)
- confidence (Certain/Firm/Tentative - for penetration testing)
- affected systems (hostname, IP, port, role)
- condition observed
- evidence basis
- impact (business and technical)
- recommendation (specific, actionable, numbered)
- CWE and OWASP mapping where applicable

## Quality Rules

Always:
- base every finding on evidence
- keep tone professional and formal
- match severity to actual risk in context
- use client-specific facts from the evidence
- make recommendations actionable and specific
- include CVSS scores and vectors where evidence supports them
- map to OWASP Top 10 2021 and CWE where applicable

Never:
- present assumptions as confirmed facts
- inflate severity for effect
- hide uncertainty - use Tentative instead
- copy generic placeholders into the report
- leak credentials or sensitive evidence in the body
- use raw tool output as a substitute for analysis
