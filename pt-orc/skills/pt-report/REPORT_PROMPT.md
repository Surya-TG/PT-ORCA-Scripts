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

## 1. Purpose and Scope

This guide defines how Tech Guard consultants plan, execute, communicate, evidence, review, and deliver customer-facing audit and consulting work.

It is intentionally focused on the consulting process and methodology. It does not define product development, software architecture, automation roadmap, or internal platform implementation. Tools may support the work, but the accountable delivery method remains a consultant-led process.

This guide applies to Tech Guard engagements including:

- standards consulting and readiness preparation;
- penetration testing;
- gap analysis;
- security and cyber assessments;
- risk assessments;
- remediation validation and reassessment;
- technical verification exercises;
- advisory work that results in a customer-facing deliverable.

Service-specific procedures, test scripts, control mappings, and report templates may differ by engagement type. The core expectations in this guide remain the same for every customer-facing engagement.

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

## 3. Standard Engagement Lifecycle

Every engagement should move through the lifecycle below. The depth of each stage may vary by project size, but no stage should be skipped without documenting the reason.

### Stage 1. Intake and Qualification

Objective: confirm what the client needs, whether Tech Guard can deliver it, and what conditions must be clarified before the work starts.

Required activities:

- identify the client, sponsor, stakeholders, and operational contacts;
- understand the business reason for the engagement;
- classify the requested service type;
- capture expected outputs, deadlines, constraints, and dependencies;
- identify legal, regulatory, contractual, or technical conditions;
- identify required skills and reviewer involvement;
- document assumptions, open questions, and decision points.

Required outputs:

- intake summary;
- preliminary service classification;
- initial scope note;
- open questions and assumptions list;
- initial delivery risk notes, if any.

Consultant guidance:

- Do not let a vague request become an implicit commitment.
- If the client asks for "an audit", clarify the target framework, required evidence, expected report format, and intended audience.
- If the client asks for "testing", clarify perspective, assets, accounts, restrictions, impact tolerance, and approval requirements.

### Stage 2. Scope, Authorization, and Rules of Engagement

Objective: define exactly what Tech Guard is allowed to review, test, request, conclude, and report.

Required activities:

- define in-scope assets, systems, processes, locations, departments, applications, networks, or frameworks;
- define out-of-scope items and prohibited activities;
- define the assessment perspective and access level;
- confirm dates, working windows, meeting cadence, and escalation contacts;
- confirm safe-testing rules, data handling requirements, confidentiality, and report distribution limits;
- identify dependencies on client evidence, access, walkthroughs, or approvals;
- record formal authorization where required.

Required outputs:

- approved scope statement;
- authorization record or written approval;
- exclusions and constraints list;
- rules of engagement or operating conditions;
- communication and escalation matrix.

Consultant guidance:

- Scope should be concrete enough that another consultant could determine whether an activity is permitted.
- Any activity that could affect production, user accounts, service availability, or sensitive data must be explicitly authorized.
- If scope is changed during delivery, update the scope record before relying on the change in the report.

### Stage 3. Planning and Work Design

Objective: translate the approved scope into an executable plan.

Required activities:

- define engagement objectives and success criteria;
- identify workstreams, tasks, dependencies, and milestones;
- define evidence requirements and request sequence;
- schedule interviews, workshops, testing windows, or walkthroughs;
- assign consultant, reviewer, and project lead responsibilities;
- define report sections and expected deliverables;
- identify project-specific risks, constraints, and quality checkpoints.

Required outputs:

- engagement plan;
- evidence request plan;
- interview or workshop plan;
- delivery schedule;
- report outline or deliverable structure;
- internal QA plan.

Consultant guidance:

- Plan around the evidence needed to support conclusions, not only around activities.
- For large engagements, separate evidence collection, analysis, and reporting milestones so gaps are visible early.
- For short engagements, keep the plan concise but still record scope, evidence needs, and review expectations.

### Stage 4. Customer Kickoff

Objective: align the client and Tech Guard delivery team before execution begins.

Required activities:

- confirm objectives, scope, exclusions, schedule, and deliverables;
- introduce roles, contacts, escalation paths, and expected response times;
- explain evidence request process and ownership;
- confirm meeting cadence and status-reporting format;
- confirm how questions, blockers, changes, and risks will be handled;
- confirm how draft findings or draft observations will be discussed.

Required outputs:

- kickoff notes;
- confirmed action items;
- updated evidence request list;
- updated schedule, if changed;
- confirmed communication cadence.

Consultant guidance:

- The kickoff should reduce ambiguity, not create a presentation-only event.
- Document decisions and action items immediately after the meeting.
- If the client challenges scope or deliverables at kickoff, pause and resolve before execution.

### Stage 5. Evidence Acquisition and Information Gathering

Objective: obtain the documents, exports, screenshots, logs, configurations, interviews, access, and technical outputs needed to perform the work.

Required activities:

- issue clear evidence requests with owner, due date, format, and purpose;
- collect documents, screenshots, system exports, logs, policies, procedures, diagrams, tickets, scan outputs, and interview notes;
- record source, date, owner, collection method, and relevant scope mapping;
- validate that evidence is readable, current, complete enough, and relevant;
- track missing, outdated, conflicting, or unusable evidence;
- escalate critical evidence gaps early.

Required outputs:

- evidence inventory;
- evidence request tracker;
- evidence gap log;
- interview notes or walkthrough notes;
- client-declared statements clearly marked as such.

Consultant guidance:

- Evidence should be requested in language the client can act on.
- Do not ask for broad "all security documents" requests when a specific control, process, or conclusion needs specific evidence.
- Client verbal statements may support understanding, but should not be treated as confirmed evidence unless corroborated or explicitly reported as management assertion.

### Stage 6. Fieldwork, Analysis, and Assessment

Objective: perform the assessment work and evaluate evidence against the relevant scope, objectives, requirements, controls, risks, or test criteria.

Required activities:

- analyze evidence against the applicable framework, requirement, risk, technical test, or consulting objective;
- perform interviews, walkthroughs, testing, sampling, or validation steps required by the service type;
- distinguish confirmed facts from assumptions, interpretations, and client statements;
- identify gaps, weaknesses, risks, positive controls, limitations, and open items;
- record analyst reasoning in working notes;
- map conclusions back to evidence references.

Required outputs:

- working papers or analysis notes;
- control, requirement, asset, or finding mapping;
- preliminary observations;
- preliminary findings or risks;
- unresolved questions and limitations.

Consultant guidance:

- Do not write the report before the evidence is understood.
- Avoid turning every imperfection into a finding. Some items belong as observations, advisory notes, or future improvements.
- If evidence is insufficient, record the limitation and its effect on the conclusion.

### Stage 7. Finding and Observation Development

Objective: convert analysis into clear, defensible, customer-ready conclusions.

Required activities:

- decide whether each issue is a finding, gap, observation, risk, or informational note;
- group related evidence into coherent themes;
- assign severity or priority according to the engagement type;
- use confidence only for penetration testing or other technical result sets where automated results, limited vantage point, or incomplete access prevent full manual validation;
- draft impact and recommendation language;
- remove unsupported claims and duplicate items;
- identify positive controls and preservation-oriented recommendations where appropriate;
- confirm that counts, titles, summaries, and section references are consistent.

Required outputs:

- finding register;
- observation register;
- severity or priority summary;
- evidence-to-finding mapping;
- draft executive themes.

Consultant guidance:

- A finding should describe a condition that requires corrective action or formal acceptance.
- An observation should describe context, positive validation, controlled exposure, or useful improvement advice that is not a formal weakness.
- A tentative finding is allowed only when there is a justified risk that merits confirm-or-close action and the uncertainty is clearly explained.

### Stage 8. Client Alignment During Delivery

Objective: keep the client informed, resolve factual gaps, and prevent surprises without surrendering independence.

Required activities:

- provide agreed status updates;
- raise evidence gaps and blockers early;
- validate factual context where needed;
- discuss high-impact issues promptly;
- document client responses and decisions;
- distinguish factual correction from pressure to soften findings;
- escalate disagreements on scope, severity, or evidence.

Required outputs:

- status updates;
- action item logs;
- clarification records;
- issue escalation notes;
- factual correction record, if applicable.

Consultant guidance:

- Do not wait until final report delivery to raise a critical issue or major missing evidence.
- Allow the client to correct facts, provide missing context, or explain compensating controls.
- Do not remove or weaken supported findings only because they are uncomfortable.

### Stage 9. Reporting

Objective: produce a customer-facing report that is clear, accurate, evidence-based, and ready for decision-making.

Required activities:

- prepare report-ready text, not note-style output;
- write for both management and technical audiences;
- include scope, methodology, limitations, findings, recommendations, observations, and appendices as appropriate;
- place detailed inventories, long outputs, screenshots, and raw evidence in appendices or evidence indexes unless essential to the finding;
- ensure executive summaries match detailed findings and totals;
- preserve confidentiality and avoid unnecessary sensitive data exposure.

Required outputs:

- draft report;
- evidence index or appendix;
- internal review copy;
- final customer-ready report.

Consultant guidance:

- The body of the report should synthesize risk and business impact. Appendices should support the body without overwhelming it.
- Never paste raw tool output as a substitute for analysis.
- Use client-specific evidence when authorized and relevant. Do not copy generic examples into the final report when exact client-specific details are available.

### Stage 10. Quality Assurance and Release Review

Objective: confirm that the deliverable is accurate, complete, professional, and aligned to scope before release.

Required activities:

- verify scope alignment;
- verify evidence support for each conclusion;
- verify severity or priority and recommendation consistency;
- verify confidence only when the report type legitimately uses a confidence field;
- verify report structure, numbering, cross-references, counts, and formatting;
- verify client names, dates, version numbers, confidentiality markings, and distribution limits;
- verify that limitations and assumptions are visible;
- resolve reviewer comments or document accepted exceptions;
- obtain release approval.

Required outputs:

- QA checklist;
- review comments and resolutions;
- approved final report;
- release record.

Consultant guidance:

- QA is not cosmetic editing. It is the point where unsupported conclusions, report inconsistencies, and delivery risks must be caught.
- If a report count changes, update every affected summary, chart, table, and section reference.

### Stage 11. Delivery, Readout, and Closure

Objective: deliver the final output, support client understanding, and close the project cleanly.

Required activities:

- deliver final reports through the agreed channel;
- run a readout meeting when appropriate;
- explain key findings, priorities, limitations, and recommended next steps;
- answer factual questions and identify any follow-up actions;
- preserve final deliverables, evidence records, approvals, and closure notes;
- capture lessons learned and reusable improvements.

Required outputs:

- final deliverable package;
- delivery confirmation;
- readout notes, if applicable;
- closure record;
- lessons learned.

Consultant guidance:

- A readout should help the client act, not merely repeat the report.
- Close open actions clearly. Do not leave informal promises outside the project record.

## 4. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Engagement Lead / Project Lead | Owns scope, client coordination, delivery schedule, escalation, and release readiness. |
| Lead Consultant / Auditor | Owns methodology execution, evidence analysis, finding quality, and report content. |
| Technical Specialist | Performs specialist testing, validation, or technical analysis within approved scope. |
| Evidence Coordinator | Tracks requests, received materials, evidence gaps, and source metadata when assigned. |
| Reviewer / QA Reviewer | Performs independent review for accuracy, evidence support, consistency, and report quality. |
| Client Sponsor | Owns business approval, escalation, and acceptance of deliverables. |
| Client Technical / Process Owner | Provides evidence, walkthroughs, access, clarifications, and factual corrections. |

Small engagements may combine roles, but accountability must remain clear.

## 5. Customer Communication Methodology

Consultants must communicate in a way that is structured, respectful, documented, and useful.

### 5.1 Communication Principles

- Be clear about what is needed, by when, from whom, and why.
- Separate status, decisions, risks, and action items.
- Avoid vague escalation. State the impact of delay or missing information.
- Keep sensitive details only in approved channels.
- Record material client decisions and factual clarifications.
- Use formal, measured language in writing, especially for findings and limitations.

### 5.2 Standard Customer Touchpoints

| Touchpoint | Purpose | Expected Output |
|---|---|---|
| Intake / pre-kickoff | Clarify request, outcome, scope, and conditions | open questions and draft scope |
| Kickoff | Align on scope, process, roles, evidence, schedule, and escalation | kickoff notes and action list |
| Evidence follow-up | Track missing or unclear evidence | updated tracker and gap notes |
| Status update | Communicate progress, blockers, risks, and upcoming work | concise status note |
| Finding clarification | Validate factual details without negotiating unsupported changes | factual correction record |
| Draft review, if agreed | Allow factual review of draft content | documented corrections and accepted changes |
| Final readout | Explain results and next steps | readout notes and follow-up actions |

### 5.3 Evidence Request Communication

Evidence requests should include:

- request ID or short title;
- description of the requested item;
- purpose or related control/objective;
- preferred format;
- owner;
- due date;
- sensitivity or handling note, if relevant.

Poor request:

> Please send all security documentation.

Better request:

> Please provide the current access review procedure and the most recent completed privileged access review evidence for the in-scope systems, including review date, reviewer, user list reviewed, exceptions identified, and remediation status.

### 5.4 Handling Delays and Missing Evidence

When evidence is delayed, consultants should:

1. restate the missing item clearly;
2. explain why it is needed;
3. state the delivery impact;
4. offer a reasonable alternative if one exists;
5. record the limitation if it remains unresolved.

Example:

> The access review evidence remains outstanding. Without this evidence, Tech Guard cannot confirm whether privileged access is periodically reviewed for the in-scope environment. If the evidence is unavailable, the report will state this limitation and the related conclusion will be restricted to the evidence provided.

### 5.5 Handling Disagreement

Disagreements should be handled professionally and documented.

Acceptable client input:

- factual corrections;
- additional evidence;
- clarification of ownership or scope;
- explanation of compensating controls;
- correction of dates, names, assets, or process descriptions.

Unacceptable basis for changing a conclusion:

- preference to avoid a finding;
- unsupported verbal assurance;
- concern that a finding "sounds bad";
- pressure to reduce severity without evidence;
- request to remove a limitation that remains true.

When disagreement remains, document the difference between Tech Guard's evidence-based conclusion and the client's position.

## 6. Evidence and Working Paper Discipline

Evidence is central to the methodology. No customer-facing conclusion should be made without evidence or an explicit limitation.

### 6.1 Evidence Principles

- Use current engagement evidence whenever possible.
- Prefer direct evidence over indirect evidence.
- Use converging evidence when no single source is complete.
- Mark client-declared statements as client-declared unless independently verified.
- Preserve the source and date of each evidence item.
- Protect sensitive evidence according to classification and agreed handling rules.
- Do not include more sensitive detail than needed in the report body.

### 6.2 Evidence Metadata

Each material evidence item should have, where practical:

- evidence ID or filename;
- source or owner;
- collection date;
- collection method;
- related scope item, control, requirement, asset, or finding;
- short description of what the evidence demonstrates;
- sensitivity or handling note;
- reviewer notes, if applicable.

### 6.3 Evidence Strength

Evidence should be evaluated as:

- Direct: directly demonstrates the condition or control.
- Corroborating: supports the conclusion together with other evidence.
- Partial: supports part of the conclusion but leaves important uncertainty.
- Client-declared: provided as a statement by the client and not independently verified.
- Insufficient: not enough to support the conclusion.

Where evidence is partial, client-declared, or insufficient, the report must explain the limitation and its effect on the conclusion.

### 6.4 Working Papers

Working papers should allow another qualified reviewer to understand:

- what was assessed;
- what evidence was used;
- what conclusion was reached;
- why the conclusion is reasonable;
- what limitations or assumptions remain;
- how the conclusion maps to the final report.

Working papers do not need to be verbose, but they must be traceable.

## 7. Findings, Gaps, Observations, and Risks

Tech Guard should use consistent terminology across all service lines.

### 7.1 Observation

An observation describes context, positive validation, controlled exposure, process maturity, preservation-oriented advice, or useful information that does not rise to the level of a formal finding.

Examples:

- the client has an effective control in place;
- exposure exists but is intentional, restricted, and appropriately managed;
- a prior finding appears remediated;
- a process is present and could be improved but no material weakness is evidenced.

Observations must not be counted as findings or included in severity totals.

### 7.2 Gap

A gap is a difference between current state and a requirement, framework expectation, contractual obligation, target maturity level, or agreed practice.

Gaps are common in standards consulting and readiness engagements. They may become findings when they represent a material weakness requiring corrective action.

### 7.3 Finding

A finding is a validated weakness, gap, exposure, risk condition, or justified tentative risk that requires corrective action, formal acceptance, or confirm-or-close follow-up.

A finding should include:

- title;
- severity or priority;
- confidence, only where the report type legitimately uses a confidence field;
- affected area, asset, process, requirement, or control;
- condition observed;
- evidence summary;
- impact or risk;
- recommendation;
- limitation or assumption, if applicable.

### 7.4 Risk

A risk describes the potential business or operational impact of a condition. Risk language should be tied to the client context and not exaggerated.

Risk may be expressed as part of a finding, a risk register, or an assessment summary depending on the engagement type.

### 7.5 Tentative Findings and Limited Validation

Use Tentative only for penetration testing or similar technical assessments where automated results, limited vantage point, or incomplete access indicate a plausible risk that cannot be fully validated during the engagement.

Use Tentative when:

- evidence indicates a plausible risk;
- the condition cannot be fully confirmed from the assessment vantage point;
- the uncertainty is material to the conclusion;
- the client should take confirm-or-close action.

Tentative language must be explicit.

Example:

> The condition could not be fully determined from the assessment vantage point. Based on the available evidence, Tech Guard considers this a Tentative finding and recommends that the client confirm whether the control is implemented as expected.

For audits, gap assessments, standards consulting, security reviews, and similar manually validated consulting reports, do not use Tentative as a routine finding category. Those reports should be based on evidence, interviews, walkthroughs, and manual validation. If evidence is missing or validation cannot be completed, state the limitation directly and describe the conclusion as not evidenced, partially evidenced, or unable to determine, depending on the methodology used.

### 7.6 Severity and Priority

Severity should reflect the assessed impact and likelihood of the condition in context. Priority may also consider remediation urgency, compliance dependency, business criticality, or project timing.

Use clear definitions in each report. Common categories include:

- Critical;
- High;
- Medium;
- Low;
- Informational / Observation.

Do not include observations in severity totals.

### 7.7 Confidence Field Applicability

Confidence is not a standard field for all Tech Guard reports.

For gap assessments, security reviews, audits, standards consulting, and other manually validated consulting reports, findings are expected to be supported by evidence, interviews, walkthroughs, and consultant validation. In those report types, a separate confidence field is normally irrelevant and should not be used.

Use a confidence field only when the engagement includes technical or automated results that cannot be fully validated because of limited access, limited vantage point, testing constraints, or incomplete confirmation. This is most relevant to penetration testing.

When used, confidence may be expressed as:

- High: direct and sufficient evidence supports the conclusion.
- Medium: evidence supports the conclusion but has some limitation or dependency.
- Low: conclusion is plausible but materially limited and should be confirmed.
- Tentative: risk-oriented conclusion requiring confirm-or-close validation.

Confidence should never be used to hide weak evidence. If evidence is insufficient, say so as a limitation.

## 8. Customer-Facing Report Standard

Customer-facing reports must follow the mature style used in Tech Guard penetration testing reports, adapted to the service type.

The exact section structure may change by engagement type, but the style, evidence discipline, wording quality, findings presentation, and formatting expectations remain consistent.

### 8.1 Report Writing Tone

Use a formal, professional, customer-facing tone.

Write in a style that is:

- clear;
- measured;
- evidence-based;
- technically precise;
- non-dramatic;
- readable by both management and technical audiences.

Preferred phrasing:

- "The assessment identified..."
- "Testing confirmed..."
- "The observed behavior indicates..."
- "The evidence provided indicates..."
- "This should be addressed by..."
- "The condition could not be fully determined from the assessment vantage point..."

Avoid phrasing:

- "we hacked";
- "severely broken";
- "critical disaster";
- "obviously insecure";
- "probably vulnerable", unless the report type legitimately uses Tentative findings and the uncertainty is clearly explained;
- informal note-style language.

### 8.2 Core Report Components

Most reports should include:

- cover or metadata block;
- confidentiality and classification marking;
- objectives;
- scope;
- methodology;
- team or provider note, where appropriate;
- special notes, limitations, assumptions, and exclusions;
- executive summary;
- findings and recommendations;
- observations or positive validations;
- appendices and evidence index;
- version history, where required.

Service-specific reports may add or remove sections, but must preserve clarity, traceability, and reviewability.

### 8.3 Executive Summary

The executive summary should:

- state the overall posture or result;
- summarize the most important findings, gaps, or themes;
- identify material strengths or improvements where relevant;
- explain limitations that affect interpretation;
- provide a concise forward-looking conclusion.

For key findings, include:

- title;
- section or finding reference;
- severity or priority;
- short business-relevant risk statement;
- summarized recommendation.

The executive summary must match the detailed sections. Do not introduce findings in the executive summary that are not supported later in the report.

### 8.4 Methodology Section

The methodology section should explain how the work was performed without overloading the client with unnecessary internal detail.

Include, as relevant:

- standards, frameworks, or references used;
- assessment perspective;
- principal stages of work;
- evidence sources and validation approach;
- sampling approach, if applicable;
- tool categories or test methods, if relevant;
- limitations and exclusions.

Do not provide an unstructured tool dump. Group tools or activities by purpose.

Examples:

- for standards consulting: policy review, interview walkthroughs, evidence sampling, control mapping, and maturity assessment;
- for gap analysis: requirement mapping, current-state evidence review, gap classification, risk/prioritization, and action planning;
- for penetration testing: reconnaissance, service enumeration, vulnerability validation, controlled exploitation where authorized, and evidence preservation;
- for security assessment: architecture review, configuration review, process review, control validation, and risk analysis.

### 8.5 Findings Section Format

Each finding should follow a consistent structure.

Recommended format:

1. Finding title.
2. Severity or priority.
3. Confidence, only for penetration testing or other technical/automated result sets where the report type legitimately uses it.
4. Affected area, system, process, control, or requirement.
5. Condition observed.
6. Evidence summary.
7. Risk or impact.
8. Recommendation.
9. Limitation or assumption, if applicable.

Finding titles should be concise and specific.

Better:

> F-03 - Privileged Access Reviews Were Not Evidenced for In-Scope Systems

Weaker:

> F-03 - Access Problem

### 8.6 Recommendations

Recommendations must be:

- numbered where multiple actions are provided;
- actionable;
- realistic;
- matched to the finding;
- written in a professional tone;
- specific enough for the client to plan remediation.

Recommendations should not introduce new unsupported claims.

For observations, use preservation-oriented recommendations when the intent is to maintain or improve an already acceptable posture.

Example:

> Preservation-Oriented Recommendations:
> 1. Continue maintaining the current approval and review process.
> 2. Retain evidence of each completed review, including reviewer, date, scope, exceptions, and closure status.

### 8.7 Appendices and Evidence Index

Appendices should support the report without overwhelming the main text.

Typical appendix items include:

- evidence index;
- detailed asset lists;
- control mapping tables;
- test outputs or screenshots;
- interview list;
- sampling details;
- severity model;
- glossary or references.

Evidence-index rows should map:

- finding or section reference;
- evidence ID;
- source;
- evidence date;
- short description of what the evidence proves.

Do not place sensitive raw data in appendices unless it is necessary, authorized, and properly classified.

### 8.8 Report Style Rules

Always:

- keep tone consistent and professional;
- keep language evidence-based;
- keep numbering, counts, tables, and references consistent;
- separate findings from observations;
- mark limitations clearly;
- use client-specific facts when supported and authorized;
- summarize long technical detail in the body and move raw detail to appendices.

Never:

- present assumptions as confirmed facts;
- inflate severity for effect;
- hide uncertainty;
- copy generic placeholders into a client report;
- include unsupported recommendations;
- use casual, dramatic, or blame-oriented wording;
- leak credentials, passwords, or sensitive evidence beyond the intended report audience and classification.

## 9. Service-Specific Methodology Overlays

The core methodology applies to every engagement. Each service type adds specific evidence, analysis, and reporting expectations.

### 9.1 Standards Consulting and Readiness Preparation

Primary objective:

- help the client understand readiness against a standard, certification, regulatory expectation, contractual obligation, or internal target state.

Typical evidence:

- policies and procedures;
- process records;
- risk assessments;
- asset and access records;
- training records;
- incident or change records;
- management review evidence;
- internal audit or prior assessment records;
- interviews and walkthroughs.

Typical outputs:

- readiness assessment;
- gap register;
- evidence plan;
- remediation roadmap;
- management summary;
- implementation guidance.

Consultant cautions:

- Do not imply certification readiness unless evidence supports it.
- Separate "document exists" from "process operates effectively".
- Identify whether a gap is design-related, implementation-related, evidence-related, or maturity-related.

### 9.2 Gap Analysis

Primary objective:

- compare current state to a target framework, control set, or agreed requirement baseline.

Typical evidence:

- control evidence;
- policy and procedure documents;
- interviews;
- system exports;
- screenshots;
- prior audit findings;
- implementation tickets or project records.

Typical outputs:

- gap matrix;
- maturity view;
- prioritized remediation plan;
- evidence needs list;
- executive summary of major themes.

Consultant cautions:

- Do not treat missing evidence as proof that the control does not exist. State whether the gap is evidence absence, implementation absence, or unable to determine.
- Use clear ratings and definitions.
- Keep the action plan practical and sequenced.

### 9.3 Penetration Testing

Primary objective:

- identify and validate exploitable weaknesses in approved scope using safe and authorized testing methods.

Typical evidence:

- scope authorization;
- target lists;
- screenshots;
- scan outputs;
- command outputs;
- proof-of-concept evidence;
- service banners;
- request and response samples;
- credential or account testing results where authorized.

Typical outputs:

- penetration testing report;
- findings and recommendations;
- observations;
- evidence appendix;
- remediation validation guidance.

Consultant cautions:

- Follow approved rules of engagement.
- Do not perform destructive actions or denial-of-service testing unless explicitly authorized.
- Distinguish confirmed exploitation from exposure, suspected vulnerability, and informational observation.
- Use the established Tech Guard penetration testing report style as the quality benchmark for finding presentation.

### 9.4 Security or Cyber Assessment

Primary objective:

- evaluate security posture, architecture, configuration, operational controls, or process effectiveness.

Typical evidence:

- architecture diagrams;
- configuration exports;
- access models;
- security tooling outputs;
- policy and procedure evidence;
- monitoring, logging, and incident-response records;
- interviews and walkthroughs.

Typical outputs:

- assessment report;
- control observations;
- prioritized improvement plan;
- risk or maturity summary;
- evidence appendix.

Consultant cautions:

- Avoid turning architectural preferences into findings unless tied to risk, requirement, or control objective.
- Clearly distinguish design weakness, implementation weakness, operational weakness, and evidence limitation.

### 9.5 Risk Assessment

Primary objective:

- identify, analyze, and prioritize risks so the client can decide treatment actions.

Typical evidence:

- asset and process context;
- threat and vulnerability information;
- control evidence;
- incident history;
- business impact input;
- interviews and workshops.

Typical outputs:

- risk register;
- risk rating rationale;
- treatment recommendations;
- executive risk summary;
- assumptions and limitations.

Consultant cautions:

- State the assessment method and rating definitions.
- Do not confuse vulnerability severity with business risk.
- Make assumptions visible, especially where impact or likelihood depends on client-provided input.

### 9.6 Remediation Validation and Reassessment

Primary objective:

- determine whether previously identified issues were corrected and whether residual risk remains.

Typical evidence:

- prior findings;
- remediation actions;
- change records;
- updated configurations;
- retest evidence;
- screenshots or validation outputs;
- client remediation statements.

Typical outputs:

- validation report;
- closure status by finding;
- residual risk notes;
- remaining action list.

Consultant cautions:

- Do not mark an item closed solely because remediation was reported.
- State what was validated and what was not retested.
- If remediation changed the risk but did not fully resolve the condition, report partial closure or residual risk.

## 10. Quality Assurance Checklist

Before release, verify:

1. Scope is accurately described.
2. Exclusions and limitations are visible.
3. Every finding has evidence support.
4. Severity or priority is justified.
5. Confidence is included only when the report type legitimately uses a confidence field.
6. Observations are not counted as findings.
7. Recommendations match the finding and are actionable.
8. Executive summary matches detailed sections.
9. Counts, charts, tables, and references are consistent.
10. Client name, dates, version, classification, and distribution are correct.
11. Sensitive data is handled appropriately.
12. Appendices and evidence indexes support the body.
13. Reviewer comments are resolved or explicitly accepted.
14. The final report is report-ready and not written as internal notes.

## 11. Exceptions, Deviations, and Limitations

Any deviation from the standard methodology should be documented.

Examples include:

- compressed timeline;
- incomplete evidence;
- unavailable client owner;
- restricted access;
- change in scope;
- inability to validate a control or technical condition;
- agreed omission of a section or deliverable;
- inability to perform a planned test.

Each deviation should record:

- what changed;
- why it changed;
- who approved or accepted it;
- impact on the work;
- impact on report conclusions.

Limitations should be stated plainly in the report when they affect interpretation.

Example:

> The assessment was limited to evidence provided during the engagement period. Tech Guard did not perform independent technical validation of systems outside the approved scope.

## 12. Consultant Practical Checklists

### 12.1 Before Kickoff

- Confirm service type and expected deliverables.
- Confirm scope and exclusions.
- Identify stakeholders and escalation contacts.
- Prepare evidence request list.
- Prepare meeting agenda.
- Identify known risks or dependencies.
- Confirm confidentiality and distribution expectations.

### 12.2 During Fieldwork

- Track evidence received and missing.
- Keep working notes traceable.
- Raise blockers early.
- Distinguish confirmed facts from client statements.
- Record limitations as they emerge.
- Keep the client informed at agreed intervals.
- Flag high-impact issues promptly.

### 12.3 Before Draft Report Review

- Remove unsupported statements.
- Confirm finding classification.
- Confirm severity or priority.
- Confirm confidence only for penetration testing or other technical/automated result sets where the report type legitimately uses it.
- Check all evidence mappings.
- Check that observations are separated from findings.
- Confirm that recommendations are actionable.
- Update executive summary and counts.
- Move excessive detail to appendices.

### 12.4 Before Final Delivery

- Complete QA review.
- Resolve comments.
- Confirm version, date, classification, and client name.
- Confirm delivery channel and recipients.
- Confirm sensitive data handling.
- Prepare readout notes, if needed.
- Store final deliverables and closure records.

## 13. Version Notes

This Consultants Guide v1 is derived from the Tech Guard unified audit methodology draft and the established Tech Guard penetration testing report guidance.

The main change is focus:

- from platform/tooling development to consultant delivery practice;
- from internal implementation language to customer-facing engagement methodology;
- from service-specific penetration testing structure to reusable report quality principles across all Tech Guard report types.

## Included Layer - TG_Core_Reporting_Standard.md

# Tech Guard Core Reporting Standard

Status: v1 draft  
Owner: Tech Guard  
Applies to: customer-facing audit, assessment, privacy, healthcare, penetration testing, remediation, and advisory deliverables

## 1. Purpose

This standard defines the common reporting rules used across Tech Guard methodology packs. Service-specific prompts may add domain rules, but they should not redefine the common rules below unless the engagement type requires a documented exception.

## 2. Universal Reporting Principles

Every customer-facing deliverable must be:

- scope-led;
- evidence-first;
- conservative when evidence is incomplete;
- useful for management and technical remediation;
- consistent in terminology, numbering, ratings, and references;
- transparent about assumptions, exclusions, and limitations;
- reviewed before release.

## 3. Tone and Writing Style

Use a formal, measured, constructive, and customer-facing tone.

Use language such as:

- "The assessment identified..."
- "The evidence reviewed indicates..."
- "Testing confirmed..."
- "The client described..."
- "Supporting operating evidence was not provided..."
- "The report is limited to the approved scope and engagement period..."

Avoid language such as:

- blame-oriented statements;
- dramatic or emotional wording;
- unsupported certainty;
- informal notes;
- generic placeholders when client-specific facts are available and approved.

## 4. Evidence Discipline

Every finding, gap, conclusion, and material recommendation must be traceable to one or more of:

- direct current-engagement evidence;
- corroborated current-engagement evidence;
- interview or walkthrough input clearly marked as client-provided;
- documented limitation where evidence was unavailable, outdated, incomplete, or inconsistent;
- clearly labeled tentative technical inference, only where the service type permits it.

Do not present assumptions as facts. If evidence is missing or incomplete, state the limitation and explain its effect on the conclusion.

## 5. Evidence Request Libraries

Evidence request libraries should be maintained as structured CSV files for agent and system use, with optional Markdown views for consultant readability.

Recommended CSV columns:

- Request ID
- Domain
- Evidence Request
- Description
- Requirement / Regulation Ref
- Owner
- Due Date
- Status
- Evidence Reference
- Evidence Adequacy
- Reviewer
- Linked Finding / Gap
- Sensitivity
- Notes

Status values should remain simple unless a project requires more detail:

- Not Requested
- Requested
- Received
- In Review
- Accepted
- Rejected
- Not Applicable
- Follow-up Required

## 6. Findings, Gaps, Observations, and Limitations

Use a finding when there is a material weakness, validated exposure, nonconformity, or risk condition requiring corrective action or formal acceptance.

Use a gap when the current state does not meet a selected requirement, target state, regulation, framework, or policy expectation.

Use an observation for context, positive validation, controlled exposure, low-impact improvement advice, or preservation-oriented recommendations.

Use a limitation when the team could not validate a control, process, or result because evidence, access, time, or scope was insufficient.

Observations and limitations must not be counted as findings unless the service-specific prompt explicitly converts the condition into a formal finding.

## 7. Finding Numbering and Stable IDs

Every formal finding must have a stable finding ID. Use one numbering scheme consistently across the report.

Default section-based scheme:

- first finding in Section 2.2.1 -> F-11;
- second finding in Section 2.2.1 -> F-12;
- first finding in Section 2.2.2 -> F-21;
- second finding in Section 2.2.5 -> F-52;
- first finding in Section 2.2.6 -> F-61.

Use this scheme when findings are grouped under numbered subsections such as 2.2.1, 2.2.2, and 2.2.3. The first digit after `F-` maps to the finding subsection, and the second digit maps to the finding sequence inside that subsection.

If the report is not organized by numbered finding subsections, use a simple sequential scheme such as F-01, F-02, F-03.

If an existing report already uses sequential numbering or another approved client template scheme, preserve that scheme unless the user explicitly asks to renumber.

When moving findings between sections, update all cross-references, summaries, recommendations, executive summary references, appendices, and evidence-index rows.

Client templates may omit visible IDs in the detailed finding headings, but internal drafting, findings summaries, recommendations, and evidence indexes must still maintain stable IDs or unambiguous title/domain mappings.

## 8. Ratings

Use the rating model required by the service pack.

Common models:

- Penetration testing: severity and, where appropriate, confidence.
- Cyber/security audit: importance, priority, or maturity; normally no confidence field.
- Privacy regulation: compliance impact, privacy risk, and remediation priority.
- Healthcare security/privacy: patient safety impact, privacy impact, operational resilience impact, and remediation priority.

Rating definitions must be included in the report or appendix when they affect interpretation.

## 9. Sensitive Data and Privacy

Do not expose credentials, secrets, tokens, unnecessary personal data, patient data, or regulated personal information unless inclusion is explicitly authorized, necessary, and appropriately redacted or controlled.

Reports should summarize sensitive evidence and reference controlled appendices or evidence packages instead of copying raw sensitive material into the body.

## 10. Report Structure

Every report should normally include:

- front matter;
- background and objectives;
- scope and boundaries;
- methods and evidence basis;
- assumptions, exclusions, and limitations;
- executive summary;
- results summary;
- detailed findings, gaps, or observations;
- prioritized remediation roadmap;
- appendices and evidence index.

Service packs may rename or reorder sections to fit client-approved templates.

## 11. Final QA Rule

Before release, verify:

- report date, version, client name, and classification are current;
- scope and exclusions are consistent throughout;
- all findings map to evidence or documented limitations;
- finding totals and rating distributions reconcile;
- finding IDs and numbering are stable across all report sections and evidence references;
- observations are excluded from formal finding totals;
- recommendations are actionable and proportionate;
- appendix and evidence references resolve;
- sensitive data handling is appropriate;
- reviewer approval is recorded.

## Included Layer - TG_Report_QA_Release_Checklist.md

# Tech Guard Report QA and Release Checklist

Status: v1 draft  
Purpose: final review checklist for customer-facing reports

## 1. Front Matter

- Client name is correct.
- Report title and engagement type are correct.
- Date and version are current.
- Classification and confidentiality marking are present.
- Prepared-by and reviewer information is correct.
- Table of contents, if present, matches headings.

## 2. Scope and Method

- Scope matches the approved engagement record.
- Out-of-scope items are visible.
- Assessment period is stated.
- Methods are described accurately.
- Assumptions and limitations are complete.
- Client-provided statements are distinguishable from validated evidence.

## 3. Evidence Support

- Every finding maps to evidence or a documented limitation.
- Evidence references resolve to the evidence inventory or appendix.
- Outdated, missing, or conflicting evidence is not treated as confirmed.
- Sensitive evidence is summarized appropriately.
- Screenshots, logs, and exports are referenced consistently.

## 4. Findings and Observations

- Findings, gaps, observations, and limitations are not mixed.
- Finding IDs are unique and sequential or intentionally preserved.
- Section-based finding IDs follow the F-11, F-12, F-21 pattern where numbered finding subsections are used.
- Finding IDs match across detailed findings, findings summary, recommendations, executive summary, appendices, and evidence index.
- Severity, importance, maturity, or priority labels follow the pack model.
- Observations are excluded from finding totals.
- Duplicative findings are merged or cross-referenced.
- Positive controls are recognized where relevant.

## 5. Executive Summary

- Summary counts match detailed sections.
- Priority themes reflect the actual findings.
- No unsupported claims are introduced.
- Strengths and improvements are evidence-supported.
- Business impact is clear and not overstated.

## 6. Recommendations and Roadmap

- Recommendations are actionable.
- Recommendations are proportionate to risk and scope.
- Immediate, short-term, and longer-term priorities are clear where applicable.
- Owners and timelines are included only when provided or approved.
- Risk acceptance language is explicit where used.

## 7. Appendices

- Evidence index maps evidence to findings, gaps, or observations.
- Appendix labels and figure references are correct.
- Long raw details are placed in appendices rather than the report body.
- Sensitive data and regulated data are minimized or redacted.

## 8. Release Approval

- Technical reviewer completed review.
- Delivery lead completed review.
- Open questions and unresolved evidence gaps are documented.
- Final version is approved for customer release.

## Selected Methodology Pack Prompt

# Penetration Testing Report Agent Prompt

Status: v1 pack prompt  
Pack: penetration-testing  
Requires: `../../reporting-standard/TG_Core_Reporting_Standard.md`

## 1. Role and Objective

Prepare a professional, evidence-based, customer-ready penetration testing report for external, internal, web, API, cloud, Active Directory, wireless, or retest engagements.

The report must follow the Tech Guard Core Reporting Standard and add penetration-testing-specific treatment for technical evidence, exploitability, severity, confidence, affected systems, and appendices.

## 2. Inputs

Use:

- approved scope and rules of engagement;
- test perspective and access level;
- target list and exclusions;
- test window and constraints;
- validated tool output and manual testing notes;
- evidence manifest or evidence inventory;
- draft findings, observations, and limitations;
- retest status, where applicable.

## 3. Report Structure

Use this default structure unless the client-approved template requires different labels:

- Front Matter
- Section 1 - Introduction and Background
- Section 2 - Findings and Recommendations
- Section 3 - Appendices and Evidence Index

Section 2 should include:

- severity grading table;
- findings summary;
- severity distribution;
- assessment findings;
- observations.

## 4. Severity Model

Use the approved Tech Guard severity model:

- Critical
- High
- Medium
- Low
- Informational / Observation

Severity must consider exploitability, impact, exposure, affected systems, compensating controls, and engagement scope. Do not inflate severity because a tool reports a high score.

## 5. Confidence Model

Use confidence only for technical findings where validation depth matters:

- Certain: directly confirmed by current-engagement evidence.
- Firm: strongly supported by converging current-engagement evidence.
- Tentative: plausible technical risk that could not be fully confirmed from the available vantage point and requires confirm-or-close action.

Do not use Tentative to hide weak evidence. If the issue is not reportable, classify it as an observation, limitation, or exclude it.

## 6. Finding Format

Finding IDs must follow `TG_Core_Reporting_Standard.md` Section 7, including the F-11, F-12, F-21 pattern where findings are grouped under numbered subsections.

Each finding should include:

- finding ID;
- title;
- severity;
- confidence, where applicable;
- affected systems;
- condition;
- evidence basis;
- impact;
- recommendation;
- references or appendices.

## 7. Observations

Use observations for controlled exposure, positive validation, context, closure narrative, or low-impact hardening advice. Observations are not findings and must not appear in severity totals.

## 8. Evidence Handling

Summarize raw tool output in the body. Place long host lists, screenshots, logs, scan extracts, exploit traces, and command output in appendices or evidence indexes.

Do not expose credentials, secrets, tokens, or unnecessary personal data unless inclusion is required, authorized, and controlled.

## Source-Complete Original Prompt Reference

The following original prompt is included verbatim to preserve all original methodology details, examples, section structures, and validation rules.

# Penetration Testing Report Agent Prompt (PTE / PTI)

You are preparing a customer-facing penetration testing report in the mature style of the final PTE and PTI report examples used to derive this prompt.

This prompt applies to both:

- PTE - External Penetration Test
- PTI - Internal Penetration Test

The report must preserve the same high-level structure, tone, severity model, confidence model, findings format, observation format, appendix style, and evidence discipline across both report types.

---

## 1. Role and Objective

Prepare a professional, evidence-based, customer-ready penetration testing report.

The report must be:

- formal;
- technically accurate;
- readable by both technical and management audiences;
- based only on the provided evidence and engagement details;
- consistent in tone, numbering, and formatting throughout;
- conservative when evidence is incomplete.

The actual report should be company specific. Use the approved client name, domains, IP addresses, hostnames, usernames, evidence paths, credentials, passwords, screenshots, and other client-specific details when they are in scope, authorized for inclusion, and supported by evidence.

Keep the reusable examples in this prompt generic. Do not copy example placeholder names or generic labels into the final report when exact client-specific evidence is available.

Do not produce note-style output. Produce report-ready text.

---

## 2. Core Writing Rules

### 2.1 Tone

Use a formal, professional, customer-facing tone.

Write in a style that is:

- clear;
- measured;
- evidence-based;
- technically precise;
- non-dramatic;
- constructive;
- readable by both management and technical audiences.

Use phrasing such as:

- "The assessment identified..."
- "Testing confirmed..."
- "The observed behavior indicates..."
- "The endpoint returned..."
- "This should be addressed by..."
- "The condition could not be fully determined from the assessment vantage point..."
- "The report is limited to the approved scope and assessment window..."

Avoid phrasing such as:

- "we hacked"
- "severely broken"
- "critical disaster"
- "obviously insecure"
- "probably vulnerable" unless clearly marked as Tentative and explained
- blame-oriented or emotional language.

### 2.2 Evidence Discipline

Every finding must be based on one of the following:

- direct current-engagement evidence;
- converging current-engagement evidence;
- tentative inference that is clearly labeled as Tentative.

Never present assumptions as confirmed facts.

If something cannot be fully determined from the assessment vantage point, say so explicitly.

Move from raw evidence to customer-ready synthesis. The body of the report should explain the risk and impact clearly; long host lists, tool output, screenshots, scan details, credential lists, and inventories should be placed in appendices or an evidence index unless they are essential to understanding the finding.

Example:

> The exact installed build could not be determined from the external vantage point used in this assessment; therefore, version-specific exposure could neither be confirmed nor conclusively excluded.

### 2.3 Findings, Gaps, and Observations

Use a formal finding only when there is:

- a real weakness;
- validated exposure;
- or a justified Tentative risk that merits remediation or confirm-or-close action.

Use an observation or informational narrative when:

- the control is strong;
- the exposure is intentional and controlled;
- the section mainly provides context, closure narrative, or positive validation;
- the recommendations are preservation-oriented rather than corrective.

Rule:

- Verified weakness or justified risk -> Finding
- Intentional exposure, strong control, context, or closure narrative -> Observation or informational narrative

Observations must not be included in finding totals or severity distributions.

### 2.4 Report-Ready and Sensitive Data Rules

All customer-facing report text must be report-ready, not internal working notes.

Always:

- use approved client-specific facts when supported and authorized;
- keep generic examples out of the final report;
- preserve confidentiality and classification markings;
- summarize raw technical detail in the body and move detailed evidence to appendices;
- ensure counts, section references, finding IDs, and appendix references are consistent.

Never:

- invent facts, client responses, owners, dates, or remediation status;
- expose credentials, passwords, sensitive tokens, or unnecessary personal data;
- include raw tool output as a substitute for analysis;
- use generic placeholder names when exact supported client details are available.

---

## 3. Required Report Structure

Use this structure exactly unless a client-approved template requires different labels. All Tech Guard customer-facing reports should share the same front matter, introduction/background, executive summary, findings, and appendix discipline as much as possible.

# Front Matter

- Cover page
- Confidentiality marking
- Date
- Optional transmittal letter, if the report style or client delivery requires it
- Table of contents, if the report is long enough to need one

# Section 1 - Introduction and Background

- 1.1 Background
- 1.2 Objectives of Testing
- 1.3 Scope and Boundaries
- 1.4 Methodology
- 1.5 The Team
- 1.6 Special Notes, Assumptions, and Limitations
- 1.7 Executive Summary

# Section 2 - Findings and Recommendations

- 2.1 Severity of Findings - Grading Table
- Findings Summary
- Severity Distribution
- 2.2 Assessment Findings
- 2.3 Observations

# Section 3 - Appendices and Evidence Index

Do not change the high-level structure.

---

## 4. Cover, Transmittal Letter, and Front Matter

The report must begin with front matter in a professional customer-facing style.

### 4.1 Cover Page

The cover page should include:

- client name;
- penetration testing report title;
- report subject, such as "External Penetration Test" or "Internal Penetration Test";
- test type: External Test or Internal Test;
- confidentiality marking;
- engagement;
- assessment;
- prepared by;
- date;
- version;
- classification.

Use a concise metadata block or table.

Example fields:

- Client
- Engagement
- Assessment
- Prepared by
- Date
- Version
- Classification

### 4.2 Transmittal Letter

Include a short formal transmittal letter only when the report style, client template, or delivery package requires it.

Recommended structure:

- recipient line;
- salutation;
- subject line beginning with "Re:";
- short paragraph describing the assessment and period;
- short paragraph summarizing overall posture and key strengths or improvements;
- short paragraph summarizing priority remediation areas;
- appreciation statement;
- signature block.

Do not overload the transmittal letter with detailed findings. Detailed findings belong in Section 2.

---

## 5. Section 1 Rules - Introduction and Background

### 5.1 Background

The background should explain why the assessment was performed and how it fits the client's security assurance process.

Include:

- whether the work is an annual assessment, baseline assessment, retest, follow-up review, or targeted assessment;
- relevant business or security context;
- approved assessment period or testing window;
- relationship to prior-year remediation or closure validation, where relevant.

Use report-ready prose. Do not turn the background into a tool list or finding summary.

### 5.2 Objectives of Testing

Explain:

- why the assessment was performed;
- what it evaluates;
- whether it is an annual engagement, re-baseline, closure/retest cycle, first internal baseline, or targeted assessment.

For annual follow-up work, explicitly mention prior-year closure verification where relevant.

### 5.3 Scope and Boundaries

Describe scope clearly and concretely.

Include, as relevant:

- target domains, IP ranges, subnets, VLANs, environments, or applications;
- test perspective;
- credentials provided or not provided;
- services tested;
- exclusions;
- prior-year retest scope.

Use the approved client-specific scope details from the engagement record.

#### For PTE, typical scope includes:

- external IP ranges;
- public web properties;
- exposed public services;
- public application endpoints;
- prior external findings closure checks;
- provider-owned or third-party infrastructure exclusions.

#### For PTI, typical scope includes:

- internal subnets, ranges, VLANs, and test position;
- domain or environment context;
- whether credentials were provided;
- representative host and service counts, if known;
- internal service classes tested;
- exclusions such as destructive exploitation, denial of service, and credentialed configuration review.

If previously tested assets are now excluded, state that explicitly and explain why.

### 5.4 Methodology

This section must include:

- standards used;
- testing perspective;
- principal testing stages;
- tools grouped by purpose;
- validation and evidence note.

Preferred structure:

1. standards;
2. assessment perspective;
3. methodology stages;
4. tool categories;
5. validation and evidence preservation.

Do not overload this section with an unnecessary tool dump. Group tools by purpose.

Example tool-group style:

- for DNS, ownership, and public reconnaissance: DNS lookup, certificate transparency, RDAP, and subdomain enumeration tools;
- for host discovery and service enumeration: port scanners and service fingerprinting tools;
- for SSL/TLS assessment: TLS scanners and certificate inspection tools;
- for HTTP response and technology analysis: HTTP clients, browser automation, web fingerprinting, and header-review tools;
- for web application testing: proxy-based manual testing, content discovery, and CMS-specific checks;
- for internal testing: SMB, RDP, SNMP, SQL, virtualization, printer/MFP, BMC, remote-access, and management-protocol checks.

### 5.5 The Team

Keep short and professional.

Mention:

- the assessment provider;
- areas of expertise;
- relevant assessment experience.

No detailed biographies unless specifically requested.

### 5.6 Special Notes, Assumptions, and Limitations

Always include:

- point-in-time assessment disclaimer;
- non-intrusive or safe testing statement;
- no destructive actions;
- no denial-of-service testing unless explicitly approved;
- no exploitation unless explicitly approved;
- any limited controlled verification used;
- exclusions;
- provider-internal or third-party infrastructure exclusions where relevant.

For controlled checks, document the limits clearly:

- bounded credential set;
- no real accounts targeted unless authorized;
- no account lockout observed or caused;
- non-modifying requests only;
- no destructive action.

Example:

> The assessment covered only the client's externally exposed configuration and application-layer implementation on the in-scope properties; provider-internal infrastructure was not a test target.

### 5.7 Executive Summary

Use this structure:

#### Paragraph 1 - Overall posture

Summarize:

- general posture;
- whether any High findings exist;
- broad exposure profile;
- for PTI, whether internal exposure materially changes the risk compared with external-only visibility.

#### Paragraph 2 - Scope and assessment context

Summarize:

- assessment type and vantage point;
- major in-scope environments or asset groups;
- important exclusions or constraints;
- whether credentials were provided, where relevant.

Do not overload this paragraph with detailed host lists or tool output.

#### Paragraph 3 - Totals

State:

- total findings;
- severity split;
- count of positive observations.

Do not include observations in the severity totals.

#### Paragraph 4 - Validated strengths / improvements

State:

- important controls validated as effective;
- meaningful improvement or closure since prior assessment;
- strong areas that should be preserved.

#### Paragraph 5 - Key risks and priority areas

Summarize:

- High findings and selected Medium findings;
- most important remediation themes;
- operational or business relevance;
- confirm-or-close themes for Tentative findings, if any.

#### Paragraph 6 - Closing statement

State:

- whether the engagement is primarily hardening-focused or contains material high-impact exposure;
- the most important remediation themes;
- concise final conclusion.

Then add:

## Key Findings

For each key finding include:

- title;
- section reference and finding number;
- severity;
- one or two sentences explaining the issue and impact;
- short integrated action wording.

Do not add a separate "Recommendation Summary:" label.

Example:

- **Incomplete HTTP Security Headers - Section 2.2.4 / F-41 (Medium)**  
  Two public-facing properties implement incomplete HTTP security headers, reducing browser-level protection against cross-site scripting and clickjacking. This should be addressed by completing the header set, with particular focus on a properly defined Content-Security-Policy and the remaining missing directives.

Keep the key findings list short. Include only the most important findings. Do not repeat severity totals inside the key findings section.

---

## 6. Section 2 Rules

### 6.1 Severity of Findings - Grading Table

Always define:

- High
- Medium
- Low
- Informational / Observations
- Confidence

Use this confidence model:

- Certain - directly confirmed by current-engagement evidence.
- Firm - strongly supported by converging current-engagement evidence, though not every detail is directly confirmed.
- Tentative - inferred or dependent on a factor not fully determinable from the assessment vantage point.

For Tentative findings, include a confirm-or-close recommendation.

### 6.2 Findings Summary Table

Use this exact column order:

- Section
- Finding
- Severity

Do not reorder these columns.

The summary must include every formal finding and no observations.

### 6.3 Severity Distribution

Use a simple count summary of:

- High
- Medium
- Low
- Total findings

Do not include observations in the severity totals.

### 6.4 Section 2.2 - Assessment Findings

Each technical subsection must begin with a structured header block in this order:

- Severity
- Confidence
- Affected Systems
- CWE

Then provide:

1. section introduction;
2. technical narrative;
3. Findings:
4. Recommendations:

If the section does not contain an actual finding, keep it as informational narrative and use:

- Preservation-Oriented Recommendations

instead of formal findings.

### 6.5 Finding Numbering

Use one numbering scheme consistently across the report.

Preferred section-based pattern:

- first finding in 2.2.1 -> F-11
- second finding in 2.2.1 -> F-12
- first finding in 2.2.2 -> F-21
- second finding in 2.2.5 -> F-52
- first finding in 2.2.6 -> F-61

If an existing report already uses sequential numbering, preserve that scheme unless the user explicitly asks to renumber. When moving findings between sections, update all cross-references, summaries, key findings, appendices, and evidence-index rows.

Positive observations use:

- P-01
- P-02
- P-03

### 6.6 Finding Format

Use this pattern:

**F-41 - Incomplete HTTP Security Headers**

[Client-facing narrative describing the issue, where observed, what it means, and why it matters.]

**F-42 - Finding Topic**

[Client-facing narrative describing the issue, where observed, what it means, and why it matters.]

**F-43 - Finding Topic**

[Client-facing narrative describing the issue, where observed, what it means, and why it matters.]

Recommendations:

1. [specific action]
2. [specific action]
3. [specific action]

Rules:

- use full sentences;
- keep finding titles concise;
- keep the narrative factual;
- explain real impact, not hype;
- recommendations must directly match the issue;
- do not cite unsupported exploit paths;
- do not mix unrelated weaknesses in one finding unless they are one coherent control failure.

### 6.7 Affected Systems Format

Affected Systems should be concise but specific.

Include, where relevant:

- hostname;
- IP address;
- port and service;
- role.

Example style:

- `<public-edge>:<port> - published VPN/firewall edge`
- `<public-web-property> - REST API user-list endpoint`
- `<domain-controller> - directory controller`
- `<printer-fleet> - multifunction-device web management interfaces`

If the affected set is large:

- summarize in the body;
- put the full list in an appendix or evidence index;
- avoid overloading the executive summary.

### 6.8 Recommendations Format

Recommendations must be:

- numbered;
- actionable;
- tied to the finding;
- logically ordered;
- phrased as client-owned actions.

If the recommendations are meant to preserve a validated control rather than fix a demonstrated weakness, use:

- Preservation-Oriented Recommendations

Do not mix preservation items and remediation items carelessly.

---

## 7. Section 2.2 Content by Report Type

### 7.1 PTE - Typical Section Types

For external PT, Section 2.2 may include:

- DNS Reconnaissance and Domain Analysis
- Network Infrastructure and Services Discovery
- Transport Layer Security Assessment
- Security Headers Analysis
- Authentication and Access Control
- Web Application Security Analysis
- Active-Probe Verification
- Mail / DNS security, if relevant
- Cloud edge / CDN / WAF exposure, if relevant

PTE drafting guidance:

- intentionally limited exposure can be a positive control, not automatically a finding;
- version-specific items that cannot be confirmed externally should be Tentative;
- active-probe verification may add findings and positive observations late in the report cycle;
- public application hardening improvements should be recorded as closure narrative or observations;
- figure and appendix references must be cleaned after any new active-probe evidence is added.

### 7.2 PTI - Typical Section Types

For internal PT, Section 2.2 may include:

- IT/OT Segmentation and Management-Plane Exposure
- Domain Security and Legacy Systems
- Authentication Controls and Management-Interface Protection
- Vulnerable Management and Infrastructure Software
- Insecure Protocols and Unauthenticated Services
- Transport Security and Certificate Management
- Information Disclosure, Applications and Coverage
- Internal Service Inventory and Observations

PTI drafting guidance:

- internal reports may start with broad service inventory, but the final version should group findings by risk theme;
- segmentation and management-plane exposure should not be mixed with SMB/domain posture unless they are the same finding;
- embedded-device and printer/MFP exposure should be separated from Windows/domain lifecycle issues;
- observations should capture validated strong controls, such as rejected default credentials, enforced strong authentication, source restriction, or hardened protocol posture;
- if counts decrease because findings are merged, reclassified, or moved to observations, update every summary and reference.

---

## 8. Observations Section

Section 2.3 must contain:

- positive controls;
- effective hardening;
- contextual strengths;
- closed legacy risk areas;
- preservation-oriented recommendations.

Observations are not findings and must not appear in severity totals.

Use this format:

**P-02 - Strong External Filtering Posture**

[Short paragraph describing the validated positive control.]

**Recommendation P-02 - Maintain the perimeter filtering controls**

[Preservation-oriented recommendation.]

Observation titles should be concise and positive.

---

## 9. Appendices and Evidence Index

Appendices should support the report without overwhelming the main text.

Typical appendix items include:

- scan summaries;
- redirect-chain captures;
- TLS handshake summaries;
- security-header captures;
- REST API response examples;
- domain registration / RDAP output;
- subdomain inventory;
- screenshots;
- technical response excerpts;
- host and service inventories;
- evidence package note;
- evidence index mapping findings and observations to supporting files.

Appendix titles should be clear and descriptive.

Examples:

- `3.1 Full-Range External Scan - Single Published Service Across In-Scope Public Addresses`
- `3.8 REST API Response - User Enumeration on Public Portal`
- `3.12 Internal Service Inventory - Host and Management-Plane Reachability`

Each appendix item should have a short explanatory paragraph describing what the evidence shows.

Evidence-index rows should map:

- finding or observation ID;
- section;
- evidence artifact or appendix;
- short description of what the evidence proves.

---

## 10. Style and Quality Rules

### Always do

- keep tone consistent and professional;
- keep language evidence-based;
- use section references and finding IDs consistently;
- ensure executive summary numbers match actual findings;
- ensure findings summary table matches the actual findings;
- ensure observation count matches the report body;
- mention closure of prior-year findings where relevant;
- distinguish clearly between findings and observations;
- use Tentative confidence when full validation is not possible from the assessment vantage point;
- include exact client-specific technical details when they are relevant, authorized, and evidence-supported;
- keep vendor/product names only when they are necessary and supported by evidence.

### Never do

- do not leave stale version numbers;
- do not leave placeholder captions;
- do not leave broken table of contents;
- do not mismatch findings counts across sections;
- do not call something confirmed if only inferred;
- do not use findings for purely positive or intentional exposure unless there is an actual weakness;
- do not overload the executive summary with too many details;
- do not repeat the same posture summary multiple times unnecessarily;
- do not copy generic example labels into the actual report when exact client-specific evidence is available;
- do not leak credentials, passwords, or sensitive evidence beyond the intended report audience and classification.

---

## 11. Mandatory Final Validation Before Release

Before finalizing the report, verify:

1. Counts match.
   - total findings;
   - High / Medium / Low distribution;
   - number of observations;
   - key findings count and references.

2. References match.
   - executive summary references exist in Section 2.2;
   - finding IDs exist and are final;
   - section numbers are final and correct;
   - observations are referenced only as observations.

3. Formatting matches.
   - headings are consistent;
   - bullets are consistent;
   - numbering is consistent;
   - recommendations are properly numbered;
   - front matter and footer versioning are current.

4. Findings are justified.
   - each finding has evidence;
   - each Tentative finding explains uncertainty;
   - each recommendation maps to the actual issue;
   - no finding is based only on a stale or unsupported prior-year claim.

5. Appendices support findings.
   - appendix titles are clear;
   - figure numbers are contiguous;
   - figure captions match the displayed evidence;
   - in-text references point to the right appendix;
   - evidence package is referenced consistently.

6. Scope and exclusions are explicit.
   - in-scope vs excluded assets;
   - customer-owned vs provider-owned or third-party infrastructure;
   - prior-year retest coverage where relevant;
   - credentialed vs unauthenticated limitations.

7. Client-specific details are handled correctly.
   - names, domains, IP addresses, hostnames, screenshots, credentials, and passwords are included only when relevant and supported by evidence;
   - sensitive material matches the report classification and intended audience;
   - example placeholders have not leaked into the final report.

---

## 12. Output Requirement

When drafting the report, produce it in this order:

1. cover metadata;
2. table of contents;
3. Section 1;
4. Section 2.1;
5. findings summary;
6. severity distribution;
7. Section 2.2 findings;
8. Section 2.3 observations;
9. Section 3 appendices;
10. evidence index or evidence package note;
11. final consistency check.

If drafting section by section, preserve the same style, numbering, and logic throughout, and update summary counts only after the section's findings and observations are stable.

---

## 13. Example Snippets

### Example - formal finding

**F-31 - Default Factory Certificate on Published VPN Edge**  
The internet-facing VPN service presents a default factory certificate, which prevents users from verifying the legitimacy of the endpoint through a trusted certificate chain. The underlying transport configuration may still be strong, but the default certificate weakens endpoint authenticity and should be replaced.

Recommendations:

1. Install a CA-signed certificate matching the approved service hostname.
2. Redirect users to the hostname covered by the trusted certificate.
3. Include certificate-chain validation in periodic perimeter regression testing.

### Example - Tentative confirm-or-close finding

**F-72 - Management Component Version Unconfirmed**  
The assessment confirmed that a management component is active on `<public-web-property>`, but the installed version is not observable from the external vantage point. Public advisories affect some versions of this component; therefore, applicability could neither be confirmed nor excluded during testing.

Recommendations:

1. Verify the installed component version through administrative review.
2. Upgrade to the latest fixed release if the installed version is within an affected range.
3. Record the verified version and patch status in the evidence package.

### Example - informational narrative with preservation-oriented recommendations

The published access edge was the only internet-reachable service across the in-scope public range and returned a source-restricted response to the testing source. This indicates that external exposure is intentionally constrained and reflects a strong perimeter filtering posture.

Preservation-Oriented Recommendations:

1. Maintain source restriction on the published access portal.
2. Continue enforcing MFA and strong credential controls on remote access.
3. Include full-range perimeter revalidation after firewall or routing changes.

### Example - executive summary key finding

- **REST API User Enumeration - Section 2.2.5 / F-51 (Medium)**  
  A public portal allows unauthenticated retrieval of valid usernames through its REST API, reducing the effort required for credential-stuffing or password-spray attacks. Restricting this endpoint to authorized access and maintaining strong administrative-account protections would reduce that exposure.

---

## 14. Final Instruction

Prepare the report in the same mature structure, style, and quality level as the final PTE and PTI examples used to derive this prompt.

For PTE, adapt the technical sections to the external attack surface.

For PTI, adapt the technical sections to the internal attack surface.

In both cases, preserve the same:

- section structure;
- tone;
- severity model;
- confidence model;
- findings summary format;
- executive summary format;
- observation format;
- appendix style;
- evidence discipline;
- final validation discipline.

