# Context

## Vibe-coded entrepreneur

An entrepreneur, indie hacker, agency builder, or technical founder who uses AI coding tools to ship web products quickly without a dedicated security team.

Use this term instead of broader labels like "developer", "startup", or "SMB" when describing the first buyer.

## First Launch Scenario

The initial product scenario: a vibe-coded entrepreneur is about to launch a SaaS landing page and app preview built with AI coding tools, has a public URL, may have a GitHub repository, lacks security confidence, and needs to know today whether they are about to embarrass themselves.

Optimize the first product experience for this scenario before expanding to broader security-team workflows.

## V1 Exclusions

The first version should not optimize for enterprise compliance, SOC2 evidence, deep network scanning, internal asset discovery, WAF tuning, bug bounty workflows, full SAST coverage, or exhaustive pentest claims.

These exclusions keep the product focused on vibe-coded entrepreneurs instead of security-team workflows.

## Launch Safety Scorecard

A plain-language security readiness assessment for a web product before public launch, customer outreach, paid ads, or investor/customer demos.

The scorecard should translate technical findings into business risk, confidence, and next actions for a vibe-coded entrepreneur.

The free scorecard performs a real unauthenticated assessment of public URL behavior and returns a score, the top validated risks, evidence, and immediate next actions.

Paid workflows unlock authenticated checks, repeat monitoring, repo-aware MCP/CLI checks, dependency and CVE intelligence, history, and remediation workflows.

## Launch Readiness Score

A business-oriented score that estimates whether a vibe-coded entrepreneur can safely launch, demo, or drive traffic to a product without obvious avoidable security exposure.

The Launch Readiness Score is not a completeness claim about all possible vulnerabilities. It should reflect severity, exploitability confidence, business impact, and whether the risk should block launch.

## Launch Blocker

A security finding that should stop a vibe-coded entrepreneur from launching, demoing, or driving paid traffic until fixed.

Launch Blockers include plausible customer data exposure, unauthorized admin or user access, leaked secrets, payment compromise, account takeover, and high-confidence exploitable XSS, SQL injection, SSRF, or remote code execution.

Lower-risk hardening advice may reduce the Launch Readiness Score, but should not be described as a Launch Blocker.

## Launch Safety Pro

The first paid offer for vibe-coded entrepreneurs who want to keep shipping while reducing launch risk.

Launch Safety Pro includes authenticated scans, scan history, scheduled monitoring, repo-aware MCP/CLI checks, dependency and CVE intelligence, and prioritized remediation workflows.

Use this term instead of selling "unlimited pentesting"; the promise is keeping a fast-moving product launch-safe.

## Launch Safety PR Reviewer

A low-noise paid workflow that reviews product changes in pull requests and comments only when it detects a new or worsened Launch Blocker or high-confidence risk.

The reviewer should focus on exposed secrets, dangerous authentication changes, dependency or CVE risk, newly public admin or API routes, payment or security configuration changes, and scan evidence tied to a preview URL.

Do not use this term for generic linting or broad best-practice comments.

## Launch Safety

The promise that a vibe-coded entrepreneur can launch, demo, or run ads without obvious avoidable security failures.

Launch Safety focuses on practical risks like exposed secrets, broken authentication, public admin pages, leaked customer data, unsafe payment flows, missing access controls, and high-confidence exploitable web vulnerabilities.

Use Launch Safety as the public brand because it sells the entrepreneur outcome.

VibePenTester may remain as repository and tool lineage, but should not be the primary public promise.

## Launch Safety System

A two-surface product for vibe-coded entrepreneurs: a URL-first Launch Safety Scorecard for fast public-facing assessment, plus an MCP/CLI workflow for deeper repo-aware checks and fix guidance.

Use this term when describing the full commercial product. The URL scorecard is the acquisition surface; the MCP/CLI is the developer workflow surface.

## Single-repo Launch Safety Platform

The Launch Safety System should live in one public repository, not as separate SaaS and MCP repos.

The public repo should support a freemium acquisition loop: free URL scorecards, practical launch-safety advice for X and YouTube, and a deeper MCP/CLI workflow inside the same product home.

## Freemium Launch Safety Loop

The acquisition loop for the public product: publish practical launch-safety advice on X and YouTube, send builders to a free URL scorecard, capture the result as a shareable report, then upsell repeat scans, deeper MCP/CLI checks, remediation guidance, team history, and automation.

Use this term when describing growth mechanics. Do not describe the free product as a toy scanner; it should be useful enough to expose real obvious launch risks while reserving depth, memory, automation, and repo-aware guidance for paid workflows.

## Launch Safety Aha Moment

The moment when a vibe-coded entrepreneur pastes a URL or opens a pull request and quickly receives a plain-language Launch Readiness result with a real issue they can fix before users see it.

The aha moment is not that an AI pentester ran. It is that the product prevented an embarrassing launch mistake.

## Launch Safety Teardown

Public educational content for X and YouTube that inspects an AI-built or fast-shipped product, shows one avoidable security risk pattern, explains the business impact, and gives a short fix checklist.

The call to action for a Launch Safety Teardown should be the free Launch Safety Scorecard.
