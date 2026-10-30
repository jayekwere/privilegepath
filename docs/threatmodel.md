# PrivilegePath threat model

## Overview

Intended use: the runnable repository implementation and its documented local demo. The user requested an open-source implementation with honest security scope. This model describes inspected source, not a security certification or a claim of complete audit coverage.

Data flow: Offline provider evidence --> explicit normalization contract --> tenant/cloud graph validation --> bounded traversal --> candidate paths and observed denies --> owner-review recommendations.

| Component/source | Responsibility |
| --- | --- |
| `importer/normalize.py:10` | Restricted offline provider export normalization |
| `src/graph.ts:35` | Strict graph and evidence contract |
| `src/graph.ts:62` | Tenant/cloud semantics, bounded traversal and explicit not-proven output |
| `src/io.ts:21` | Stateless local workbench |

| Deployment or workflow | Resource/configuration and effective location | Readers, writers or recipients | Enforcing control or unknown |
| --- | --- | --- | --- |
| Graph evaluation | Caller-selected JSON or POST input; memory only | Local evaluator | Strict graph semantics; tenant consistency; no authenticated multi-tenant store |
| Offline importer | Caller-selected source/output paths; explicit resolved action/resource mapping | Trusted local operator | Unsupported constraints reject; output is a normalized observation graph |
| Web listener | HOST or 127.0.0.1; PORT or 8080 | Reachable clients, no accounts | Host/origin/size controls; loopback default; bounded graph work |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets: Accuracy of relationships, path evidence, completeness status and the distinction between observations and effective authorization. Real identity snapshots may contain sensitive metadata.

An input author can supply graph labels, hashes and timestamps. Schema consistency does not authenticate their cloud origin. Membership, candidate assumption and grants have explicit endpoint semantics; cross-cloud or cross-tenant edges reject. Traversal returns simple bounded candidate paths, preserves observed deny evidence and unresolved conditions, and marks truncation. No path is converted to a proven provider permission. Explicit grants without usage evidence receive no removal recommendation.

Host administrators, private configuration owners and trusted repository maintainers can alter code, files and private state. They are trusted. An ordinary input author does not gain those capabilities by supplying JSON. Public demo credentials represent synthetic roles in one trusted local demonstration. The local stateless TypeScript evaluators do not establish authenticated service tenancy; the Python services derive tenancy from trusted identities. External assertions retain their stated trust prerequisites.

Provider collection and authorization simulation are unimplemented. AWS SCPs/boundaries/resource policies/trust, Azure PIM/denies/inheritance, and GCP denies/boundaries/hierarchy are not evaluated. Missing paths never prove absence of access.

## Attack Surface, Mitigations, and Attacker Stories

These are threat scenarios and review obligations, not reported vulnerabilities. Priority describes plausible impact if the named control fails in its stated deployment. The source table above identifies the actual consumers and controls.

| Priority | Scenario and potential capability gain | Existing source-established controls | Additional mitigation or prerequisite |
| --- | --- | --- | --- |
| High | A reviewer mistakes a candidate grant path for effective access and removes needed permissions. | Every report states not_proven with no proven permission set; recommendations require owner review and simulation. | Evaluate provider-specific denies, contexts and trust before change. |
| Medium | A malformed graph crosses tenants or uses invalid relationship endpoints. | Duplicate, dangling, cloud, tenant and endpoint checks reject. | Treat this as input consistency, not authenticated tenant ownership. |
| Medium | A cyclic or branching graph exhausts a local evaluator or silently omits a path. | Cycle checks, depth/state/work/path caps and explicit incomplete status. | Check completeness before interpreting absence of paths. |
| Low | A claimed source hash is accepted as authenticated cloud provenance. | Documentation labels input evidence as supplied observations; demo hashes point to included synthetic records. | Verify source artifacts and collector identity outside this analyzer. |

## Severity Calibration (Critical, High, Medium, Low)

Critical would require a credible unauthenticated path to broad privileged external execution or equivalent cross-tenant compromise. This model does not establish such a path. A fictional sandbox state change is not critical cloud compromise.

High includes a reachable authorization, approval or gate bypass that grants a materially new capability over another tenant or a deployment decision, with the required privileged consuming workflow present. An input author changing their own local file is a counterexample.

Medium includes bounded local denial of service, decision-fidelity loss or evidence misbinding under realistic deployment prerequisites. Merely changing trusted policy as its administrator is a counterexample.

Low includes limited presentation/integrity confusion without a new privileged operation. A string that is safely rendered as text is controlled behavior, not an injection finding. Confidence depends on source and executable evidence, independently of impact.

One fresh-context independent read-only architecture review informed this model. Source changed during construction; the parent rechecked the controls and source anchors after the reported discrepancies were fixed. Verified negatives are recorded in tests and verification artifacts. External account behavior remains unverified wherever stated.

Repository: https://github.com/jayekwere/privilegepath
Version: 8e602b44053cffe18ab47a58beaa3266052f75c6
