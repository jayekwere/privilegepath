# PrivilegePath threat model

## Overview

PrivilegePath analyzes observed IAM relationships using a TypeScript CLI and stateless local web evaluator. A restricted Python importer accepts saved exports. A separate operator-only Python CLI collects native read-only AWS, Azure and GCP evidence. The final Node container has no Python collector runtime. Output paths and recommendations describe observations and unresolved prerequisites; effective permissions always remain not_proven. One independent fresh-context read-only architecture review informed this model; it does not establish audit coverage or live account acceptance.

| Component | Source and role |
| --- | --- |
| CLI and local web startup | `src/main.ts:4` |
| Strict graph and traversal | `src/graph.ts:43`, `src/graph.ts:83` |
| HTTP ingress and fixed assets | `src/io.ts:10`, `src/io.ts:21` |
| Restricted offline importer | `importer/normalize.py:10` |
| Live operator CLI | `collectors/__main__.py:76` |
| Native transports, evidence and graphs | `collectors/core.py:48`, `collectors/core.py:93`, `collectors/core.py:137` |
| Provider semantics | `collectors/providers.py:31`, `collectors/providers.py:262`, `collectors/providers.py:394` |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| CLI analyze/demo | Graph input and stdout | analyze argument or samples/aws.json | Selected JSON file or cwd/samples/aws.json | Local operator and output consumer | Strict graph semantics and traversal bounds after JSON parsing | `src/main.ts:4`, `src/io.ts:8`; host file-byte budget is caller-owned |
| Host web | Stateless evaluator | HOST/PORT or defaults | 127.0.0.1:8080; request/response in memory | Reachable clients | Host/Origin, JSON content type, 1 MiB request bound, static allowlist | `src/io.ts:10`, `src/io.ts:21`, `src/io.ts:46` |
| Compose web | Evaluator and static files | WORKDIR /app, HOST=0.0.0.0, loopback publication | /app/samples/aws.json, /app/web; host 127.0.0.1:8080 | Container peers and loopback clients | UID 10001, read-only root, no capabilities, no-new-privileges, resource limits | `Dockerfile:8`, `Dockerfile:13`, `compose.yaml:4`; no collector runtime |
| Offline importer | Source and normalized export | Operator-selected source/output arguments | Selected local paths | Operator and later analyzer | 1 MiB input acceptance check and restricted export semantics | `importer/normalize.py:10`, `importer/normalize.py:41`; ordinary write_text does not enforce private/no-overwrite output |
| AWS collector | Native identity-policy inventory | Explicit profile/account/principal/resource | Fixed STS us-east-1 and global IAM HTTPS endpoints | Trusted AWS CLI credential mechanism and AWS | Read-only allowlist, expected caller account, pagination and policy-version identity checks | `collectors/__main__.py:100`, `collectors/core.py:48`, `collectors/providers.py:31` |
| Azure collector | Applicable ARM grants and optional directory membership | Explicit directory/subscription/resource, az context | management.azure.com; optional graph.microsoft.com group transitiveMembers | Azure CLI, collector token memory, ARM and Graph | Credential context, authority/scope and pagination checks; control/data planes and exclusions retained | `collectors/__main__.py:14`, `collectors/providers.py:262`, `collectors/providers.py:362` |
| GCP collector | Project/ancestor allow policies and role definitions | Explicit project; active gcloud credential context | cloudresourcemanager.googleapis.com/v3 metadata and getIamPolicy; iam.googleapis.com/v1 roles | Trusted gcloud, Resource Manager and IAM | Returned project identity, fixed HTTPS authorities, read-only POST/GET, ancestry bounds | `collectors/__main__.py:55`, `collectors/providers.py:394`; no explicit operator-account selection |
| Live CLI | Normalized graph file | --out P | Exactly selected P, with whole-snapshot digest | Private operator and analyzer | 0600 staging and no-overwrite hard-link publication | `collectors/__main__.py:139`, `collectors/core.py:304` |
| Live CLI | Native snapshot | P.stem plus .snapshot.json in P's parent | Example .private/aws.snapshot.json for .private/aws.json | Private evidence readers | Bounded captured calls/observations; private no-overwrite publication | `collectors/__main__.py:96`, `collectors/core.py:150`, `collectors/core.py:188`, `collectors/core.py:304` |
| Offline native fixtures | Graph and native fixture files | Synthetic transport and --out P | P plus P.with_suffix(.native.json) | Offline operator and CI artifact readers | Same provider normalizers, no network, private output helper | `collectors/fixtures.py:20`, `collectors/fixtures.py:182` |
| Verification CI | Synthetic graphs, analyses and coverage | Fixture loop and artifact upload | artifacts/, selected evidence, 14-day verification-evidence | GitHub artifact readers | contents:read, checkout credentials disabled, synthetic sources | `.github/workflows/verify.yml:7`, `.github/workflows/verify.yml:17`; real inventory must remain outside export paths |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets are confidential cloud inventories and policy documents, collection credentials, graph tenant/cloud consistency, evidence fidelity and honest analysis status. An input author can choose submitted graph labels, policies and asserted hashes. A reachable web client can request unauthenticated local evaluation. Neither actor initially controls collector credentials, trusted provider tools, the host, private evidence directories or repository policy. Host administrators and trusted maintainers already control local code and state and are outside isolation (`SECURITY.md:6`).

Tenant labels in a graph enforce internal consistency, not authenticated tenant ownership. Strict schemas, endpoint and relationship checks reject cross-tenant/cloud ambiguity; a declared collection provider must match its nodes. Traversal has node, edge, work, path and depth bounds. Partial collection forces incomplete analysis and CLI exit status 2; truncated analysis also remains incomplete (`src/graph.ts:83`, `src/graph.ts:104`, `src/graph.ts:139`, `src/main.ts:4`). Web ingestion has a separate 1 MiB streaming bound; direct CLI/library callers own their byte budget.

Native collection cannot be invoked through the HTTP evaluator. AWS uses explicit account scope and an allowlist of STS/IAM read operations. Identity policies project onto one selected resource. NotAction, NotResource, policy variables, unreadable managed versions and incomplete pagination make collection partial. Candidate AssumeRole edges retain unresolved trust; resource policies, SCPs, boundaries and sessions remain unevaluated (`collectors/core.py:48`, `collectors/providers.py:31`).

Azure verifies directory/subscription context, reads applicable inherited/direct assignments and resolves native role definitions. NotActions subtracts only its permission block and is not explicit deny. Control/data planes and unresolved conditions stay distinct. Optional directory expansion is an independent Graph read boundary; unavailable membership makes collection partial. Deny assignments and PIM are excluded (`collectors/__main__.py:14`, `collectors/providers.py:262`, `collectors/providers.py:362`).

GCP verifies returned project identity and reads accessible project/folder/organization allow policies and native role definitions. Ancestry has cycle/depth limits. Unexpanded groups, unsupported public/domain/federated sets, unreadable ancestors or invalid/deleted roles remain explicit issues. Conditions, deny policies and principal access boundaries are not evaluated. Project observations do not establish access to every descendant resource (`collectors/providers.py:394`).

Capture limits requests, aggregate evidence bytes, observations and issues; native response size checks and timeouts are separate controls. HTTPS authorities, redirect rejection and scoped pagination keep credentials within configured provider recipients. Tokens are in-memory transport state and not snapshot fields (`collectors/core.py:93`, `collectors/core.py:137`, `collectors/core.py:202`). Provider CLIs, PATH, proxies, credential stores and active profiles are trusted operator configuration.

Observation pointers and SHA-256 references preserve local integrity relationships; they are not cloud signatures. The analyzer does not authenticate an arbitrary submitted snapshot. Collection complete means only the declared observation scope completed. Permissions always remain not_proven, and missing paths never prove absence of access or safe removal (`collectors/core.py:188`, `collectors/core.py:273`, `src/graph.ts:83`).

Private creation requests 0700 for new parent directories and 0600 for files, but existing parent privacy and ownership remain host responsibilities. Graph and snapshot publish separately, not as an atomic pair. Build exclusions cover private paths, snapshots, keys and environment files; arbitrary sensitive output names still require private placement (`collectors/core.py:304`, `.dockerignore:11`). Live account acceptance remains unverified. There is no authenticated multi-tenant storage service, IAM mutation engine or provider authorization simulator.

## Attack Surface, Mitigations, and Attacker Stories

These are review hypotheses, not validated findings.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High | Attacker-controlled pagination sends a bearer token to another recipient | A malicious or compromised provider response | Credential disclosure | Fixed HTTPS authorities, no redirects, scoped pagination | Preserve authority validation before token retrieval and request dispatch | `collectors/core.py:93`, `collectors/providers.py:228` |
| Medium | Missing policy/group access is presented as clean absence | Restricted provider permissions or unsupported semantics | Unsound access recommendation | Explicit issues, partial status, nonzero incomplete CLI status, not_proven output | Require declared scope and inspect incompleteness before decisions | `collectors/providers.py:31`, `collectors/providers.py:262`, `collectors/providers.py:394`, `src/main.ts:4` |
| Medium | Forged graph evidence is mistaken for authenticated native access | Ability to submit JSON | Misleading analysis | Strict consistency checks and explicit observation-only semantics | Obtain evidence through the trusted collector and verify snapshot relationships | `src/graph.ts:43`, `src/graph.ts:83`, `collectors/core.py:188` |
| Medium | Cloud graph or policy input exhausts a shared evaluator | Reachable HTTP listener or broad collection scope | Availability loss | HTTP and collection bounds, bounded traversal, timeouts | Apply deployment-level concurrency and resource limits | `src/io.ts:10`, `src/graph.ts:139`, `collectors/core.py:137` |
| Medium | Real native inventory enters an image or public artifact | Operator chooses public output paths | Confidentiality loss | Private output helper, build exclusions, synthetic CI | Keep native material under private operator-controlled paths | `collectors/core.py:304`, `.dockerignore:11` |
| Low | Azure exclusions or candidate role assumption is overstated | Misreading observed semantics | Incorrect local conclusion | Separate planes, per-grant subtraction, unresolved trust and no automatic removal | Preserve provider-specific evidence and limitations | `collectors/providers.py:262`, `src/graph.ts:83` |

## Severity Calibration (Critical, High, Medium, Low)

Critical requires evidence of broad unauthorized authority beyond this read-only design; an observed grant path is not such evidence. High can apply to a concrete collector credential disclosure to an attacker-controlled recipient. Medium covers bounded confidentiality, availability or consequential evidence-integrity failures with actual prerequisites. Low covers local-only defects or misleading presentation without new authority. A graph's synthetic tenant label is not an authenticated account boundary. Trusted host control, speculative effective access and missing live credentials do not by themselves establish a finding.

Repository: https://github.com/jayekwere/privilegepath
Version: 7f91ad8d37f2d9b4e011e374d2161cd6e56b5593
