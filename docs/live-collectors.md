# Read-only live IAM collectors

`python3 -m collectors` collects native IAM evidence through official cloud APIs and existing local credentials. It writes a graph for the TypeScript analyzer plus a separate native snapshot. Both files are created privately with mode 0600 and are never overwritten. Use `.private/` or another private directory. Do not commit real account inventories.

The collectors are implemented and contract tested. AWS live acceptance is recorded in [the native receipt](aws-live-verification.json): 14 API calls, a retained private snapshot and partial coverage due to policy variables requiring context. Analysis kept effective permissions unproven. Azure and GCP account acceptance remains unverified. Synthetic fixtures do not establish account verification.

| Provider | Collected evidence | Explicit limitations |
| --- | --- | --- |
| AWS | STS account identity, paginated GetAccountAuthorizationDetails users/groups/roles and local managed policies, attached AWS-managed policy default versions, inline statements, group memberships and candidate AssumeRole relationships | Projected to one explicit resource. Resource policies, role trust, SCPs, permission boundaries and session restrictions are not evaluated. NotAction/NotResource, policy variables, unreadable versions and malformed pagination make collection partial. A candidate AssumeRole edge always retains unresolved trust prerequisites. |
| Azure | Expected subscription identity, direct/inherited role assignments applicable to one explicit target scope, native role definitions, Actions/NotActions and DataActions/NotDataActions; optional transitive Graph group membership | NotActions subtracts only that permission block and is never modeled as explicit deny. Control and data planes remain separate. Group lookup failures make collection partial. Deny assignments, PIM, conditions and effective permission evaluation remain outside scope. |
| GCP | Expected project identity, project and accessible folder/organization IAM policies with version 3 requested, native predefined/custom role includedPermissions, conditions and stable evidence references | Cloud Identity group expansion is not implemented. Group bindings, public/domain/federated principal sets, unreadable ancestry/policies or role definitions make collection partial. Project-scope observed grants do not establish access to every descendant resource. |

## Live commands

Authenticate using the official AWS CLI, Azure CLI or gcloud CLI first. The collector does not create credentials, change IAM, select credentials from an incoming graph or allow arbitrary API endpoints.

```sh
python3 -m collectors aws --profile sandbox --account 123456789012 \
  --tenant alder --principal arn:aws:iam::123456789012:user/example \
  --resource 'arn:aws:s3:::example-archive/*' --action s3:GetObject \
  --out .private/aws.json

python3 -m collectors azure \
  --directory-tenant 11111111-1111-1111-1111-111111111111 \
  --subscription 22222222-2222-2222-2222-222222222222 \
  --tenant alder --principal 33333333-3333-3333-3333-333333333333 \
  --resource /subscriptions/22222222-2222-2222-2222-222222222222 \
  --plane control --action Microsoft.Storage/storageAccounts/read \
  --include-groups --out .private/azure.json

python3 -m collectors gcp --project example-project \
  --tenant alder --principal user:reader@example.invalid \
  --action resourcemanager.projects.get --out .private/gcp.json

node dist/src/main.js analyze .private/aws.json
```

These identifiers are fictional templates. AWS requires read-only STS/IAM inventory permissions; Azure requires scope-limited ARM reads and, for optional groups, directory reads; GCP requires metadata, getIamPolicy and role-definition reads on the selected project and ancestors. Missing access remains visible instead of producing a clean no-access result. Use a dedicated least-privilege collection identity. Azure subscription and directory IDs are checked against the CLI context. AWS caller account and GCP returned project identity are checked before graph collection.

## Offline native-provider demonstration

These fixtures contain fictional native API responses and make no network calls. They exercise the same provider normalizers used by live collection, including a managed AWS policy version, Azure exclusions and permission planes, and inherited GCP grants with unresolved directory membership.

```sh
python3 -m collectors.fixtures aws --out artifacts/synthetic-aws.json
python3 -m collectors.fixtures azure --out artifacts/synthetic-azure.json
python3 -m collectors.fixtures gcp --out artifacts/synthetic-gcp.json
node dist/src/main.js analyze artifacts/synthetic-azure.json
```

Use new output paths on subsequent runs. The original `npm run demo` and UI remain available offline.

Each graph edge contains a native observation pointer and SHA-256. The graph collection record binds the entire native snapshot digest. These are provenance and integrity references, not a cloud signature or a proof of authorization. The analyzer always reports effective permissions as `not_proven`. A partial collection forces incomplete analysis status. The live collector and analyzer CLI return exit status 2 for incomplete results while retaining private evidence; automation must inspect this status. The deliberately partial GCP offline fixture also produces analyzer exit status 2. Even complete collection means only that the declared observation scope completed, not that effective cloud permissions are known.

The clients enforce fixed HTTPS authorities, reject credential-bearing or redirected URLs and enforce read-only operation allowlists, request/page/graph bounds and output privacy. Pagination links must remain inside the configured provider scope. Provider tokens are used only in memory and are not included in snapshots. Cloud identity names, policy contents and account IDs are sensitive inventory data. CLI implementations, credential files, configured profiles, the workstation and local state remain trusted. There is no claim of a universal cross-cloud authorization evaluator.

The verification workflow reports branch-inclusive Python collector coverage with tests and synthetic fixture definitions excluded. It also feeds every native provider graph through the TypeScript schema and path analyzer. Tests cover account mismatches, managed-policy version identity, missing access, pagination escape, Azure exclusions/planes, candidate trust and private output handling.

API contracts: [AWS account authorization details](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html), [Azure scoped role assignments](https://learn.microsoft.com/rest/api/authorization/role-assignments/list-for-scope), [GCP project IAM policies](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/getIamPolicy).

The AWS acceptance run used an existing authorized administrator role and a dedicated temporary IAM principal with no grants. Collection and analysis both returned exit 2 for partial coverage. Native IAM identities, exports and credentials were kept private; only the snapshot digest, counts and bounded result are published. The temporary key and principal were deleted after the response verification.
