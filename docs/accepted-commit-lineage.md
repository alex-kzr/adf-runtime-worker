# Accepted commit lineage across owner generations

A confirmed Git delta is durable input data. The native permission receipt of the
execution that produced it remains tied to that execution's provider generation.
Importing accepted history into a newly approved execution must not reactivate or
forward the historical execution's native grants.

The current API already pins predecessor/integration commit SHAs in its approved
request. The worker records that closed selection with the target project,
repository, run, task and execution allocation. Before cherry-picking any selected
delta, it validates both the current target and local source provenance:

- Exactly one private source worktree journal must identify the selected SHA.
- The source request must match its project, repository, run, task, execution and
  allowed paths. Registered checks must all pass for the reviewed tree; approval
  must be explicit and developer/reviewer identities must differ.
- A separate `git_commit` dispatch journal must bind the target writer and exact
  project/run/task/repository. Its approved commit request and successful terminal
  result must name the exact SHA/tree and be durably published to the API. An
  earlier successful `agent_task` result in the writer journal is insufficient.
- The Git object, parent, tree, ADF identity trailers and changed paths must match
  those records. Missing, ambiguous, unpublished or inconsistent history fails
  before cherry-pick and before a new native turn.

New commits also store a versioned `commit_validation` projection. Imports compare
it with independently persisted source request/check/review fields; the projection
cannot declare its own required checks or broaden its original allowed paths.
Historical journals use those existing fields and the separate successful commit
publication, so accepted history does not require replaying old executions.

This minimal implementation requires exactly one matching successful publication
journal. Multiple separately dispatched commit nodes that publish the same delta
are treated as ambiguous and denied. Result retransmission into the original
journal remains supported; broader duplicate-publication coalescing is follow-up
work. Source-writer ambiguity is always denied.

For sealed history from a retired generation, the worker verifies the original
operator manifest/configuration seals and current target allocation. It records a
closed `artifact_import_fence` used only for subsequent validation. This field does
not install a native permission grant. The normal current provider owner assigns
fresh native receipts when executing the new target. Imports in the same active
generation retain the existing receipt-inheritance path.

Execution, repair, test, commit and owner-generation guards remain mandatory.
Retired execution IDs are never reauthorized. Operator manifests, native override
construction, SDK authentication, filesystem masks and API permissions are
unchanged. Ordinary existing subscription use remains the provider path; no paid
API fallback is introduced.

The private journal scan is bounded and uses the existing no-follow, ownership,
mode and file-lock checks. These records are trusted host-worker metadata, not a
cryptographic signature over a hostile same-UID host. Untrusted repositories and
hostile code still require the separate isolation work described in the
[security design](../../../docs/security.md).

See [development](development.md), [sealed profile policy](shared-profile-policy.md),
[native-read policy](native-read-policy.md) and the matching
[umbrella acceptance status](../../../docs/acceptance-status.md). Source tests alone
do not establish installed or native acceptance; that evidence belongs to the
dated umbrella checkpoint.
