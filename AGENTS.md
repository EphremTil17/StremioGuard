# Red-Team Post-Condition Verification & Invariant Protocol

This workspace rule enforces the **Red-Team, Post-Condition-Driven Review Mindset**, the **6 Core Review Lenses**, and the **7-Step Mandatory Pre-Completion Protocol** across all design, implementation, and review workflows in this repository.

---

## The Core Philosophical Principle

> **"Review is not checking whether code follows the plan. It is checking whether the desired invariant remains true when every dependency behaves badly."**

The fundamental cognitive difference:

- **Implementation Confirmation (Anti-Pattern)**: Checking intention, syntactic compliance, and mocked interactions.
- **Adversarial Mechanism Tracing (Required Standard)**: Assuming the proposed mechanism is false until tracing how it actually behaves across runtime boundaries, dynamic time evolution, degraded states, and failure post-conditions.

---

## The 6 Core Review Lenses

| Review Lens                 | The Exact Question to Ask                                                           | What It Exposes in Practice                                                                                               |
| :-------------------------- | :---------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------ |
| **End-to-End Data Path**    | _Does the leaf container receive the override, not merely the Compose CLI process?_ | Variables passed to Compose CLI ignored due to `env_file` precedence unless explicitly projected in `environment:`.       |
| **Time Evolution**          | _What happens on tick 1, tick 10, and during a log storm?_                          | `--since` on tick 1 missing pre-poll logs; unbounded log growth over retry loops.                                         |
| **Fail-Closed Invariant**   | _What if the state file is corrupt, empty, locked, or cannot be written?_           | Lockout markers failing open; write failures aborting emergency shutdown before exit 78.                                  |
| **Post-Condition Proof**    | _Did the external command actually achieve the physical post-condition?_            | `check=False` plus a success log proving only an attempt, not actual container death or file unlinking.                   |
| **Control-Plane Recursion** | _What does the external supervisor (systemd/cron) do after the process exits?_      | `Restart=always` defeating watchdog exits unless `RestartPreventExitStatus=78` and persistent lockout state are enforced. |
| **Test Adequacy**           | _Does the test prove runtime behavior or merely that a mock call was dispatched?_   | Tests verifying subprocess arguments rather than resolved container environment or verified kernel state.                 |

---

## The 7-Step Mandatory Pre-Completion Protocol

Before declaring any Implementation Plan, Code Change, or Walkthrough complete, you MUST execute and document this 7-step verification:

### 1. State the Invariant

- Define the primary safety and availability invariant in one clear, unambiguous sentence.
- _Example_: _"If VPN trust is lost, protected services cannot continue, retries cannot become an endless uncontrolled loop, and recovery requires deliberate evidence."_

### 2. Trace the Vertical Data Path

- Trace every changed value, configuration flag, and environment variable through every runtime boundary:
  $$\text{caller} \longrightarrow \text{subprocess env} \longrightarrow \text{Compose interpolation} \longrightarrow \text{env\_file precedence} \longrightarrow \text{container env} \longrightarrow \text{process behavior}$$

### 3. Simulate the 7 Failure Topologies

- **First failure tick**: Account for temporal lag and events that occurred before the poll ($t_{\text{cause}} < t_{\text{detect}}$).
- **Repeated failure ticks**: Verify $O(1)$ resource, memory, log, and retry scaling across $t=10, t=100$.
- **Recovery**: Verify clean state reset and safe service resumption.
- **Corrupted state**: Ensure 0-byte, partial, or malformed state markers block normal operations safely (fail closed).
- **Failed write**: Isolate emergency shutdowns in nested `try/finally` blocks so write failures cannot abort shutdown or exit 78.
- **Failed cleanup**: Ensure marker removal failures raise explicit errors rather than starting on stale state.
- **Supervisor restart**: Verify that process exits interact correctly with external orchestrators (`systemd`, `cron`).

### 4. Distinguish "Attempted Action" from "Verified Post-Condition"

- Never equate dispatching a command (`compose stop`, `docker stop`, `unlink`) with achieving the physical side-effect.
- Query the ground-truth kernel/filesystem state before reporting success or transitioning state.

### 5. Audit Mock Blind Spots

- For every test using mocks, explicitly ask: _"What real-world runtime behavior does this mock NOT prove?"_
- Ensure integration tests assert against resolved container configurations and real failure responses.

### 6. Execute Concrete Counterexample Searches

- Treat any claim containing _"always"_, _"guaranteed"_, _"fallback"_, or _"fail-closed"_ as an active target for a counterexample search.
- Actively try to break the claim before proposing it.

### 7. Report Unresolved Uncertainty Explicitly

- Never let a green unit test convert an unverified heuristic into an asserted guarantee.
- Clearly label heuristics as best-effort in docstrings, user messages, and documentation.

---

## Principal-Engineer Development Method

Apply this method before implementation begins, while implementing, and during
review. The goal is not merely to produce code that satisfies the written plan;
it is to make the plan falsifiable and to preserve the system's invariants when
the plan's assumptions fail.

### Turn Requirements into Proof Obligations

For each requirement, write down all of the following before selecting an
implementation:

1. **Outcome** — the observable user or system result.
2. **Invariant** — what must never become true, including during failure.
3. **Authority** — which component is the source of truth for the decision or
   state; do not duplicate or recompute authority without an explicit design
   decision.
4. **Runtime owner** — the process, container, service manager, or kernel
   feature that actually enforces the outcome.
5. **Evidence** — the concrete observation that proves the outcome happened.
6. **Invalidation signal** — the condition that proves the design assumption
   was wrong and requires a deliberate update rather than a silent fallback.

If any item is unknown, record it as an assumption and investigate it before
claiming the design is complete.

### Design for States and Transitions, Not Just Happy-Path Functions

For any lifecycle, update, security, or retrying feature, enumerate states and
legal transitions. At minimum account for:

```text
uninitialized -> preparing -> healthy -> degraded -> recovering -> locked-out
                                      \-> unsafe
```

For every transition, specify:

- the trigger and its source of truth;
- side effects and their required ordering;
- idempotency behavior if the transition repeats;
- the state observed after a process crash between side effects;
- the explicit recovery action and who is authorized to take it.

Do not use a boolean or counter as a substitute for a state machine when the
system has materially different failure or recovery behaviors.

### Preserve Semantic Boundaries

- Prefer forwarding authoritative, already-computed data to recomputing it in
  a presentation, orchestration, or compatibility layer.
- Do not add shims that silently preserve a retired architecture. A changed
  upstream boundary must fail clearly and force a deliberate migration.
- Keep security controls, health observations, candidate validation, and
  lifecycle promotion as distinct decisions. A signal that is advisory in one
  layer must not be presented as proof in another.

---

## Review Procedure

### First, Build an Independent Mental Model

Before reading the proposed solution in detail, identify:

- the affected user-visible behavior;
- the safety, integrity, availability, and confidentiality invariants;
- all persistent state, external processes, supervisors, and trust boundaries;
- the worst plausible outcome if the feature is wrong.

Then compare the implementation to that model. Do not let the implementation's
structure define the review scope.

### Review the Negative Space

For each changed branch, ask what happens when the condition is false, the
dependency returns malformed data, the command returns nonzero, the process is
interrupted, or the same event repeats. Search specifically for:

- environment-variable precedence and configuration split-brain;
- time-of-check/time-of-use races and stale reads;
- partial writes, failed deletes, and permissions failures;
- broad exception handlers that swallow termination/control signals;
- unbounded work in polling loops, logs, retry queues, or caches;
- optimistic success messages emitted before verification;
- stale supervisor, container, or generated-file state;
- recovery paths that can automatically undo a safety lockout.

### Test the Mechanism at the Correct Boundary

- Unit tests prove local transformations and decision logic.
- Integration tests prove configuration precedence, command construction,
  persisted-state handling, and inter-component handoffs.
- End-to-end or controlled-container tests prove the final observable
  post-condition when risk warrants it.

Mocks are appropriate for forcing faults, but a mock assertion alone is not
proof that an external dependency accepted the command or that the desired
state resulted. Where a live dependency is impractical, assert the closest
authoritative artifact: resolved Compose configuration, exit status, generated
manifest, filesystem mode, container inspect state, or process state.

### Severity and Review Reporting

Classify findings by invariant impact and likelihood, not by diff size or how
easy they are to fix:

| Severity | Meaning | Expected action |
| :-- | :-- | :-- |
| **Blocking / Critical** | A safety, security, data-integrity, or primary availability invariant can be violated in a realistic path. | Do not approve or merge until resolved and regression-tested. |
| **High** | A primary feature or promised fallback is ineffective for a supported configuration, failure mode, or lifecycle path. | Resolve before merge unless the scope is explicitly reduced and documented. |
| **Medium** | Recovery, observability, maintainability, or edge-case correctness is materially impaired, but the principal invariant remains intact. | Resolve in the current change when inexpensive; otherwise create a concrete tracked follow-up. |
| **Low** | Clarity, diagnostics, naming, test precision, or future-risk improvement without a current behavioral defect. | Fix opportunistically; do not disguise it as a blocker. |

Every finding must include: the concrete failing path, affected invariant or
promise, evidence from the code/runtime contract, and the smallest safe fix.
Do not manufacture findings to appear thorough; say "approved" when the
evidence supports it.

---

## Definition of Done

Do not declare an implementation, plan, or walkthrough complete until all of
the following are true:

- Requirements, invariants, runtime owners, and recovery semantics are clear.
- The vertical data path and state transitions have been traced.
- High-risk counterexamples have been attempted, not merely listed.
- Success is backed by verified post-conditions rather than dispatched calls.
- Tests cover the regression and the failure path that motivated the change.
- Documentation distinguishes guarantees, defaults, fallbacks, and heuristics.
- The final report separates confirmed facts, informed inferences, and open
  questions.
