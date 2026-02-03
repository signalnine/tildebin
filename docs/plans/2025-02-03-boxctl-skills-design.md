# boxctl Claude Skills Design

## Overview

Three Claude Skills to enable effective system troubleshooting using boxctl's 309 monitoring scripts (216 baremetal, 93 k8s).

## Skills

### 1. boxctl-discovery (auto-invoked)

**Purpose**: Find relevant scripts based on symptoms.

**Invocation**: Auto-triggers on explicit troubleshooting patterns, or explicit `/discover`.

**Auto-trigger patterns** (must match at least one):
- User mentions system symptoms: "high load", "disk full", "out of memory", "slow", "failing", "crashing"
- User mentions infrastructure components: "pods", "deployments", "services", "disk", "memory", "CPU", "network"
- User explicitly asks what to check or investigate
- User mentions boxctl or monitoring scripts

**Does NOT trigger on**:
- General coding questions
- Non-infrastructure discussions
- File editing without troubleshooting context

**Behavior**:
1. User describes symptoms in natural language ("disk filling up", "pods crashlooping")
2. Skill runs `boxctl search` to retrieve actual available scripts (prevents hallucination)
3. Skill ranks/filters top 3-5 relevant scripts with reasoning
4. Explains why each script is relevant to stated symptoms
5. Shows requirements (tools, privileges) for each script
6. Hands off to troubleshooting skills for execution

**Key constraint**: Always ground recommendations in `boxctl search` output - never suggest scripts without confirming they exist.

### 2. baremetal-troubleshooting (user-invoked: `/baremetal`)

**Purpose**: Guided investigation of baremetal system issues.

**Behavior**:
1. Run script → interpret output → suggest next step → iterate
2. Fast-path heuristics for obvious patterns (disk full, OOM, high CPU)
3. Correlate findings across related scripts
4. Suggest remediation when root cause identified

**Guardrails**:
- Maximum 10 investigation steps before summarizing findings (user can extend)
- Clear exit conditions: root cause found, escalation needed, or max steps reached
- Use `boxctl --sudo run <script>` for privileged operations
- Claude Code's permission system handles sudo approval

**Privilege Handling**:
1. Check `boxctl show <script>` for privilege requirements before execution
2. Only baremetal scripts in the verified allowlist may use `--sudo`
3. If privilege denied, suggest non-privileged alternatives or manual investigation

### 3. k8s-troubleshooting (user-invoked: `/k8s`)

**Purpose**: Graph-based investigation of Kubernetes issues.

**Behavior**:
1. Namespace scoping by default, cross-namespace on escalation
2. Resource graph traversal: Pod → Deployment → Service → Ingress
3. Check events at entry AND each resource hop
4. Health-state prioritization at each traversal node
5. Traverse downstream (children) or upstream (dependencies) based on symptoms

**Guardrails** (matching baremetal):
- Maximum 10 investigation steps before summarizing findings (user can extend)
- Clear exit conditions: root cause found, escalation needed, or max steps reached
- Cross-namespace escalation requires explicit user confirmation
- Handle mislabeled resources gracefully (missing owner references)

**Key differences from baremetal**:
- Horizontal/relational (graph) vs vertical (stack)
- No sudo required (kubectl handles auth)
- Handle CRD evolution, owner references
- Note 1-hour event expiration window

## Session Context Management

**Problem**: Investigation state must persist between discovery and troubleshooting skills, and across multiple investigation steps.

**Solution**: Skills maintain context in the conversation through explicit state summaries.

**Context elements tracked**:
- Original symptom description
- Scripts already run (with timestamps)
- Key findings from each script
- Current investigation hypothesis
- Ruled-out causes

**State passing pattern**:
```
[discovery] → Outputs: "Suggested scripts: X, Y, Z for symptom: <desc>"
[troubleshooting] → Reads previous messages, tracks:
  - Step 1: Ran X, found: <finding>
  - Step 2: Ran Y, found: <finding>
  - Current hypothesis: <hypothesis>
```

**Stale data handling**:
- After 5+ minutes, note that earlier script output may be stale
- For rapidly-changing metrics (CPU, memory), re-run if correlating with older data

## Error Handling

### Exit Code Semantics

| Code | Meaning | Skill Behavior |
|------|---------|----------------|
| 0 | Healthy, no issues | Report healthy, suggest next area if investigating |
| 1 | Issues detected | Parse and report issues, suggest investigation path |
| 2 | Script error | Check `boxctl doctor`, report missing tool, suggest alternatives |

### Failure Recovery

**Script fails to run (exit 2)**:
1. Run `boxctl doctor` to identify missing tools
2. Report which tool is missing
3. Suggest alternative scripts that don't require the tool
4. If no alternatives, suggest manual investigation steps

**Script timeout**:
1. Report timeout with partial output if available
2. Suggest running with `--timeout` flag if supported
3. Suggest simpler/faster alternative scripts

**JSON parsing fails**:
1. Fall back to plain text output interpretation
2. Note that structured analysis is limited
3. Extract key information from text output

**Permission denied**:
1. Report which operation was denied
2. Suggest non-privileged alternatives
3. Explain what information the privileged script would have provided

## Security

### Script Verification

**Problem**: Trusting script metadata alone for sudo execution is risky.

**Solution**: Allowlist-based verification.

**Implementation**:
1. Skills maintain an embedded allowlist of known-safe baremetal scripts
2. Before `--sudo`, verify script name is in allowlist
3. Allowlist updated when boxctl scripts are updated
4. Scripts not in allowlist cannot use `--sudo` through skills

**Allowlist criteria**:
- Script is read-only (monitoring/diagnostic only)
- Script is part of boxctl distribution (not user-added)
- Script has been reviewed for command injection risks

### Input Sanitization

- Never interpolate user input directly into boxctl commands
- Use explicit argument flags (e.g., `-n namespace` not string concatenation)
- Validate namespace/script names against alphanumeric + hyphen pattern

## Invocation Pattern

| Skill | Invocation | Rationale |
|-------|------------|-----------|
| boxctl-discovery | Auto + `/discover` | Low-risk, solves "what script?" problem |
| baremetal-troubleshooting | `/baremetal` | Explicit consent for privileged ops |
| k8s-troubleshooting | `/k8s` | Explicit consent, namespace scoping |

## Command Reference

```bash
# Discovery uses
boxctl search --tags health,disk
boxctl search --tags pod,crash
boxctl show <script-name>
boxctl list --category baremetal
boxctl list --category k8s
boxctl doctor              # Check tool availability

# Execution
boxctl run <script>              # Non-privileged
boxctl --sudo run <script>       # Privileged (baremetal)
boxctl run <script> -n <ns>      # Namespaced (k8s)
boxctl run <script> --format json  # Structured output for parsing
```

## Implementation Notes

1. **Prefer JSON output** with `--format json` for programmatic analysis
2. **Fall back gracefully** to plain text when JSON unavailable or malformed
3. **Use `boxctl show`** to find related scripts and requirements
4. **Run `boxctl doctor`** at session start to identify available tools
5. **Track investigation steps** explicitly in conversation context

## Example Workflows

### Baremetal: Investigating high load average

```
User: "The server load average is really high"

[boxctl-discovery auto-triggers]
→ Matches: "high load" symptom pattern
→ Searches: boxctl search --tags cpu,load
→ Suggests: loadavg_analyzer, cpu_usage, context_switch_monitor, run_queue
→ Explains: "loadavg_analyzer breaks down load contributors"
→ Notes: "loadavg_analyzer requires no privileges, cpu_usage needs root"

User: /baremetal

[baremetal-troubleshooting]
→ Context: Investigating high load average
→ Step 1: boxctl run loadavg_analyzer --format json
→ Interprets: "Load dominated by I/O wait, not CPU"
→ Hypothesis: Disk bottleneck
→ Step 2: boxctl --sudo run disk_io_latency --format json
→ Finds: "High latency on /dev/sda, 95th percentile 200ms"
→ Step 3: boxctl --sudo run disk_health --format json
→ Finds: "Reallocated sectors warning on /dev/sda"
→ Conclusion: "Failing disk causing I/O wait. Recommend replacement."
```

### K8s: Investigating pod crashloops

```
User: "Pods in production namespace keep crashlooping"

[boxctl-discovery auto-triggers]
→ Matches: "pods", "crashlooping" patterns
→ Searches: boxctl search --tags pod,crash,restart
→ Suggests: container_restart_analyzer, pod_health, event_monitor
→ Explains: "container_restart_analyzer shows restart patterns"

User: /k8s

[k8s-troubleshooting]
→ Context: Investigating crashloops in production
→ Scopes: namespace=production
→ Step 1: boxctl run event_monitor -n production --format json
→ Finds: "OOMKilled events on api-server pods"
→ Traverses: Pod → Deployment (checks memory limits)
→ Step 2: boxctl run resource_usage -n production --format json
→ Correlates: "Memory limit 256Mi, actual usage 280Mi at peak"
→ Step 3: boxctl run pod_health -n production --format json
→ Confirms: "3/5 api-server pods restarted in last hour, all OOMKilled"
→ Conclusion: "Memory limit too low. Recommend increasing to 512Mi."
```

## Validation Feedback Addressed

| Issue | Resolution |
|-------|------------|
| State management undefined | Added Session Context Management section |
| Auto-invocation triggers unclear | Added explicit trigger patterns |
| Read-only tag trust brittle | Added allowlist-based verification |
| Error handling insufficient | Added Error Handling section with recovery paths |
| K8s lacks guardrails | Added matching guardrails to K8s skill |
| JSON parsing assumptions fragile | Added fallback strategy |
