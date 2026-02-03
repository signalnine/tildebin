---
name: boxctl-discovery
description: Use when user describes system symptoms (high load, disk full, pods crashing) or asks what to check - finds relevant boxctl monitoring scripts before execution
---

# boxctl Discovery

Find relevant monitoring scripts from boxctl's 309-script library before running anything.

## When to Use

**Trigger on:**
- System symptoms: "high load", "disk full", "out of memory", "slow", "crashing"
- Infrastructure: "pods", "deployments", "disk", "memory", "CPU", "network"
- Explicit: "what should I check", "how do I investigate"

**Do NOT trigger on:** General coding, file editing, non-infrastructure questions.

## Workflow

```bash
# 1. Search by keywords or list by tags
boxctl search "cpu load"             # Search by keywords
boxctl list --tag cpu                # List by tag
boxctl list --category baremetal/disk  # List by category

# 2. Show requirements for top candidates
boxctl show <script>                 # Check privilege, tools needed

# 3. Report findings - DO NOT RUN YET
```

## Output Format

After discovery, report:

```
Relevant scripts for "<symptom>":

1. **script_name** - <brief description>
   - Requires: <tools>
   - Privilege: <none|root>

2. **script_name** - <brief description>
   ...

To investigate, use /baremetal or /k8s skill.
```

## Key Rules

1. **Search first** - Never guess script names. Run `boxctl search` to confirm they exist.
2. **Show requirements** - Always check `boxctl show` for privilege/tool requirements.
3. **Don't execute** - Discovery only recommends. Execution is for troubleshooting skills.
4. **Top 3-5** - Rank and filter to most relevant, not exhaustive list.

## Common Tag Combinations

| Symptom | Tags |
|---------|------|
| High load/CPU | `cpu,load` or `cpu,usage` |
| Memory issues | `memory,oom` or `memory,leak` |
| Disk problems | `disk,health` or `disk,io` |
| Network slow | `network,latency` or `tcp,connection` |
| Pod issues | `pod,health` or `pod,crash` |
| Service down | `service,health` or `systemd,failed` |
