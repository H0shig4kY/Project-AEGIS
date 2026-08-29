# AEGIS / ARGUS
## From reconnaissance snapshots to attack-surface intelligence

**Authorized Reconnaissance, Asset Discovery and Lifecycle Analysis Engine**

---

# 1. The problem

Reconnaissance tools are very good at answering:

> What can I see right now?

But a security assessment often needs to answer more:

> What existed before?

> What changed?

> What disappeared?

> Did it really disappear, or was one scan inconclusive?

> What came back?

> How are the discovered objects connected?

> Which evidence supports that conclusion?

AEGIS is being built around those questions.

---

# 2. The idea

AEGIS treats reconnaissance as a **stateful assessment process**, not a collection of disposable scan outputs.

```text
             AEGIS
               |
      +--------+--------+
      |                 |
   Scope              ARGUS
      |                 |
      |             Plugins
      |                 |
      +-------> Observations
                    |
             +------+------+
             |             |
           Assets       Relations
             |             |
             +------+------+
                    |
                Lifecycle
                    |
                  Changes
                    |
             Evidence / Integrity
```

The result is a historical model of the assessed attack surface.

---

# 3. AEGIS and ARGUS

## AEGIS

AEGIS is the assessment layer.

It manages concepts such as:

- Authorized scope
- Assets
- Relationships
- Provenance
- Lifecycle
- Change history
- Persisted results
- Integrity

## ARGUS

ARGUS is the reconnaissance and observation layer.

Its current built-in workflow includes:

```text
DNS
HTTP
SERVICE
TLS
```

ARGUS collects observations; AEGIS turns those observations into assessment intelligence.

---

# 4. Scope first

Reconnaissance begins from explicit campaign scope.

```bash
aegis init assessment
cd assessment

aegis scope add example.com
aegis scope list
```

Scope is not an afterthought in the architecture. It is part of the assessment model and processing flow.

The project is intended for explicitly authorized security testing.

---

# 5. Plugin-driven reconnaissance

Plugins provide focused observation capabilities.

```bash
aegis plugin list

aegis plugin run dns
aegis plugin run service
aegis plugin run tls
aegis plugin run http
```

A plugin execution is more than terminal output.

The execution is persisted and fed into the rest of the engine.

```text
Plugin
  |
  v
Raw Result
  |
  +--> Integrity baseline
  |
  +--> Coverage
  |
  +--> Observations
           |
           v
     Assessment state
```

---

# 6. Typed assets

Observations are promoted into typed assets.

The current assessment model includes infrastructure objects such as:

```text
DOMAIN
IP
SERVICE
CERTIFICATE
URL / supported scoped targets
```

Assets can carry:

- Metadata
- Discovery source
- First seen
- Last seen
- Last confirmed
- Seen count
- Active state
- Provenance

This makes the inventory historical rather than ephemeral.

---

# 7. The attack surface is a graph

Assets alone do not explain infrastructure.

AEGIS also stores relationships.

```text
        DOMAIN
      example.com
          |
          | resolves_to
          v
          IP

```

```text
        DOMAIN
      example.com
          |
          | exposes
          v
        SERVICE
   example.com:443
```

```text
        SERVICE
   example.com:443
          |
          | presents
          v
      CERTIFICATE
        <sha256>
```

This allows the operator to inspect not only discovered objects, but how they connect.

---

# 8. Graph exploration

The CLI exposes the relationship model directly.

```bash
aegis assets related domain example.com
```

```bash
aegis assets graph example.com --type domain
```

Lifecycle details can be included:

```bash
aegis assets graph example.com --type domain --details
```

Relations can also be queried by direction:

```bash
aegis relations from domain example.com
aegis relations to service example.com:443
```

---

# 9. Reconnaissance with memory

A single failed observation should not automatically mean:

> The asset is gone.

AEGIS uses lifecycle state to distinguish transient absence from repeated absence.

```text
ACTIVE
  |
  | first covered absence
  v
CANDIDATE_MISSING
  |
  | repeated covered absence
  v
INACTIVE
```

If the object later appears again:

```text
INACTIVE
   |
   | observed again
   v
REACTIVATED
   |
   v
ACTIVE
```

This applies to both assets and tracked relationships.

---

# 10. Why coverage matters

Absence is meaningful only when the execution actually covered the relevant object.

The current model contains explicit coverage types for reconnaissance areas such as:

```text
DNS
HTTP
SERVICE
TLS
```

This gives the lifecycle engine context for deciding whether a missing observation should be considered evidence of absence.

The principle is:

> No relevant coverage, no justified missing transition.

---

# 11. Change detection

Lifecycle transitions are persisted as change records.

Examples:

```text
CANDIDATE_MISSING
SERVICE example.com:443
```

```text
INACTIVE
DOMAIN example.com
  --resolves_to-->
IP 
```

```text
REACTIVATED
SERVICE example.com:443
```

The operator can query them:

```bash
aegis changes list
aegis changes list --type inactive
aegis changes list --type reactivated
aegis changes list --plugin dns
aegis changes list --relation-type resolves_to
```

---

# 12. Change engine ordering

The execution pipeline deliberately evaluates missing state before current observations are promoted.

```text
1. Execute plugin
2. Save current result
3. Find previous comparable result
4. Process missing objects
5. Apply lifecycle transitions
6. Hash and baseline the result
7. Process observations
8. Update assets and relations
9. Detect reactivations
10. Render execution output
```

Why?

Because missing detection must compare the current execution against the state that existed **before** the current observations modify the inventory.

---

# 13. Provenance

An assessment conclusion should be traceable back to evidence.

AEGIS stores provenance information associated with discovered state.

Depending on the object, provenance can identify:

```text
Plugin
Plugin version
Observation type
Target
Observed timestamp
Observation ID
Result ID
Result file
Result SHA-256
```

The objective is traceability:

```text
Finding
   |
   v
Asset / Relation
   |
   v
Observation
   |
   v
Stored Result
```

---

# 14. Result integrity

Persisting evidence is more useful when its integrity can later be checked.

New plugin results receive an SHA-256 integrity baseline.

```text
Plugin execution
      |
      v
 Persisted result
      |
      v
    SHA-256
      |
      v
ORIGINAL baseline
```

Verification is exposed through the CLI:

```bash
aegis results verify <filename>
aegis results verify-all
```

Integrity states include:

```text
OK
BASELINED
FAILED
UNKNOWN
CONFLICT
```

---

# 15. Legacy evidence

Older results may predate the integrity manifest.

AEGIS therefore supports retrospective baselining:

```bash
aegis results baseline-legacy
```

These records are explicitly distinguished from original baselines:

```text
ORIGINAL
RETROSPECTIVE
```

This avoids pretending that a later baseline was captured at the original collection time.

---

# 16. Human and machine interfaces

The current CLI uses a Rich-based terminal interface for human operators.

```bash
aegis
```

The interface exposes:

```text
version
info
commands
init
scope
plugin
assets
relations
changes
results
```

For automation, lifecycle changes can also be emitted as JSON:

```bash
aegis changes list --json
```

---

# 17. Example assessment flow

```text
Create campaign
      |
      v
Define authorized scope
      |
      v
Run DNS
      |
      v
Run service discovery
      |
      v
Run TLS / HTTP
      |
      v
Build assets + relations
      |
      v
Repeat executions
      |
      v
Detect lifecycle changes
      |
      v
Investigate history
      |
      v
Verify evidence integrity
```

CLI example:

```bash
aegis init assessment
cd assessment

aegis scope add example.com

aegis plugin run dns
aegis plugin run service
aegis plugin run tls
aegis plugin run http

aegis assets list
aegis relations list
aegis changes list
aegis results verify-all
```

---

# 18. Current engineering state

The current implementation includes:

- Campaign initialization
- Scope management
- Plugin registry and execution
- DNS reconnaissance
- HTTP reconnaissance
- Service discovery and fingerprinting
- TLS inspection
- Observation processing
- Asset extraction and persistence
- Relation extraction and persistence
- Provenance
- Asset lifecycle management
- Relation lifecycle management
- Coverage-aware missing detection
- Candidate-missing transitions
- Inactivation
- Reactivation
- Change persistence and querying
- Asset history
- Relation history
- Graph traversal
- Result integrity
- Legacy result baselining
- Rich CLI output
- JSON change output

The current validated development suite contains:

```text
283 passing tests
```

---

# 19. What differentiates AEGIS?

AEGIS is not trying to be only another scanner.

Its central abstraction is:

```text
RECONNAISSANCE + STATE + TIME + EVIDENCE
```

A conventional scan might say:

```text
Port 443 is open.
```

AEGIS is being designed to express something richer:

```text
SERVICE example.com:443

First seen:       T1
Last confirmed:   T5
Seen count:       N
State:            ACTIVE

Exposed by:
DOMAIN example.com

Presents:
CERTIFICATE <sha256>

Supported by:
result <file>
SHA-256 <hash>
```

And later:

```text
T6 -> CANDIDATE_MISSING
T7 -> INACTIVE
T9 -> REACTIVATED
```

That historical context is the core of the project.

---

# 20. Project direction

The architectural direction is to evolve AEGIS from a reconnaissance CLI into an **assessment intelligence engine**.

The long-term value comes from maintaining a trustworthy temporal model:

```text
What exists?
      +
How is it connected?
      +
Where did we learn it?
      +
Is the evidence intact?
      +
What changed over time?
```

The goal is not simply to scan infrastructure.

**The goal is to understand how an authorized attack surface evolves.**

---

# AEGIS / ARGUS

**Authorized Reconnaissance.  
Evidence-backed state.  
Temporal attack-surface intelligence.**
