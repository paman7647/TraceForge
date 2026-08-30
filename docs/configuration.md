# Configuration & Runtime Profiles

TraceForge provides an adaptive runtime architecture allowing operators to tailor execution between pure Python reference implementations and compiled native Go helpers.

---

## 1. Runtime Profiles

The active profile determines which language engine handles analytical operations:

| Profile | Application Logic | Fast-Path Tasks (Hash/IOC/Triage) | External Toolchain |
|---|---|---|---|
| **`python-go`** *(Default)* | Python 3 | Compiled Go Helpers (`traceforge-native`) | Standard recommended (~50 tools) |
| **`python`** | Python 3 | Pure Python | Standard recommended (~50 tools) |
| **`go`** | Python 3 (Minimal) | Compiled Go Helpers | Go utilities only |
| **`minimal`** | Python 3 | Pure Python | Core built-in utilities only (~15 tools) |
| **`full`** | Python 3 | Compiled Go Helpers | All 175 catalog tools |

| **`custom`** | Operator-defined | Operator-defined | Fine-tuned per component |

---

## 2. Managing Profiles

### View Active Profile
```bash
traceforge profile
```

### Switch Active Profile
```bash
traceforge profile python-go
# or
traceforge profile minimal
```

---

## 3. Feature Fast-Path Overrides

You can override the engine used for specific analytical tasks:

```bash
# Force compiled Go fast-path for IOC extraction
traceforge config set ioc.runtime go

# Force pure Python engine for file hashing
traceforge config set hash.runtime python

# Reset to automatic profile recommendation
traceforge config set hash.runtime auto
```

Available configurable features:
- `hash.runtime`: Cryptographic hashing and evidence directory indexing.
- `ioc.runtime`: Streaming indicator of compromise extraction and defanging.
- `diff.runtime`: Universal snapshot differing for DNS and web responses.
- `triage.runtime`: Web access log and syslog triage engine.
- `graph.runtime`: Node and edge relationship graph generation.
- `pcap.runtime`: Offline packet capture summary and protocol dissection.

---

## 4. Configuration Storage & CLI Settings

TraceForge persists configuration settings in `config.json`:

```bash
# View entire active configuration
traceforge config list

# Get a specific setting
traceforge config get profile
```

---

## 5. Environment Variables

| Variable | Description | Default |
|---|---|---|
| `TRACEFORGE_PROFILE` | Override active runtime profile for the session | `python-go` |
| `TRACEFORGE_WORKSPACE`| Custom directory path for case workspaces | `./workspace` |
| `TRACEFORGE_NATIVE_BIN`| Path to compiled `traceforge-native` binary | `./bin/traceforge-native` |
| `TRACEFORGE_VERBOSE` | Enable verbose runtime execution tracing | `0` |
