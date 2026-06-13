---
name: mcp-context-optimization
description: Use when implementing MCP tools or endpoints for WinDbg extension to minimize LLM token consumption, lazy loading, progressive disclosure, field selection, and context optimization. Trigger on keywords like "context optimization", "lazy loading", "token usage", "MCP response size", "field selection", "progressive disclosure", "context growth".
---

# MCP Context Optimization & Lazy Loading

## Objective

Minimize LLM token consumption and MCP response size.

The goal is NOT to convert text into JSON.

The goal is to reduce the amount of information transferred to the LLM.

Always optimize for:

* Smaller context
* Lower token usage
* Structured responses
* Progressive data retrieval
* Lazy loading

---

## Core Principles

### 1. Never Return Everything

Avoid returning all available fields by default.

Bad:

```json
{
  "pid": 1234,
  "image": "explorer.exe",
  "parent_pid": 1000,
  "session_id": 1,
  "peb": "...",
  "dirbase": "...",
  "object_table": "...",
  "handle_count": 543,
  "vad_root": "...",
  "priority": 8,
  "flags": [...]
}
```

Good:

```json
{
  "pid": 1234,
  "image": "explorer.exe",
  "eprocess": "ffff..."
}
```

---

### 2. Use Progressive Disclosure

Always provide a lightweight summary first.

Additional information should be retrieved through dedicated follow-up calls.

Example:

```text
enumerate_processes()
```

returns:

```json
[
  {
    "pid": 1234,
    "image": "explorer.exe"
  }
]
```

Later:

```text
get_process_details(pid=1234)
```

returns:

```json
{
  "handle_count": 543,
  "vad_root": "...",
  "object_table": "..."
}
```

---

### 3. Implement Field Selection

Support explicit field requests.

Example:

```text
get_process(
    pid=1234,
    fields=["handle_count","vad_root"]
)
```

Only requested fields should be collected and returned.

Never gather data merely to discard it later.

---

### 4. Implement True Lazy Loading

Expensive fields must not be calculated unless requested.

Examples:

* handle_count
* vad_root
* object_table
* memory maps
* handle tables
* stack traces
* thread lists

Do not collect them during summary generation.

---

### 5. Separate Core and Extended Fields

Core fields:

* pid
* image
* eprocess
* parent_pid
* session_id

Extended fields:

* handle_count
* object_table
* vad_root
* priority
* flags
* peb
* thread details

Core fields should be returned by default.

Extended fields should be opt-in.

---

### 6. Avoid Raw Debugger Output

Do not return large WinDbg output by default.

Bad:

```text
!process 0 0
```

Good:

```json
{
  "pid": 1234,
  "image": "explorer.exe",
  "thread_count": 12
}
```

Raw debugger output should only be returned when:

```text
include_raw=true
```

or

```text
show_raw_output()
```

is explicitly requested.

---

### 7. Prefer Structured APIs

Prefer:

```text
get_process()
get_thread()
get_handle_summary()
get_module()
```

Instead of:

```text
run_command("!process")
run_command("!thread")
run_command("!handle")
```

---

### 8. Minimize Context Growth

Never send large collections if summaries are sufficient.

Prefer:

```json
{
  "process_count": 187
}
```

Instead of:

```json
{
  "processes": [...]
}
```

when detailed information is not required.

---

### 9. Backward Compatibility

When refactoring existing tools:

* Preserve old behavior when possible.
* Add new structured endpoints.
* Keep legacy mode available.
* Use feature flags such as:

```text
include_raw
include_all_fields
legacy_mode
```

---

### 10. Design For Agents

Assume an autonomous agent may call the tool hundreds of times.

Every unnecessary field increases:

* token usage
* context size
* latency
* cost

Always ask:

"Does the model actually need this field right now?"

If the answer is no, do not collect it and do not return it.
