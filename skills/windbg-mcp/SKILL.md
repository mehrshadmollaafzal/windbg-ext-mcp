# Skill: windbg-mcp

## Overview

The WinDbg MCP Server exposes 16 tools across 5 categories that broker between LLM clients and a WinDbg extension over a named pipe. All tools return structured JSON dictionaries.

## Communication Architecture

- **Named pipe**: `\\.\pipe\windbgmcp`
- **Buffer size**: 8192 bytes
- **Timeout categories**: quick (10s), normal (30s), analysis (120s), memory (90s), execution (60s), bulk (180s), large_analysis (300s), process_list (480s), streaming (900s), symbols (300s), extended (1200s)
- **Retry**: 3 attempts, 1s base delay, exponential backoff
- **Modes**: LOCAL, VM_NETWORK, VM_SERIAL, REMOTE (each with a timeout multiplier)

---

## Category 1: Session Management (3 tools)

### 1.1 `debug_session`

Check extension connection, test the pipe, or retrieve WinDbg version.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | `"status"` | One of `"status"`, `"connection"`, `"version"` |

**Actions:**

- **`"status"`** — Tests the named-pipe connection and runs `version`. Returns first 200 characters of version output.
- **`"connection"`** — Quick boolean connectivity test via `test_connection()`.
- **`"version"`** — Sends a direct handler command to retrieve the WinDbg extension version, with ISO timestamp.

**Output format (`action="status"`):**

```json
{
  "connected": true,
  "status": "Active debugging session",
  "version_info": "Windows 10 Kernel Version 19041 MP (8 procs) Free x64..."
}
```

**Output format (`action="connection"`):**

```json
{
  "connected": true,
  "status": "Extension connection OK"
}
```

**Output format (`action="version"`):**

```json
{
  "success": true,
  "version": "WinDbg 10.0.19041.1",
  "timestamp": "2026-06-13T10:30:00.000000"
}
```

---

### 1.2 `connection_manager`

Query internal health metrics or run a test command against the extension.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | `"status"` | One of `"status"`, `"test"` |

**Actions:**

- **`"status"`** — Returns connection health from `CommunicationManager.get_connection_health()`.
- **`"test"`** — Executes `version` and reports success/failure with response length.

**Output format (`action="status"`):**

```json
{
  "connection_status": "connected",
  "extension_available": true,
  "target_responsive": true,
  "consecutive_failures": 0,
  "last_error": null,
  "status": "WinDbg extension is responding"
}
```

---

### 1.3 `session_manager`

Get extension/target connectivity or detailed session metadata.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | `"status"` | One of `"status"`, `"info"` |

**Actions:**

- **`"status"`** — Returns two boolean flags (`extension_connected`, `target_connected`) and an `overall_status` ("ready" / "not_ready").
- **`"info"`** — Detects kernel vs user mode via `version` output heuristics, counts loaded modules from `lm`, reports capabilities.

**Output format (`action="status"`):**

```json
{
  "extension_connected": true,
  "target_connected": true,
  "target_status": "Kernel debugging target connected",
  "overall_status": "ready"
}
```

**Output format (`action="info"`):**

```json
{
  "debugging_mode": "kernel",
  "basic_info": "Windows 10 Kernel Version 19041 MP (8 procs)...",
  "module_count": 142,
  "capabilities": {
    "can_break": true,
    "can_analyze": true,
    "can_modify": true
  }
}
```

---

## Category 2: Command Execution (3 tools)

### 2.1 `run_command`

Execute an arbitrary WinDbg command string. This is the escape hatch for commands not covered by structured tools. Supports validation, resilient retries, and caching.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `command` | string | `""` | The WinDbg command to execute |
| `validate` | bool | `true` | Validate command safety before execution |
| `resilient` | bool | `true` | Enable retry on transient failures |
| `optimize` | bool | `true` | Enable caching and timeout optimization |

**Validation:**
- Blocked commands: `q`, `qq`, `qd`, `.kill`, `.detach`, `.restart`, `.dump`, `.dumpcab`, `.load`, `.unload`, `.connect`, `.server`, `.logopen`, `.logappend`
- Safe prefixes always allowed: `lm`, `x`, `dt`, `dd`, `!process`, `!thread`, `!object`, `k`, `r`, `u`, `bp`, `g`, `p`, `t`, etc.
- Execution control (`g`, `p`, `t`, `gu`, `wt`) and breakpoints (`bp`, `bc`, `bd`, `be`) are explicitly allowed for LLM automation.

**Output format (success):**

```json
{
  "output": "Command output text...",
  "success": true,
  "execution_time": 0.345,
  "cached": false,
  "retries_attempted": 0,
  "timeout_category": "normal",
  "execution_mode": "direct"
}
```

**Output format (error):**

```json
{
  "error": "Command 'foo' failed: explanation",
  "error_code": "execution_error",
  "category": "timeout",
  "suggestions": ["Try breaking into the debugger first"],
  "help": {}
}
```

---

### 2.2 `run_sequence`

Execute a list of WinDbg commands sequentially with per-command results, summary, and recommendations.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `commands` | list[string] | required | List of WinDbg commands to run in order |
| `stop_on_error` | bool | `false` | Stop execution if any command fails |

**Output format:**

```json
{
  "sequence_results": [
    {
      "command": "version",
      "index": 0,
      "success": true,
      "result": "Windows 10...",
      "execution_time": 0.123,
      "cached": false,
      "execution_mode": "direct"
    }
  ],
  "summary": {
    "total_commands": 2,
    "successful_commands": 2,
    "failed_commands": 0,
    "execution_stopped": false,
    "total_execution_time": 0.456,
    "average_execution_time": 0.228,
    "context_saved": true,
    "sequence_performance": "excellent"
  },
  "recommendations": ["✅ All commands executed successfully"],
  "context_recovery": {
    "context_saved": true,
    "recovery_hint": "Use restore_context if sequence caused issues"
  }
}
```

---

### 2.3 `breakpoint_and_continue`

Set a breakpoint and optionally continue execution in one operation. Saves context before modifying state.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `breakpoint` | string | required | Breakpoint spec (e.g., `"nt!NtCreateFile"`, `"0x12345678"`, `"kernel32!CreateFileW"`) |
| `continue_execution` | bool | `true` | Run `g` after setting the breakpoint |
| `clear_existing` | bool | `false` | Run `bc *` first to clear all existing breakpoints |

**Output format:**

```json
{
  "success": true,
  "breakpoint": "nt!NtCreateFile",
  "breakpoint_set": true,
  "execution_continued": true,
  "steps_completed": [
    {"step": "clear_existing_breakpoints", "command": "bc *", "success": true},
    {"step": "set_breakpoint", "command": "bp nt!NtCreateFile", "success": true},
    {"step": "list_breakpoints", "command": "bl", "success": true},
    {"step": "continue_execution", "command": "g", "success": true}
  ],
  "summary": {
    "total_steps": 4,
    "successful_steps": 4,
    "total_execution_time": 1.234,
    "context_saved": true
  },
  "guidance": [
    "✅ Breakpoint set and execution continued",
    "🎯 Target will break when the specified location is hit",
    "📊 Use 'k' to examine call stack when breakpoint hits"
  ]
}
```

---

## Category 3: Analysis (4 tools)

### 3.1 `analyze_process`

Analyze processes in the debugging session. Parses `!process 0 0` output into structured JSON with configurable verbosity.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | required | One of `"list"`, `"switch"`, `"info"`, `"peb"`, `"restore"` |
| `address` | string | `""` | EPROCESS address (required for switch/info/peb) |
| `save_context` | bool | `true` | Save current process context before switching |
| `verbosity` | string | `"summary"` | Output detail for `"list"`: `"summary"` or `"full"` |

**Actions:**

- **`"list"`** — Runs `!process 0 0`, parses into JSON.
  - `verbosity="summary"`: returns `{eprocess, pid, image}` per process.
  - `verbosity="full"`: returns `{EProcess, SessionId, pid, peb, parent_pid, DirBase, ObjectTable, HandleCount, Image}` per process.

- **`"switch"`** — Runs `.process /i <address>` to context-switch to a target process. Requires `address`.

- **`"info"`** — Runs `!process <address> 7` to get detailed process info including threads and handles. Requires `address`.

- **`"peb"`** — Switches to process and reads `!peb`. Not available in kernel mode.

- **`"restore"`** — Pops saved context back.

**Output format (`action="list", verbosity="summary"`):**

```json
{
  "processes": [
    {
      "eprocess": "ffffe08a1b62f080",
      "pid": 4,
      "image": "System"
    },
    {
      "eprocess": "ffffe08a1b634080",
      "pid": 400,
      "image": "smss.exe"
    }
  ],
  "count": 2,
  "verbosity": "summary"
}
```

**Output format (`action="list", verbosity="full"`):**

```json
{
  "processes": [
    {
      "EProcess": "ffffe08a1b62f080",
      "SessionId": 0,
      "pid": 4,
      "peb": "0000000000000000",
      "parent_pid": 0,
      "DirBase": "001aa000",
      "ObjectTable": "ffffe08a1b62f1c0",
      "HandleCount": 1234,
      "Image": "System"
    }
  ],
  "count": 1,
  "verbosity": "full"
}
```

**Output format (`action="switch"`):**

```json
{
  "success": true,
  "output": "Implicit process is now ffffe08a1b62f080",
  "switched_to": "ffffe08a1b62f080",
  "next_steps": [
    "Context switch initiated",
    "Use 'g' command to let target execute",
    "After break, context will be in the target process"
  ]
}
```

---

### 3.2 `analyze_thread`

Analyze threads. Supports two output modes for `"list"`: raw debugger text or summarized JSON.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | required | One of `"list"`, `"switch"`, `"info"`, `"stack"`, `"all_stacks"`, `"teb"` |
| `address` | string | `""` | Thread ID or address (required for switch/info/stack/teb) |
| `count` | int | `20` | Number of stack frames |
| `verbosity` | string | `"raw"` | Only for `"list"`: `"raw"` or `"summary"` |

**Actions:**

- **`"list"`** — Runs `!thread`.
  - `verbosity="raw"`: Returns the raw text output as-is.
  - `verbosity="summary"`: Parses into structured JSON with core fields.

- **`"switch"`** — Runs `~<address>s` to switch to a given thread.

- **`"info"`** — Runs `!thread <address>` for detailed thread info.

- **`"stack"`** — Switches to thread if address given, then runs `k <count>`.

- **`"all_stacks"`** — Runs `k <count>` for current thread with sample stacks from other threads.

- **`"teb"`** — Reads `!teb`. Not available in kernel mode.

**Output format (`action="list", verbosity="summary"`):**

```json
{
  "thread": {
    "address": "ffff87878ae63080",
    "cid": "046c.0b18",
    "state": "RUNNING",
    "process": {
      "address": "ffff878788b3b080",
      "image": "LogonUI.exe"
    },
    "cpu": {
      "processor": 0,
      "ideal_processor": 1
    },
    "timing": {
      "wait_ticks": 871,
      "user_time_ms": 15,
      "kernel_time_ms": 0
    },
    "priority": {
      "base": 13,
      "current": 15,
      "foreground_boost": 1
    },
    "io": {
      "has_irp": true,
      "irp_count": 1
    },
    "stack_top": [
      "nt!DbgBreakPointWithStatus",
      "nt!KiBugCheckDebugBreak",
      "nt!KeBugCheck2",
      "nt!KeBugCheckEx",
      "nt!HalBugCheckSystem"
    ]
  },
  "format": "summary"
}
```

**Output format (`action="list", verbosity="raw"`):**

```json
{
  "output": "THREAD ffff87878ae63080  Cid 046c.0b18  Teb: 000000a465d0e000 Win32Thread: ffff87878ae6d560 RUNNING on processor 0\nIRP List:\n    ffff87878693a9b0: (0006,0478)...",
  "note": "Copy thread address for detailed analysis"
}
```

---

### 3.3 `analyze_memory`

Analyze memory and data structures.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | required | One of `"display"`, `"type"`, `"search"`, `"pte"`, `"regions"` |
| `address` | string | `""` | Memory address (required for display/type/search/pte) |
| `type_name` | string | `""` | Type name for `dt` display (e.g., `"_EPROCESS"`) |
| `length` | int | `32` | Number of bytes/elements |

**Actions:**

- **`"display"`** — Runs `dd <address> l<length>`.
- **`"type"`** — Runs `dt <type_name> <address>` (e.g., `dt _EPROCESS ffff...`).
- **`"search"`** — Runs `s <address> L<length> <pattern>`.
- **`"pte"`** — Runs `!pte <address>` for Page Table Entry analysis.
- **`"regions"`** — Runs `!vm` for virtual memory regions.

---

### 3.4 `analyze_kernel`

Analyze kernel objects and structures.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | required | One of `"object"`, `"idt"`, `"interrupts"`, `"modules"` |
| `address` | string | `""` | Object address (required for `"object"`) |

**Actions:**

- **`"object"`** — Runs `!object <address>` to inspect a kernel object.
- **`"idt"`** — Runs `!idt` to dump the Interrupt Descriptor Table.
- **`"interrupts"`** — Runs `!pic <address>` if address given, otherwise `!irql`.
- **`"modules"`** — Runs `lm` to list loaded kernel modules.

---

## Category 4: Performance (2 tools)

### 4.1 `performance_manager`

Manage optimization settings, monitor performance, stream large command output, and benchmark commands.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | required | One of `"report"`, `"set_level"`, `"clear_cache"`, `"stream"`, `"benchmark"` |
| `level` | string | `""` | Optimization level: `"none"`, `"basic"`, `"aggressive"`, `"maximum"` |
| `command` | string | `""` | Command for streaming or benchmarking |

**Actions:**

- **`"report"`** — Returns performance report + async statistics.
- **`"set_level"`** — Sets optimization level (caching, compression, parallel execution).
- **`"clear_cache"`** — Clears all performance caches.
- **`"stream"`** — Executes a command and streams output in chunks via `StreamingHandler`.
- **`"benchmark"`** — Runs a command 5 times and reports avg/min/max timing.

**Output format (`action="report"`):**

```json
{
  "performance_report": {
    "optimization_level": "aggressive",
    "cache_hit_rate": 0.72,
    "avg_execution_time": 0.45
  },
  "async_statistics": {
    "total_tasks": 12,
    "success_rate": 1.0,
    "concurrent_peak": 3
  },
  "recommendations": "Current optimization level: aggressive",
  "status": "Performance report generated"
}
```

**Output format (`action="benchmark"`):**

```json
{
  "benchmark_results": {
    "command": "version",
    "iterations": 5,
    "average_time_ms": "123.45",
    "min_time_ms": "98.10",
    "max_time_ms": "145.67",
    "success_rate": "100.0%"
  },
  "status": "Benchmark completed"
}
```

---

### 4.2 `async_manager`

Manage asynchronous command execution for non-blocking workflows and parallel execution.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | required | One of `"submit"`, `"status"`, `"result"`, `"parallel"`, `"stats"`, `"cancel"`, `"diagnostic"` |
| `commands` | list[string] | None | Commands for submit/parallel |
| `task_id` | string | `""` | Task ID for status/result/cancel |
| `priority` | string | `"normal"` | One of `"low"`, `"normal"`, `"high"`, `"critical"` |

**Actions:**

- **`"submit"`** — Submits commands for background execution. Returns task IDs immediately.
- **`"status"`** — Polls task status by ID, or returns system-wide async stats if no ID given.
- **`"result"`** — Retrieves completed task result.
- **`"parallel"`** — Executes multiple commands concurrently via `execute_parallel_commands()`.
- **`"stats"`** — Returns detailed async statistics with insights.
- **`"cancel"`** — Cancels a pending or running task.
- **`"diagnostic"`** — Runs a diagnostic sequence (`version`, `.effmach`, `!pcr`, `lm`, `!process -1 0`, `k`, `r`) in parallel.

**Output format (`action="submit"`):**

```json
{
  "tasks_submitted": 2,
  "task_ids": ["abc-123", "def-456"],
  "priority": "normal",
  "tip": "Use async_manager(action='status', task_id='<id>') to check progress"
}
```

**Output format (`action="parallel"`):**

```json
{
  "parallel_execution_completed": true,
  "commands_executed": 2,
  "successful_commands": 2,
  "results": {
    "version": {
      "status": "completed",
      "success": true,
      "result": "Windows 10...",
      "execution_time": 0.123
    }
  },
  "performance_summary": "2/2 commands completed successfully"
}
```

**Output format (`action="diagnostic"`):**

```json
{
  "diagnostic_report": {
    "diagnostic_time": "2026-06-13T10:30:00",
    "commands_executed": 7,
    "successful_commands": 7,
    "results": {
      "version": { "status": "completed", "execution_time": 0.1, "result_preview": "Windows..." },
      "!pcr": { "status": "completed", "execution_time": 0.2, "result_preview": "PCR..." }
    }
  },
  "execution_method": "async_parallel",
  "tip": "Diagnostic commands were executed in parallel for better performance"
}
```

---

## Category 5: Support (4 tools)

### 5.1 `troubleshoot`

Run automated troubleshooting workflows.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `action` | string | required | One of `"symbols"`, `"exception"`, `"analyze"`, `"connection"` |

**Actions:**

- **`"symbols"`** — Checks `.sympath`, verifies `nt`, `ntdll`, `kernel32` module symbols, attempts `.reload`.
- **`"exception"`** — Runs `!analyze -v` for current exception analysis.
- **`"analyze"`** — Runs `!analyze -v` for general system analysis.
- **`"connection"`** — Tests connection and returns WinDbg version.

---

### 5.2 `get_help`

Get help, parameter information, and usage examples for any tool.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tool_name` | string | `""` | Name of the tool (empty lists all tools) |
| `action` | string | `""` | Specific action to get help for |

**Output format (all tools):**

```json
{
  "available_tools": ["debug_session", "run_command", "run_sequence", "breakpoint_and_continue", "analyze_process", "analyze_thread", "analyze_memory", "analyze_kernel", "connection_manager", "session_manager", "performance_manager", "async_manager", "troubleshoot", "get_help"],
  "description": "WinDbg MCP Server - Debugging with LLM Automation",
  "tool_categories": {
    "session_management": ["debug_session", "connection_manager", "session_manager"],
    "command_execution": ["run_command", "run_sequence", "breakpoint_and_continue"],
    "analysis": ["analyze_process", "analyze_thread", "analyze_memory", "analyze_kernel"],
    "performance": ["performance_manager", "async_manager"],
    "support": ["troubleshoot", "get_help"]
  }
}
```

---

### 5.3 `test_windbg_communication`

Run a 3-step communication test: extension connection, target connection, and command execution.

**Output format (string):**

```
🧪 WINDBG COMMUNICATION TEST
========================================

✅ Test 1: Extension connection - PASSED

✅ Test 2: Target connection - PASSED (Kernel debugging target connected)

✅ Test 3: Command execution - PASSED
    Response: Windows 10 Kernel Version 19041 MP (8 procs) Free x64...

📊 Summary:
  • Communication tests completed
  • Check individual test results above for details
```

---

### 5.4 `network_debugging_troubleshoot`

Specialized troubleshooting for VM/kernel network debugging scenarios. Tests connection, detects Remote KD / network transport, and provides configuration tips.

---

## Configuration Reference

### Command Timeout Categories

| Category | Commands | Default Timeout |
|----------|----------|-----------------|
| Quick | `version`, `help`, `?`, `r` | 10s |
| Normal | `lm`, `k`, `dv`, `dt` | 30s |
| Analysis | `!analyze`, `!thread`, `!process` | 120s |
| Memory | `dd`, `dq`, `dp`, `da`, `du` | 90s |
| Execution | `g`, `p`, `t`, `bp`, `bc` | 60s |
| Bulk | `lm`, `!dlls`, `!handle`, `!vm`, `!address` | 180s |
| Large Analysis | `!analyze -v`, `!thread -1`, `!process -1` | 300s |
| Process List | `!process 0 0`, `!process 0 7`, `!process 0 1f` | 480s |
| Streaming | `!for_each_process`, `!for_each_thread`, `!for_each_module` | 900s |
| Symbols | `.reload`, `.sympath`, `.symfix` | 300s |
| Extended | `.reload /f` | 1200s |

### Mode-Specific Timeout Multipliers

| Mode | Multiplier |
|------|------------|
| LOCAL | 1.0x |
| VM_NETWORK | 2.0x |
| VM_SERIAL | 1.5x |
| REMOTE | 2.5x |

### Optimization Levels

| Level | Features |
|-------|----------|
| `none` | No optimization, direct execution |
| `basic` | Basic result caching, simple timeout optimization |
| `aggressive` | Intelligent caching with TTL, data compression, adaptive timeouts, background monitoring, network debugging optimization |
| `maximum` | Maximum caching with extended TTL, aggressive compression, concurrent execution, full analytics |

---

## Error Handling Pattern

All tools return structured error dictionaries with the following fields:

```json
{
  "error": "Human-readable error message",
  "error_code": "parameter_error | validation_error | execution_error | timeout_error | safety_error | unexpected_error",
  "category": "timeout | validation | execution | parameter | mode_mismatch",
  "suggestions": ["Suggestion 1", "Suggestion 2"],
  "help": {}
}
```

## Context Saving

`analyze_process(action='switch')`, `run_sequence`, and `breakpoint_and_continue` automatically save context before making state changes. Use `analyze_process(action='restore')` to revert.
