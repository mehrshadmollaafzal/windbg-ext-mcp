"""
Analysis tools for WinDbg MCP server.

This module contains tools for analyzing processes, threads, memory, and kernel objects.
"""
import logging
import re
from typing import Dict, Any, Union
from fastmcp import FastMCP, Context

from core.communication import send_command, TimeoutError, CommunicationError
from core.context import get_context_manager
from core.error_handler import enhance_error, error_enhancer, DebugContext
from core.hints import get_parameter_help, validate_tool_parameters
from .tool_utilities import detect_kernel_mode

logger = logging.getLogger(__name__)


def _parse_process_list(raw_output: str) -> list[dict[str, object]]:
    processes: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in raw_output.splitlines():
        stripped = line.strip()
        m = re.match(r'^PROCESS\s+([0-9a-fA-F`]+)', line)
        if m:
            if current:
                processes.append(current)
            current = {"eprocess": m.group(1).replace("`", "")}
            continue
        if current is None:
            continue
        m = re.search(r'SessionId:\s*(\d+)', stripped)
        if m:
            current["session_id"] = int(m.group(1))
        m = re.search(r'Cid:\s*([0-9a-fA-F`]+)', stripped)
        if m:
            current["pid"] = int(m.group(1).replace("`", ""), 16)
        m = re.search(r'Peb:\s*([0-9a-fA-F`]+)', stripped)
        if m:
            current["peb"] = m.group(1).replace("`", "")
        m = re.search(r'ParentCid:\s*([0-9a-fA-F`]+)', stripped)
        if m:
            current["parent_pid"] = int(m.group(1).replace("`", ""), 16)
        m = re.search(r'DirBase:\s*([0-9a-fA-F`]+)', stripped)
        if m:
            current["dirbase"] = m.group(1).replace("`", "")
        m = re.search(r'ObjectTable:\s*([0-9a-fA-F`]+)', stripped)
        if m:
            current["object_table"] = m.group(1).replace("`", "")
        m = re.search(r'HandleCount:\s*(\d+)', stripped)
        if m:
            current["handle_count"] = int(m.group(1))
        m = re.search(r'Image:\s*(.+)', stripped)
        if m:
            current["image"] = m.group(1).strip()
    if current:
        processes.append(current)
    return processes


def _summarize_process(p: dict[str, object]) -> dict[str, object]:
    return {
        "eprocess": p.get("eprocess", ""),
        "pid": p.get("pid", 0),
        "image": p.get("image", ""),
    }


def _full_process(p: dict[str, object]) -> dict[str, object]:
    return {
        "EProcess": p.get("eprocess", ""),
        "SessionId": p.get("session_id", 0),
        "pid": p.get("pid", 0),
        "peb": p.get("peb", ""),
        "parent_pid": p.get("parent_pid", 0),
        "DirBase": p.get("dirbase", ""),
        "ObjectTable": p.get("object_table", ""),
        "HandleCount": p.get("handle_count", 0),
        "Image": p.get("image", ""),
    }


def _parse_thread_output(raw_output: str) -> dict[str, object] | None:
    lines = raw_output.splitlines()
    if not lines:
        return None
    thread_line = ""
    for line in lines:
        if line.strip().startswith("THREAD"):
            thread_line = line
            break
    if not thread_line:
        return None
    thread: dict[str, object] = {}
    header = re.match(
        r'^THREAD\s+([0-9a-fA-F`]+)\s+Cid\s+([0-9a-fA-F`.]+)'
        r'(?:\s+Teb:\s+([0-9a-fA-F`]+))?'
        r'(?:\s+Win32Thread:\s+([0-9a-fA-F`]+))?'
        r'(?:\s+(RUNNING|READY|WAITING|BLOCKED|TERMINATED|SUSPENDED|TRANSITION|DEFERRED)'
        r'\s+on\s+processor\s+(\d+))?',
        thread_line
    )
    if not header:
        return None
    thread["address"] = header.group(1).replace("`", "")
    thread["cid"] = header.group(2)
    if header.group(3):
        thread["teb"] = header.group(3).replace("`", "")
    if header.group(4):
        thread["win32_thread"] = header.group(4).replace("`", "")
    if header.group(5):
        thread["state"] = header.group(5)
    if header.group(6):
        thread["processor"] = int(header.group(6))

    irp_count = 0
    for line in lines:
        stripped = line.strip()
        if re.match(r'^\s+ffff', line) and 'Flags:' in line and 'Mdl:' in line:
            irp_count += 1
        m = re.search(r'Owning Process\s+([0-9a-fA-F`]+)\s+Image:\s+(.+)', stripped)
        if m:
            thread["process_address"] = m.group(1).replace("`", "")
            thread["process_image"] = m.group(2).strip()
        m = re.search(r'Attached Process\s+([0-9a-fA-F`]+)\s+Image:\s+(.+)', stripped)
        if m:
            attached_addr = m.group(1).strip()
            thread["attached_process"] = attached_addr if attached_addr != "N/A" else None
            attached_img = m.group(2).strip()
            thread["attached_image"] = attached_img if attached_img != "N/A" else None
        m = re.search(r'Wait Start TickCount\s+(\d+)\s+Ticks:\s+(\d+)', stripped)
        if m:
            thread["wait_start_tick"] = int(m.group(1))
            thread["ticks"] = int(m.group(2))
        m = re.search(r'Context Switch Count\s+(\d+)\s+IdealProcessor:\s+(\d+)', stripped)
        if m:
            thread["context_switches"] = int(m.group(1))
            thread["ideal_processor"] = int(m.group(2))
        m = re.search(r'UserTime\s+(\d+:\d+:\d+\.\d+)', stripped)
        if m:
            parts = m.group(1).split(":")
            h, mi, s = int(parts[0]), int(parts[1]), float(parts[2])
            thread["user_time_ms"] = int(h * 3600000 + mi * 60000 + s * 1000)
        m = re.search(r'KernelTime\s+(\d+:\d+:\d+\.\d+)', stripped)
        if m:
            parts = m.group(1).split(":")
            h, mi, s = int(parts[0]), int(parts[1]), float(parts[2])
            thread["kernel_time_ms"] = int(h * 3600000 + mi * 60000 + s * 1000)
        m = re.search(r'Priority\s+(\d+)\s+BasePriority\s+(\d+)'
                      r'\s+Foreground Boost\s+(\d+)'
                      r'\s+IoPriority\s+(\d+)'
                      r'\s+PagePriority\s+(\d+)', stripped)
        if m:
            thread["priority"] = int(m.group(1))
            thread["base_priority"] = int(m.group(2))
            thread["foreground_boost"] = int(m.group(3))
            thread["io_priority"] = int(m.group(4))
            thread["page_priority"] = int(m.group(5))
    thread["has_irp"] = irp_count > 0
    thread["irp_count"] = irp_count

    in_stack = False
    stack_top: list[str] = []
    for line in lines:
        if line.strip().startswith("Child-SP"):
            in_stack = True
            continue
        if in_stack:
            m = re.match(r'^[0-9a-fA-F`]+\s+[0-9a-fA-F`]+\s+:\s+.+?:\s+(.+)', line)
            if m:
                name = m.group(1).strip()
                name = re.sub(r'\+0x[0-9a-fA-F]+$', '', name)
                if name not in stack_top:
                    stack_top.append(name)
            elif line.strip() == "":
                break
    thread["stack_top"] = stack_top[:5]

    return thread


def _summarize_thread(t: dict[str, object]) -> dict[str, object]:
    result: dict[str, object] = {
        "address": t.get("address", ""),
        "cid": t.get("cid", ""),
        "state": t.get("state", ""),
    }
    if t.get("process_address"):
        result["process"] = {
            "address": t["process_address"],
            "image": t.get("process_image", ""),
        }
    cpu: dict[str, object] = {}
    if t.get("processor") is not None:
        cpu["processor"] = t["processor"]
    if t.get("ideal_processor") is not None:
        cpu["ideal_processor"] = t["ideal_processor"]
    if cpu:
        result["cpu"] = cpu
    timing: dict[str, object] = {}
    if t.get("wait_start_tick") is not None:
        timing["wait_ticks"] = t["wait_start_tick"]
    if t.get("user_time_ms") is not None:
        timing["user_time_ms"] = t["user_time_ms"]
    if t.get("kernel_time_ms") is not None:
        timing["kernel_time_ms"] = t["kernel_time_ms"]
    if timing:
        result["timing"] = timing
    result["priority"] = {
        "base": t.get("base_priority", 0),
        "current": t.get("priority", 0),
        "foreground_boost": t.get("foreground_boost", 0),
    }
    result["io"] = {
        "has_irp": t.get("has_irp", False),
        "irp_count": t.get("irp_count", 0),
    }
    if t.get("stack_top"):
        result["stack_top"] = t["stack_top"]
    return result


def _get_timeout(command: str) -> int:
    """Helper function to get timeout for commands using unified system."""
    from core.execution.timeout_resolver import resolve_timeout
    from config import DebuggingMode
    return resolve_timeout(command, DebuggingMode.VM_NETWORK)


def register_analysis_tools(mcp: FastMCP):
    """Register all analysis tools."""
    
    @mcp.tool()
    async def analyze_process(ctx: Context, action: str, address: str = "", save_context: bool = True, verbosity: str = "summary") -> Union[str, Dict[str, Any]]:
        """
        Analyze processes in the debugging session.
        
        Args:
            ctx: The MCP context
            action: Action to perform - "list", "switch", "info", "peb", "restore"
            address: Process address (required for "switch", "info", "peb")
            save_context: Whether to save current context before switching (default: True)
            verbosity: Output detail level for "list" action - "summary" (eprocess, pid, image) or "full" (all fields) (default: "summary")
            
        Returns:
            Process analysis results
        """
        logger.debug(f"Analyze process action: {action}, address: {address}")
        
        # Parameter validation
        params = {"action": action}
        if address:
            params["address"] = address
        if save_context is not True:  # Only include if not default
            params["save_context"] = save_context
            
        is_valid, validation_errors = validate_tool_parameters("analyze_process", action, params)
        if not is_valid:
            if action not in ["list", "switch", "info", "peb", "restore"]:
                # Invalid action
                help_info = get_parameter_help("analyze_process")
                enhanced_error = enhance_error("parameter", 
                                             tool_name="analyze_process", 
                                             action="", 
                                             missing_param="action")
                error_dict = enhanced_error.to_dict()
                error_dict["available_actions"] = list(help_info.get("actions", {}).keys())
                error_dict["help"] = help_info.get("actions", {}).get(action, {})
                return error_dict
            else:
                # Missing required parameter (likely address)
                enhanced_error = enhance_error("parameter", 
                                             tool_name="analyze_process", 
                                             action=action, 
                                             missing_param="address")
                return enhanced_error.to_dict()
        
        try:
            context_mgr = get_context_manager()
            
            if action == "list":
                try:
                    raw = send_command("!process 0 0", timeout_ms=_get_timeout("!process 0 0"))
                    parsed = _parse_process_list(raw)
                    if verbosity == "full":
                        processes = [_full_process(p) for p in parsed]
                    else:
                        processes = [_summarize_process(p) for p in parsed]
                    return {
                        "processes": processes,
                        "count": len(processes),
                        "verbosity": verbosity,
                    }
                except (CommunicationError, TimeoutError) as e:
                    enhanced_error = enhance_error("timeout", command="!process 0 0", timeout_ms=_get_timeout("!process 0 0"))
                    return enhanced_error.to_dict()
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!process 0 0", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "switch":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_process", missing_param="address")
                    return enhanced_error.to_dict()
                    
                # Save current context if requested
                if save_context:
                    saved = context_mgr.push_context(send_command)
                    logger.debug(f"Saved context before process switch")
                
                try:
                    # Switch to the specified process
                    switch_cmd = f".process /i {address}"
                    result = send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                    
                    return {
                        "success": True,
                        "output": result,
                        "switched_to": address,
                        "next_steps": [
                            "Context switch initiated",
                            "Use 'g' command to let target execute", 
                            "After break, context will be in the target process"
                        ]
                    }
                    
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=switch_cmd, original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "info":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_process", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    # Get detailed process information
                    result = send_command(f"!process {address} 7", timeout_ms=_get_timeout(f"!process {address} 7"))
                    return {"output": result, "process_address": address}
                except (CommunicationError, TimeoutError) as e:
                    enhanced_error = enhance_error("timeout", command=f"!process {address} 7", timeout_ms=_get_timeout(f"!process {address} 7"))
                    return enhanced_error.to_dict()
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!process {address} 7", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "peb":
                # Get Process Environment Block information
                if detect_kernel_mode():
                    return {
                        "error": "PEB analysis not available in kernel mode",
                        "suggestion": "Use !process command for kernel-mode process analysis",
                        "category": "mode_mismatch"
                    }
                
                try:
                    if address:
                        # Switch to process first, then get PEB
                        switch_cmd = f".process /i {address}"
                        send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                        
                    peb_result = send_command("!peb", timeout_ms=_get_timeout("!peb"))
                    return {"output": peb_result, "context": "Process Environment Block"}
                    
                except (CommunicationError, TimeoutError) as e:
                    enhanced_error = enhance_error("timeout", command="!peb", timeout_ms=_get_timeout("!peb"))
                    return enhanced_error.to_dict()
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!peb", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "restore":
                try:
                    success = context_mgr.pop_context(send_command)
                    if success:
                        error_enhancer.update_context(DebugContext.UNKNOWN)  # Reset context
                        result = send_command("!peb", timeout_ms=_get_timeout("!peb"))
                        return {"success": True, "message": "Context restored", "current_context": result[:200]}
                    else:
                        return {"success": False, "message": "No saved context to restore"}
                except (CommunicationError, TimeoutError) as e:
                    enhanced_error = enhance_error("timeout", command="!peb", timeout_ms=_get_timeout("!peb"))
                    return enhanced_error.to_dict()
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!peb", original_error=str(e))
                    return enhanced_error.to_dict()
            
            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["list", "switch", "info", "peb", "restore"],
                    "examples": [
                        "analyze_process(action='list')",
                        "analyze_process(action='info', address='0xffff8e0e481d7080')"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_process", original_error=str(e))
            return enhanced_error.to_dict()

    @mcp.tool()
    async def analyze_thread(ctx: Context, action: str, address: str = "", count: int = 20, verbosity: str = "raw") -> Union[str, Dict[str, Any]]:
        """
        Analyze threads in the debugging session.
        
        Args:
            ctx: The MCP context
            action: Action to perform - "list", "switch", "info", "stack", "all_stacks", "teb"
            address: Thread address (required for "switch", "info", "stack", "teb")
            count: Number of stack frames or threads to show (default: 20)
            verbosity: Output format for "list" action - "raw" (original WinDbg output) or "summary" (structured JSON) (default: "raw")
            
        Returns:
            Thread analysis results
        """
        logger.debug(f"Analyze thread action: {action}, address: {address}")
        
        try:
            context_mgr = get_context_manager()
            
            if action == "list":
                try:
                    raw = send_command("!thread", timeout_ms=_get_timeout("!thread"))
                    if verbosity == "summary":
                        parsed = _parse_thread_output(raw)
                        if parsed:
                            return {"thread": _summarize_thread(parsed), "format": "summary"}
                        return {"error": "Failed to parse thread output", "raw": raw}
                    return {"output": raw, "note": "Copy thread address for detailed analysis"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!thread", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "switch":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_thread", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    switch_cmd = f"~{address}s"
                    result = send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                    return {"output": result, "switched_to": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=switch_cmd, original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "info":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_thread", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    result = send_command(f"!thread {address}", timeout_ms=_get_timeout(f"!thread {address}"))
                    return {"output": result, "thread_address": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!thread {address}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "stack":
                try:
                    if address:
                        # Switch to thread first, then get stack
                        switch_cmd = f"~{address}s"
                        send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                    
                    stack_result = send_command(f"k {count}", timeout_ms=_get_timeout(f"k {count}"))
                    return {"output": stack_result, "stack_frames": count}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"k {count}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "all_stacks":
                try:
                    result = send_command(f"k {count}", timeout_ms=_get_timeout(f"k {count}"))
                    
                    # Get basic thread list for context
                    thread_list = send_command("!thread", timeout_ms=_get_timeout("!thread"))
                    
                    # For performance, show limited stacks for multiple threads
                    stacks = []
                    try:
                        # Try to get stacks for a few threads (simplified approach)
                        for i in range(min(3, count // 10)):  # Sample a few threads
                            try:
                                stack = send_command("k 10", timeout_ms=_get_timeout("k 10"))  # Shorter stacks for multiple threads
                                stacks.append(f"Thread {i} stack (sample):\n{stack}")
                            except:
                                continue
                    except:
                        pass
                    
                    return {
                        "output": result,
                        "thread_list": thread_list[:500] + "..." if len(thread_list) > 500 else thread_list,
                        "sample_stacks": stacks
                    }
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"k {count}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "teb":
                # Get Thread Environment Block information  
                if detect_kernel_mode():
                    return {
                        "error": "TEB analysis not available in kernel mode",
                        "suggestion": "Use !thread command for kernel-mode thread analysis",
                        "category": "mode_mismatch"
                    }
                
                try:
                    if address:
                        # Switch to thread first
                        switch_cmd = f"~{address}s"
                        send_command(switch_cmd, timeout_ms=_get_timeout(switch_cmd))
                        
                    teb_result = send_command("!teb", timeout_ms=_get_timeout("!teb"))
                    return {"output": teb_result, "context": "Thread Environment Block"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!teb", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["list", "switch", "info", "stack", "all_stacks", "teb"],
                    "examples": [
                        "analyze_thread(action='list')",
                        "analyze_thread(action='stack', count=20)"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_thread", original_error=str(e))
            return enhanced_error.to_dict()

    @mcp.tool()
    async def analyze_memory(ctx: Context, action: str, address: str = "", type_name: str = "", length: int = 32) -> Union[str, Dict[str, Any]]:
        """
        Analyze memory and data structures.
        
        Args:
            ctx: The MCP context
            action: Action to perform - "display", "type", "search", "pte", "regions"
            address: Memory address (required for most actions)
            type_name: Type name for structure display (required for "type" action)
            length: Number of bytes/elements to display (default: 32)
            
        Returns:
            Memory analysis results
        """
        logger.debug(f"Analyze memory action: {action}, address: {address}, type: {type_name}")
        
        try:
            # Detect debugging mode for mode-specific commands
            is_kernel_mode = detect_kernel_mode()
            logger.debug(f"Detected debugging mode: {'kernel' if is_kernel_mode else 'user'}")
            
            if action == "display":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    # Display memory content
                    result = send_command(f"dd {address} l{length}", timeout_ms=_get_timeout(f"dd {address} l{length}"))
                    return {"output": result, "address": address, "length": length}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"dd {address} l{length}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "type":
                if not address or not type_name:
                    missing = "address and type_name" if not address and not type_name else ("address" if not address else "type_name")
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param=missing)
                    return enhanced_error.to_dict()
                
                try:
                    # Display typed structure
                    result = send_command(f"dt {type_name} {address}", timeout_ms=_get_timeout(f"dt {type_name} {address}"))
                    return {"output": result, "type": type_name, "address": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"dt {type_name} {address}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "search":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    # Search for pattern in memory range
                    search_cmd = f"s {address} L{length} {address[:8]}"  # Search for first 8 chars as pattern
                    result = send_command(search_cmd, timeout_ms=_get_timeout(search_cmd))
                    return {"output": result, "search_range": f"{address} L{length}"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=search_cmd, original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "pte":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_memory", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    # Page Table Entry analysis
                    result = send_command(f"!pte {address}", timeout_ms=_get_timeout(f"!pte {address}"))
                    return {"output": result, "pte_address": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!pte {address}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "regions":
                try:
                    # Virtual memory regions
                    result = send_command("!vm", timeout_ms=_get_timeout("!vm"))
                    return {"output": result, "context": "Virtual memory regions"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!vm", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["display", "type", "search", "pte", "regions"],
                    "examples": [
                        "analyze_memory(action='display', address='0x1000')",
                        "analyze_memory(action='type', address='0x1000', type_name='_EPROCESS')"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_memory", original_error=str(e))
            return enhanced_error.to_dict()

    @mcp.tool()
    async def analyze_kernel(ctx: Context, action: str, address: str = "") -> Union[str, Dict[str, Any]]:
        """
        Analyze kernel objects and structures.
        
        Args:
            ctx: The MCP context
            action: Action to perform - "object", "idt", "interrupts", "modules"
            address: Object address (required for "object", "interrupts")
            
        Returns:
            Kernel analysis results
        """
        logger.debug(f"Analyze kernel action: {action}, address: {address}")
        
        try:
            if action == "object":
                if not address:
                    enhanced_error = enhance_error("parameter", tool_name="analyze_kernel", missing_param="address")
                    return enhanced_error.to_dict()
                
                try:
                    result = send_command(f"!object {address}", timeout_ms=_get_timeout(f"!object {address}"))
                    return {"output": result, "object_address": address}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command=f"!object {address}", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "idt":
                try:
                    result = send_command("!idt", timeout_ms=_get_timeout("!idt"))
                    return {"output": result, "context": "Interrupt Descriptor Table"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="!idt", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            elif action == "interrupts":
                if address:
                    try:
                        result = send_command(f"!pic {address}", timeout_ms=_get_timeout(f"!pic {address}"))
                        return {"output": result, "interrupt_controller": address}
                    except Exception as e:
                        enhanced_error = enhance_error("execution", command=f"!pic {address}", original_error=str(e))
                        return enhanced_error.to_dict()
                else:
                    try:
                        result = send_command("!irql", timeout_ms=_get_timeout("!irql"))
                        return {"output": result, "context": "Current IRQL and interrupts"}
                    except Exception as e:
                        enhanced_error = enhance_error("execution", command="!irql", original_error=str(e))
                        return enhanced_error.to_dict()
                        
            elif action == "modules":
                try:
                    result = send_command("lm", timeout_ms=_get_timeout("lm"))
                    return {"output": result, "context": "Loaded modules"}
                except Exception as e:
                    enhanced_error = enhance_error("execution", command="lm", original_error=str(e))
                    return enhanced_error.to_dict()
                    
            else:
                return {
                    "error": f"Unknown action: {action}",
                    "available_actions": ["object", "idt", "interrupts", "modules"],
                    "examples": [
                        "analyze_kernel(action='idt')",
                        "analyze_kernel(action='object', address='0xffffffff80000000')"
                    ]
                }
                
        except Exception as e:
            enhanced_error = enhance_error("unexpected", tool_name="analyze_kernel", original_error=str(e))
            return enhanced_error.to_dict() 
