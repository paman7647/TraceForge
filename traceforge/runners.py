import datetime
import os
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from traceforge.config import get_runtime_profile, get_feature_runtime
from traceforge.platform_detect import which_tool, is_tool_installed

class ToolExecutionResult:
    def __init__(
        self,
        command: List[str],
        exit_code: int,
        stdout: str,
        stderr: str,
        duration_seconds: float,
        executed_at: str,
    ):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_seconds = duration_seconds
        self.executed_at = executed_at

    @property
    def success(self) -> bool:
        return self.exit_code == 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": " ".join(self.command),
            "exit_code": self.exit_code,
            "stdout_length": len(self.stdout),
            "stderr_length": len(self.stderr),
            "duration_seconds": round(self.duration_seconds, 3),
            "executed_at": self.executed_at,
            "success": self.success,
        }

class ToolRunner:
    """Safely executes external native binaries using structured parameter arrays."""

    @staticmethod
    def run(
        binary_name: str,
        args: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        timeout: int = 60,
        env: Optional[Dict[str, str]] = None,
        input_data: Optional[Union[str, bytes]] = None,
    ) -> ToolExecutionResult:
        binary_path = which_tool(binary_name)
        if not binary_path:
            return ToolExecutionResult(
                command=[binary_name] + (args or []),
                exit_code=127,
                stdout="",
                stderr=f"Tool not found on system PATH: {binary_name}",
                duration_seconds=0.0,
                executed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            )

        cmd = [binary_path] + (args or [])
        start_time = time.time()
        exec_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        stdin_mode = subprocess.PIPE if input_data is not None else None
        text_mode = isinstance(input_data, str) or input_data is None

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=stdin_mode,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=text_mode,
                cwd=cwd,
                env=run_env,
            )

            stdout_data, stderr_data = proc.communicate(
                input=input_data,
                timeout=timeout
            )
            duration = time.time() - start_time

            if isinstance(stdout_data, bytes):
                stdout_str = stdout_data.decode("utf-8", errors="replace")
            else:
                stdout_str = stdout_data or ""

            if isinstance(stderr_data, bytes):
                stderr_str = stderr_data.decode("utf-8", errors="replace")
            else:
                stderr_str = stderr_data or ""

            return ToolExecutionResult(
                command=cmd,
                exit_code=proc.returncode,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_seconds=duration,
                executed_at=exec_ts,
            )

        except subprocess.TimeoutExpired:
            proc.kill()
            return ToolExecutionResult(
                command=cmd,
                exit_code=124,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                duration_seconds=float(timeout),
                executed_at=exec_ts,
            )
        except Exception as e:
            return ToolExecutionResult(
                command=cmd,
                exit_code=1,
                stdout="",
                stderr=str(e),
                duration_seconds=time.time() - start_time,
                executed_at=exec_ts,
            )


# -----------------------------------------------------------------------------
# Runtime Capability Matrix & Adaptive Fast-Path Engine
# -----------------------------------------------------------------------------

CAPABILITY_MATRIX: Dict[str, Dict[str, Any]] = {
    "hash": {
        "preferred": "go",
        "fallback": "python",
        "native_tool": "tracehash",
        "performance_class": "high-throughput",
        "reason": "Go provides sub-millisecond cold start and high-throughput recursive file hashing.",
    },
    "pcap": {
        "preferred": "native",
        "fallback": "go",
        "secondary_fallback": "python",
        "native_tool": "tshark",
        "go_tool": "tracepcap",
        "performance_class": "dissection",
        "reason": "TShark provides deep protocol dissection; Go provides fast packet header triage; Python is offline fallback.",
    },
    "ioc": {
        "preferred": "go",
        "fallback": "python",
        "native_tool": "traceforge-native",
        "performance_class": "streaming",
        "reason": "Go compiled scanner processes high-volume log streams with zero GC pauses; Python provides offline regex engine.",
    },
    "timeline": {
        "preferred": "go",
        "fallback": "python",
        "native_tool": "traceforge-native",
        "performance_class": "sorting",
        "reason": "Go handles high-volume timestamp parsing and sorting; Python provides dateutil parser flexibility.",
    },
    "triage": {
        "preferred": "go",
        "fallback": "python",
        "native_tool": "traceforge-native",
        "performance_class": "aggregation",
        "reason": "Go handles streaming log file aggregation; Python provides flexible structure parsing.",
    },
    "baseline": {
        "preferred": "go",
        "fallback": "python",
        "native_tool": "traceforge-native",
        "performance_class": "filesystem",
        "reason": "Go provides fast recursive directory traversal and parallel hashing.",
    },
    "graph": {
        "preferred": "python",
        "fallback": "none",
        "performance_class": "graph",
        "reason": "Python handles entity relationship modeling and interactive HTML network graph generation.",
    },
    "report": {
        "preferred": "python",
        "fallback": "none",
        "performance_class": "rendering",
        "reason": "Python has the strongest cross-platform reporting ecosystem (Markdown, HTML, STIX, MISP, XLSX).",
    },
}

class RuntimeDecision:
    def __init__(
        self,
        feature: str,
        selected_runtime: str,
        preferred_runtime: str,
        fallback_runtime: str,
        reason: str,
        binary_used: Optional[str] = None,
    ):
        self.feature = feature
        self.selected_runtime = selected_runtime
        self.preferred_runtime = preferred_runtime
        self.fallback_runtime = fallback_runtime
        self.reason = reason
        self.binary_used = binary_used

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "selected_runtime": self.selected_runtime,
            "preferred_runtime": self.preferred_runtime,
            "fallback_runtime": self.fallback_runtime,
            "reason": self.reason,
            "binary_used": self.binary_used,
        }

    def print_verbose(self) -> None:
        print(f"[*] [Runtime] Feature: {self.feature} | Active: {self.selected_runtime.upper()} | Preferred: {self.preferred_runtime} | Reason: {self.reason}")

def select_runtime_for_feature(feature: str, verbose: bool = False) -> RuntimeDecision:
    """Evaluates the active profile, overrides, and binary availability to choose the runtime."""
    spec = CAPABILITY_MATRIX.get(feature, {
        "preferred": "python",
        "fallback": "none",
        "reason": "Default Python execution",
    })

    pref = spec.get("preferred", "python")
    fallback = spec.get("fallback", "python")
    profile = get_runtime_profile()

    # Check explicit user feature override
    override = get_feature_runtime(feature)
    if override:
        if override == "go":
            go_bin = which_tool(spec.get("native_tool", "traceforge-native")) or which_tool("traceforge-native")
            if go_bin:
                dec = RuntimeDecision(feature, "go", pref, fallback, "User configuration override (Go enabled)", go_bin)
                if verbose:
                    dec.print_verbose()
                return dec
        elif override == "python":
            dec = RuntimeDecision(feature, "python", pref, fallback, "User configuration override (Python forced)")
            if verbose:
                dec.print_verbose()
            return dec

    # Check profile restrictions
    if profile == "minimal":
        dec = RuntimeDecision(feature, "python", pref, fallback, "Minimal profile active (Python built-ins only)")
        if verbose:
            dec.print_verbose()
        return dec

    if profile == "python":
        dec = RuntimeDecision(feature, "python", pref, fallback, "Python profile active (pure Python execution)")
        if verbose:
            dec.print_verbose()
        return dec

    # Profile allows Go / Native (e.g. 'go', 'python-go', 'full', 'custom')
    if pref in ("go", "native"):
        # Look for dedicated tool or traceforge-native
        target_tool = spec.get("native_tool", "traceforge-native")
        bin_path = which_tool(target_tool) or which_tool("traceforge-native")
        if bin_path:
            dec = RuntimeDecision(feature, "go" if "trace" in target_tool else "native", pref, fallback, spec.get("reason", "Native helper available"), bin_path)
            if verbose:
                dec.print_verbose()
            return dec

    # Fallback to Python
    dec = RuntimeDecision(feature, "python", pref, fallback, f"Fallback to Python ({spec.get('reason', 'Reference implementation')})")
    if verbose:
        dec.print_verbose()
    return dec
