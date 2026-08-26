import threading
import uuid
from typing import Any, Dict, List, Optional

from traceforge.batch import (
    BatchEngine,
    BatchPlan,
    BatchResult,
    PREDEFINED_WORKFLOWS,
)
from traceforge.case import Case

# Active in-memory jobs store for live execution streaming
ACTIVE_JOBS: Dict[str, Dict[str, Any]] = {}
ACTIVE_CANCEL_EVENTS: Dict[str, threading.Event] = {}
_JOB_LOCK = threading.Lock()


def get_engine() -> BatchEngine:
    return BatchEngine()


def build_plan(
    raw_input: str,
    tool_identifiers: Optional[List[str]] = None,
    workflow: Optional[str] = None,
    execution_mode: str = "sequential",
    max_workers: int = 3,
    timeout_seconds: int = 60,
) -> BatchPlan:
    """Builds pre-flight batch execution plan for validation and review."""
    engine = get_engine()
    if workflow and workflow in PREDEFINED_WORKFLOWS:
        return engine.create_plan_for_workflow(
            raw_input=raw_input,
            workflow_id=workflow,
            execution_mode=execution_mode,
            max_workers=max_workers,
            per_tool_timeout=timeout_seconds,
        )
    return engine.create_plan(
        raw_input=raw_input,
        tool_identifiers=tool_identifiers or [],
        execution_mode=execution_mode,
        max_workers=max_workers,
        timeout_seconds=timeout_seconds,
    )


def start_job(plan: BatchPlan, case_id: Optional[str] = None) -> str:
    """Starts background batch execution with thread-safe live log streaming."""
    job_id = f"batch-{uuid.uuid4().hex[:8]}"
    cancel_event = threading.Event()

    with _JOB_LOCK:
        ACTIVE_JOBS[job_id] = {
            "job_id": job_id,
            "status": "RUNNING",
            "plan": plan.to_dict(),
            "logs": [],
            "results": None,
            "error": None,
            "case_id": case_id,
        }
        ACTIVE_CANCEL_EVENTS[job_id] = cancel_event

    def _worker():
        engine = get_engine()
        def _log(m: str):
            with _JOB_LOCK:
                if job_id in ACTIVE_JOBS:
                    ACTIVE_JOBS[job_id]["logs"].append(m)

        try:
            res: BatchResult = engine.execute_plan(plan, job_id=job_id, on_log=_log, cancel_event=cancel_event)
            
            # Associate extracted IOCs and findings to active case if provided
            if case_id:
                try:
                    c = Case(case_id)
                    for ioc in res.deduplicated_indicators:
                        c.add_ioc(ioc["type"], ioc["value"], confidence=ioc.get("confidence", "high"))
                    for f in res.aggregated_findings:
                        c.add_finding(f["title"], f["details"], severity=f.get("severity", "Medium"))
                    c.add_timeline_event(f"Batch investigation '{job_id}' completed across {res.total_tools_run} tools.")
                except Exception:
                    pass

            with _JOB_LOCK:
                if job_id in ACTIVE_JOBS:
                    ACTIVE_JOBS[job_id]["status"] = "COMPLETED"
                    ACTIVE_JOBS[job_id]["results"] = res.to_dict()
        except Exception as e:
            with _JOB_LOCK:
                if job_id in ACTIVE_JOBS:
                    ACTIVE_JOBS[job_id]["status"] = "FAILED"
                    ACTIVE_JOBS[job_id]["error"] = str(e)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return job_id


def get_job_status(job_id: str) -> Optional[Dict[str, Any]]:
    """Returns current state and logs of a batch job."""
    with _JOB_LOCK:
        job = ACTIVE_JOBS.get(job_id)
        if not job:
            return None
        return dict(job)


def cancel_job(job_id: str) -> bool:
    """Signals cancellation to an active batch execution job."""
    with _JOB_LOCK:
        evt = ACTIVE_CANCEL_EVENTS.get(job_id)
        if evt:
            evt.set()
            if job_id in ACTIVE_JOBS:
                ACTIVE_JOBS[job_id]["status"] = "CANCELLED"
            return True
    return False


def list_profiles() -> List[Dict[str, Any]]:
    return get_engine().list_saved_profiles()


def save_profile(name: str, description: str, tools: List[str]) -> Dict[str, Any]:
    return get_engine().save_custom_profile(name, description, tools)


def delete_profile(name: str) -> bool:
    return get_engine().delete_custom_profile(name)


def list_history() -> List[Dict[str, Any]]:
    return get_engine().list_history()
