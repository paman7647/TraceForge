from traceforge.web.router import Request, Response, Router
from traceforge.web.services import batch_service


def register_batch_routes(router: Router) -> None:
    @router.post("/api/batch/plan")
    def handle_create_plan(req: Request) -> Response:
        data = req.json()
        raw_input = data.get("input", "").strip()
        tools = data.get("tools", [])
        workflow = data.get("workflow", "")
        mode = data.get("mode", "sequential")
        workers = int(data.get("workers", 3))
        timeout = int(data.get("timeout", 60))

        if not raw_input:
            return Response.error("Target input specimen or entity is required", status_code=400)

        plan = batch_service.build_plan(
            raw_input=raw_input,
            tool_identifiers=tools,
            workflow=workflow,
            execution_mode=mode,
            max_workers=workers,
            timeout_seconds=timeout,
        )
        return Response.json({"plan": plan.to_dict()})

    @router.post("/api/batch/run")
    def handle_start_batch(req: Request) -> Response:
        data = req.json()
        raw_input = data.get("input", "").strip()
        tools = data.get("tools", [])
        workflow = data.get("workflow", "")
        mode = data.get("mode", "sequential")
        workers = int(data.get("workers", 3))
        timeout = int(data.get("timeout", 60))
        case_id = data.get("case_id", "")

        if not raw_input:
            return Response.error("Target input specimen or entity is required", status_code=400)

        plan = batch_service.build_plan(
            raw_input=raw_input,
            tool_identifiers=tools,
            workflow=workflow,
            execution_mode=mode,
            max_workers=workers,
            timeout_seconds=timeout,
        )
        job_id = batch_service.start_job(plan, case_id=case_id)
        return Response.json({"success": True, "job_id": job_id}, status_code=202)

    @router.get("/api/batch/jobs/<job_id>")
    def handle_get_job(req: Request, job_id: str) -> Response:
        job = batch_service.get_job_status(job_id)
        if not job:
            return Response.error(f"Batch job '{job_id}' not found", status_code=404)
        return Response.json({"job": job})

    @router.post("/api/batch/jobs/<job_id>/cancel")
    def handle_cancel_job(req: Request, job_id: str) -> Response:
        success = batch_service.cancel_job(job_id)
        if not success:
            return Response.error(f"Could not cancel job '{job_id}'", status_code=400)
        return Response.json({"success": True, "job_id": job_id, "status": "CANCELLED"})

    @router.get("/api/batch/profiles")
    def handle_list_profiles(req: Request) -> Response:
        profiles = batch_service.list_profiles()
        return Response.json({"profiles": profiles})

    @router.post("/api/batch/profiles")
    def handle_save_profile(req: Request) -> Response:
        data = req.json()
        name = data.get("name", "").strip()
        desc = data.get("description", "").strip()
        tools = data.get("tools", [])
        if not name or not tools:
            return Response.error("Profile name and at least one tool are required", status_code=400)
        prof = batch_service.save_profile(name, desc, tools)
        return Response.json({"success": True, "profile": prof}, status_code=201)

    @router.post("/api/batch/profiles/delete")
    def handle_delete_profile(req: Request) -> Response:
        data = req.json()
        name = data.get("name", "").strip()
        if not name:
            return Response.error("Profile name is required", status_code=400)
        success = batch_service.delete_profile(name)
        return Response.json({"success": success, "deleted": name})

    @router.get("/api/batch/history")
    def handle_list_history(req: Request) -> Response:
        history = batch_service.list_history()
        return Response.json({"history": history})
