from traceforge.web.router import Request, Response, Router
from traceforge.web.services import investigation_service


def register_investigation_routes(router: Router) -> None:
    @router.get("/api/investigations")
    def handle_list_modules(req: Request) -> Response:
        modules = investigation_service.list_investigation_modules()
        return Response.json({"modules": modules})

    @router.get("/api/investigations/<module_id>")
    def handle_get_module(req: Request, module_id: str) -> Response:
        mod = investigation_service.get_investigation_module(module_id)
        if not mod:
            return Response.error(f"Investigation module '{module_id}' not found", status_code=404)
        return Response.json({"module": mod})

    @router.post("/api/investigations/<module_id>/run")
    def handle_run_module(req: Request, module_id: str) -> Response:
        data = req.json()
        target = data.get("target", "").strip()
        case_id = data.get("case_id", "").strip() or None
        if not target:
            return Response.error("Target parameter (file path or entity string) is required", status_code=400)

        try:
            res = investigation_service.run_investigation(module_id, target, case_id=case_id)
            return Response.json({"success": True, "results": res})
        except FileNotFoundError as e:
            return Response.error(str(e), status_code=404)
        except Exception as e:
            return Response.error(f"Investigation execution failed: {str(e)}", status_code=500)
