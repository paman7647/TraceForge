from traceforge.web.router import Request, Response, Router
from traceforge.web.services import runtime_service


def register_runtime_routes(router: Router) -> None:
    @router.get("/api/runtime/status")
    def handle_get_status(req: Request) -> Response:
        status = runtime_service.get_runtime_status()
        return Response.json(status)

    @router.post("/api/runtime/profile")
    def handle_set_profile(req: Request) -> Response:
        data = req.json()
        profile = data.get("profile", "").strip()
        if not profile:
            return Response.error("Profile name is required", status_code=400)
        if not runtime_service.set_profile(profile):
            return Response.error(f"Invalid profile name '{profile}'", status_code=400)
        return Response.json({"success": True, "active_profile": profile})

    @router.get("/api/runtime/paths")
    def handle_get_paths(req: Request) -> Response:
        paths = runtime_service.get_paths()
        return Response.json({"paths": paths})

    @router.post("/api/runtime/repair")
    def handle_repair(req: Request) -> Response:
        res = runtime_service.execute_repair()
        return Response.json(res)
