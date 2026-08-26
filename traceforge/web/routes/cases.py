from traceforge.web.router import Request, Response, Router
from traceforge.web.services import case_service


def register_case_routes(router: Router) -> None:
    @router.get("/api/cases")
    def handle_list_cases(req: Request) -> Response:
        cases = case_service.list_cases()
        active_id = case_service.get_active_case_id()
        return Response.json({"cases": cases, "active_case": active_id})

    @router.post("/api/cases")
    def handle_create_case(req: Request) -> Response:
        data = req.json()
        name = data.get("name", "").strip()
        analyst = data.get("analyst", "Analyst").strip()
        if not name:
            return Response.error("Case name is required", status_code=400)
        c = case_service.create_case(name, analyst)
        return Response.json({"success": True, "case": c.summary()}, status_code=201)

    @router.get("/api/cases/active")
    def handle_get_active_case(req: Request) -> Response:
        active_id = case_service.get_active_case_id()
        if not active_id:
            return Response.json({"active_case": None})
        c = case_service.get_case(active_id)
        return Response.json({"active_case": c.summary() if c else None})

    @router.post("/api/cases/active")
    def handle_set_active_case(req: Request) -> Response:
        data = req.json()
        cid = data.get("case_id", "").strip()
        if not case_service.set_active_case_id(cid):
            return Response.error(f"Case '{cid}' not found", status_code=404)
        return Response.json({"success": True, "active_case": cid})

    @router.get("/api/cases/<case_id>")
    def handle_get_case(req: Request, case_id: str) -> Response:
        c = case_service.get_case(case_id)
        if not c:
            return Response.error(f"Case '{case_id}' not found", status_code=404)
        return Response.json(c.data)

    @router.delete("/api/cases/<case_id>")
    def handle_delete_case(req: Request, case_id: str) -> Response:
        if not case_service.delete_case(case_id):
            return Response.error(f"Could not delete case '{case_id}'", status_code=404)
        return Response.json({"success": True, "deleted": case_id})

    @router.get("/api/cases/<case_id>/evidence")
    def handle_list_evidence(req: Request, case_id: str) -> Response:
        evidence = case_service.list_evidence(case_id)
        return Response.json({"evidence": evidence})

    @router.get("/api/cases/<case_id>/iocs")
    def handle_list_iocs(req: Request, case_id: str) -> Response:
        ioc_type = req.get_param("type")
        search = req.get_param("q")
        iocs = case_service.list_case_iocs(case_id, ioc_type=ioc_type, search=search)
        return Response.json({"iocs": iocs})

    @router.post("/api/cases/<case_id>/iocs")
    def handle_add_ioc(req: Request, case_id: str) -> Response:
        data = req.json()
        ioc_type = data.get("type", "").strip()
        value = data.get("value", "").strip()
        confidence = data.get("confidence", "high").strip()
        if not ioc_type or not value:
            return Response.error("IOC type and value are required", status_code=400)
        ioc = case_service.add_case_ioc(case_id, ioc_type, value, confidence=confidence)
        if not ioc:
            return Response.error(f"Case '{case_id}' not found", status_code=404)
        return Response.json({"success": True, "ioc": ioc}, status_code=201)

    @router.get("/api/cases/<case_id>/findings")
    def handle_list_findings(req: Request, case_id: str) -> Response:
        sev = req.get_param("severity")
        findings = case_service.list_case_findings(case_id, severity=sev)
        return Response.json({"findings": findings})

    @router.post("/api/cases/<case_id>/findings")
    def handle_add_finding(req: Request, case_id: str) -> Response:
        data = req.json()
        title = data.get("title", "").strip()
        details = data.get("details", "").strip()
        severity = data.get("severity", "Medium").strip()
        if not title:
            return Response.error("Finding title is required", status_code=400)
        f = case_service.add_case_finding(case_id, title, details, severity=severity)
        if not f:
            return Response.error(f"Case '{case_id}' not found", status_code=404)
        return Response.json({"success": True, "finding": f}, status_code=201)

    @router.get("/api/cases/<case_id>/timeline")
    def handle_list_timeline(req: Request, case_id: str) -> Response:
        timeline = case_service.list_case_timeline(case_id)
        return Response.json({"timeline": timeline})

    @router.post("/api/cases/<case_id>/timeline")
    def handle_add_timeline(req: Request, case_id: str) -> Response:
        data = req.json()
        desc = data.get("description", "").strip()
        source = data.get("source", "analyst").strip()
        if not desc:
            return Response.error("Event description is required", status_code=400)
        evt = case_service.add_case_timeline_event(case_id, desc, source=source)
        if not evt:
            return Response.error(f"Case '{case_id}' not found", status_code=404)
        return Response.json({"success": True, "event": evt}, status_code=201)
