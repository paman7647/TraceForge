from traceforge.web.router import Request, Response, Router
from traceforge.web.services import report_service


def register_report_routes(router: Router) -> None:
    @router.get("/api/cases/<case_id>/report")
    def handle_get_report(req: Request, case_id: str) -> Response:
        fmt = req.get_param("format", "markdown")
        redact = req.get_param("redact") == "1"
        report_text = report_service.generate_case_report(case_id, fmt=fmt, redact=redact)
        if report_text is None:
            return Response.error(f"Case '{case_id}' not found", status_code=404)

        if fmt.lower() == "html":
            return Response(status_code=200, body=report_text.encode("utf-8"), content_type="text/html; charset=utf-8")
        elif fmt.lower() == "json" or fmt.lower() == "stix":
            return Response(status_code=200, body=report_text.encode("utf-8"), content_type="application/json")
        else:
            return Response.text(report_text)

    @router.post("/api/cases/<case_id>/export")
    def handle_export_case(req: Request, case_id: str) -> Response:
        data = req.json()
        redact = data.get("redact", False)
        out_files = report_service.export_case(case_id, redact=redact)
        if out_files is None:
            return Response.error(f"Case '{case_id}' not found", status_code=404)
        return Response.json({"success": True, "exports": out_files})
