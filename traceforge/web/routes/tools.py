from traceforge.web.router import Request, Response, Router
from traceforge.web.services import tool_service


def register_tool_routes(router: Router) -> None:
    @router.get("/api/tools")
    def handle_list_tools(req: Request) -> Response:
        cat = req.get_param("category")
        subcat = req.get_param("subcategory")
        q = req.get_param("q")
        installed_only = req.get_param("installed") == "1"
        available_only = req.get_param("available") == "1"

        tools = tool_service.list_catalog_tools(
            category=cat,
            subcategory=subcat,
            search=q,
            installed_only=installed_only,
            available_only=available_only,
        )
        return Response.json({"tools": tools, "total": len(tools)})

    @router.get("/api/tools/<tool_id>")
    def handle_get_tool(req: Request, tool_id: str) -> Response:
        tool = tool_service.get_tool_details(tool_id)
        if not tool:
            return Response.error(f"Tool '{tool_id}' not found in catalog", status_code=404)
        return Response.json({"tool": tool})

    @router.get("/api/catalog/platform-audit")
    def handle_platform_audit(req: Request) -> Response:
        audit = tool_service.get_platform_audit()
        return Response.json({"audit": audit})

    @router.get("/api/tools/audit")
    def handle_integration_audit(req: Request) -> Response:
        audit = tool_service.get_integration_audit()
        return Response.json({"audit": audit})

    @router.post("/api/tools/<tool_id>/run")
    def handle_run_tool(req: Request, tool_id: str) -> Response:
        data = req.json()
        target = data.get("target", "").strip()
        extra_args = data.get("args", [])
        timeout = int(data.get("timeout", 60))

        res = tool_service.run_catalog_tool(tool_id, target=target, extra_args=extra_args, timeout=timeout)
        return Response.json(res)

    @router.post("/api/tools/<tool_id>/install")
    def handle_install_tool(req: Request, tool_id: str) -> Response:
        res = tool_service.install_catalog_tool(tool_id)
        status_code = 200 if res.get("success") else 400
        return Response.json(res, status_code=status_code)

