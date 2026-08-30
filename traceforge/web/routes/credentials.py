"""TraceForge Web Routes for API Key & Credentials Vault.

Exposes REST endpoints for viewing, updating, deleting, and testing
third-party OSINT API keys and provider tokens.
"""

from traceforge.web.router import Request, Response, Router
from traceforge.web.services import credentials_service


def register_credentials_routes(router: Router) -> None:
    @router.get("/api/credentials")
    def handle_list_credentials(req: Request) -> Response:
        try:
            data = credentials_service.list_credentials()
            return Response.json(data)
        except Exception as e:
            return Response.error(f"Failed to list credentials: {str(e)}", status_code=500)

    @router.post("/api/credentials/set")
    def handle_set_credential(req: Request) -> Response:
        data = req.json()
        key = data.get("key", "").strip()
        value = data.get("value", "").strip()
        if not key or not value:
            return Response.error("Both 'key' and 'value' parameters are required", status_code=400)

        try:
            res = credentials_service.set_credential(key, value)
            return Response.json(res)
        except Exception as e:
            return Response.error(f"Failed to set credential: {str(e)}", status_code=500)

    @router.post("/api/credentials/remove")
    def handle_remove_credential(req: Request) -> Response:
        data = req.json()
        key = data.get("key", "").strip()
        if not key:
            return Response.error("'key' parameter is required", status_code=400)

        try:
            res = credentials_service.delete_credential(key)
            return Response.json(res)
        except Exception as e:
            return Response.error(f"Failed to remove credential: {str(e)}", status_code=500)

    @router.post("/api/credentials/test")
    def handle_test_credential(req: Request) -> Response:
        data = req.json()
        key = data.get("key", "").strip()
        if not key:
            return Response.error("'key' parameter is required", status_code=400)

        try:
            res = credentials_service.validate_credential(key)
            return Response.json(res)
        except Exception as e:
            return Response.error(f"Failed to test credential: {str(e)}", status_code=500)

    @router.get("/api/credentials/template")
    def handle_get_template(req: Request) -> Response:
        try:
            tpl = credentials_service.get_template()
            return Response(
                status_code=200,
                headers={"Content-Type": "text/plain; charset=utf-8"},
                body=tpl.encode("utf-8"),
            )
        except Exception as e:
            return Response.error(f"Failed to generate template: {str(e)}", status_code=500)
