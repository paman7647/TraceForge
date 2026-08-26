from traceforge.web.router import Router
from traceforge.web.routes.batch import register_batch_routes
from traceforge.web.routes.cases import register_case_routes
from traceforge.web.routes.investigations import register_investigation_routes
from traceforge.web.routes.reports import register_report_routes
from traceforge.web.routes.runtime import register_runtime_routes
from traceforge.web.routes.tools import register_tool_routes


def register_all_routes(router: Router) -> None:
    """Registers all modular endpoint handlers with the router."""
    register_case_routes(router)
    register_investigation_routes(router)
    register_tool_routes(router)
    register_batch_routes(router)
    register_report_routes(router)
    register_runtime_routes(router)
