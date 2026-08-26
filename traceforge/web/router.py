import json
import re
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Pattern, Tuple


class Request:
    def __init__(self, method: str, path: str, query_params: Dict[str, str], body: bytes, headers: Dict[str, str]):
        self.method = method.upper()
        self.path = path
        self.query_params = query_params
        self.body = body
        self.headers = headers
        self._json_cache: Optional[Dict[str, Any]] = None

    def json(self) -> Dict[str, Any]:
        if self._json_cache is None:
            if not self.body:
                self._json_cache = {}
            else:
                try:
                    self._json_cache = json.loads(self.body.decode("utf-8"))
                except Exception:
                    self._json_cache = {}
        return self._json_cache

    def get_param(self, key: str, default: str = "") -> str:
        return self.query_params.get(key, default)


class Response:
    def __init__(self, status_code: int = 200, body: bytes = b"", content_type: str = "application/json", headers: Optional[Dict[str, str]] = None):
        self.status_code = status_code
        self.body = body
        self.content_type = content_type
        self.headers = headers or {}

    @classmethod
    def json(cls, data: Any, status_code: int = 200) -> "Response":
        body = json.dumps(data, indent=2).encode("utf-8")
        return cls(status_code=status_code, body=body, content_type="application/json")

    @classmethod
    def error(cls, message: str, status_code: int = 400) -> "Response":
        return cls.json({"error": message, "success": False}, status_code=status_code)

    @classmethod
    def text(cls, text: str, status_code: int = 200) -> "Response":
        return cls(status_code=status_code, body=text.encode("utf-8"), content_type="text/plain; charset=utf-8")


class Router:
    def __init__(self):
        self.routes: List[Tuple[str, Pattern, List[str], Callable[..., Response]]] = []

    def add(self, method: str, path_pattern: str, handler: Callable[..., Response]):
        # Convert path like /api/cases/<case_id>/evidence to regex
        param_names: List[str] = []
        
        def replace_param(match):
            name = match.group(1)
            param_names.append(name)
            return r"([^/]+)"

        regex_pattern = "^" + re.sub(r"<([a-zA-Z_][a-zA-Z0-9_]*)>", replace_param, path_pattern) + "$"
        compiled = re.compile(regex_pattern)
        self.routes.append((method.upper(), compiled, param_names, handler))

    def get(self, path: str):
        def decorator(handler: Callable[..., Response]):
            self.add("GET", path, handler)
            return handler
        return decorator

    def post(self, path: str):
        def decorator(handler: Callable[..., Response]):
            self.add("POST", path, handler)
            return handler
        return decorator

    def delete(self, path: str):
        def decorator(handler: Callable[..., Response]):
            self.add("DELETE", path, handler)
            return handler
        return decorator

    def dispatch(self, req: Request) -> Optional[Response]:
        for method, pattern, param_names, handler in self.routes:
            if method != req.method:
                continue
            m = pattern.match(req.path)
            if m:
                extracted_args = m.groups()
                kwargs = {param_names[i]: urllib.parse.unquote(extracted_args[i]) for i in range(len(param_names))}
                try:
                    return handler(req, **kwargs)
                except Exception as e:
                    import logging
                    logging.getLogger("traceforge.web").exception("Unhandled error in route handler: %s", req.path)
                    return Response.error(f"Internal server error: {str(e)}", status_code=500)
        return None
