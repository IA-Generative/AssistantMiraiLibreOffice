"""HTTP, proxy, and model-catalog helpers shared by MIrAI components."""

import json
import urllib.parse
import urllib.request


def as_bool(value):
    """Parse common config values into a strict boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(value, (int, float)):
        return value != 0
    return False


def normalize_proxy_url(proxy_url):
    """Return a normalized proxy URL with scheme and optional port."""
    proxy_url = (proxy_url or "").strip()
    if not proxy_url:
        return ""
    if "://" not in proxy_url:
        proxy_url = "http://" + proxy_url
    try:
        parsed = urllib.parse.urlparse(proxy_url)
        host = parsed.hostname or ""
        port = parsed.port
        if not host:
            return ""
        if port:
            return f"{parsed.scheme}://{host}:{port}"
        return f"{parsed.scheme}://{host}"
    except Exception:
        return proxy_url


def build_proxy_opener(proxy_cfg, context=None, log_func=None):
    """Build a urllib opener with optional proxy and proxy auth."""
    log = log_func or (lambda _message: None)
    handlers = []

    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))

    if not proxy_cfg.get("enabled"):
        log("[PROXY] disabled")
        return urllib.request.build_opener(*handlers)

    proxy_url = normalize_proxy_url(proxy_cfg.get("proxy_url", ""))
    if not proxy_url:
        log("[PROXY] enabled but proxy_url is empty/invalid")
        return urllib.request.build_opener(*handlers)

    username = str(proxy_cfg.get("username", "") or "")
    password = str(proxy_cfg.get("password", "") or "")
    proxy_url_for_handler = proxy_url

    if username and password:
        try:
            parsed = urllib.parse.urlparse(proxy_url)
            host = parsed.hostname or ""
            port = f":{parsed.port}" if parsed.port else ""
            proxy_url_for_handler = f"{parsed.scheme}://{username}:{password}@{host}{port}"
        except Exception:
            proxy_url_for_handler = proxy_url

    proxy_map = {"http": proxy_url_for_handler, "https": proxy_url_for_handler}
    handlers.append(urllib.request.ProxyHandler(proxy_map))

    if username and password:
        try:
            pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            pwd_mgr.add_password(None, proxy_url, username, password)
            handlers.append(urllib.request.ProxyBasicAuthHandler(pwd_mgr))
            handlers.append(urllib.request.ProxyDigestAuthHandler(pwd_mgr))
            log("[PROXY] auth enabled (username+password)")
        except Exception:
            pass
    else:
        log("[PROXY] auth disabled (empty username or password)")

    log(f"[PROXY] using {proxy_url}")
    return urllib.request.build_opener(*handlers)


def split_endpoint_api_path(endpoint, is_openwebui):
    """Return (endpoint_base, api_path) for OpenAI-compatible backends."""
    endpoint = (endpoint or "").rstrip("/")
    if endpoint.endswith("/api") or endpoint.endswith("/v1"):
        return endpoint, ""
    api_path = "/api" if is_openwebui else "/v1"
    return endpoint, api_path


def build_auth_headers(
    api_key,
    auth_header_name="Authorization",
    auth_header_prefix="Bearer ",
):
    """Build standard JSON plus optional auth headers for API calls."""
    header_name = str(auth_header_name or "Authorization").strip() or "Authorization"
    header_prefix = str(auth_header_prefix or "Bearer ").strip()
    if header_prefix and not header_prefix.endswith(" "):
        header_prefix += " "

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers[header_name] = f"{header_prefix}{api_key}"
    return headers


def _extract_models(data, include_info=False):
    models = []
    descriptions = {}

    def _add_model(item):
        if not isinstance(item, dict):
            return
        model_id = item.get("id") or item.get("model") or item.get("name")
        if not model_id:
            return
        model_id = str(model_id)
        models.append(model_id)
        if include_info:
            info = item.get("info") or {}
            meta = info.get("meta") or {}
            description = (
                meta.get("description")
                or info.get("description")
                or item.get("description")
                or item.get("summary")
                or item.get("name")
                or item.get("owned_by")
            )
            if description:
                descriptions[model_id] = str(description)

    items = []
    if isinstance(data, dict):
        items = data.get("data") or data.get("models") or []
    elif isinstance(data, list):
        items = data

    for item in items:
        if isinstance(item, str) and not include_info:
            models.append(item)
        else:
            _add_model(item)

    return (models, descriptions) if include_info else models


def fetch_models(
    endpoint,
    api_key,
    is_openwebui,
    *,
    urlopen,
    ssl_context=None,
    auth_header_name="Authorization",
    auth_header_prefix="Bearer ",
    with_user_agent=None,
    log_func=None,
    curl_headers_for_log=None,
    include_info=False,
):
    """Fetch a model catalog from an OpenAI-compatible endpoint."""
    log = log_func or (lambda _message: None)
    endpoint, api_path = split_endpoint_api_path(endpoint, is_openwebui)
    url = endpoint + api_path + "/models" if api_path else endpoint + "/models"
    headers = build_auth_headers(
        api_key,
        auth_header_name=auth_header_name,
        auth_header_prefix=auth_header_prefix,
    )

    try:
        if curl_headers_for_log is not None:
            log(f"Models fetch curl: curl -i {curl_headers_for_log(headers)} '{url}'")
    except Exception:
        pass

    request_headers = with_user_agent(headers) if with_user_agent else headers

    try:
        request = urllib.request.Request(url, headers=request_headers)
        with urlopen(request, context=ssl_context, timeout=10) as response:
            payload = response.read().decode("utf-8")
        data = json.loads(payload)
    except Exception as exc:
        log(f"Failed to fetch models: {str(exc)}")
        return ([], {}) if include_info else []

    if include_info:
        log(f"Models API raw response: {payload[:2000]}")

    return _extract_models(data, include_info=include_info)
