"""HTTP client abstraction for proxy/SSL-aware requests."""

import base64
import json
import os
import ssl
import urllib.error
import urllib.request

from .http_helpers import as_bool, build_proxy_opener

try:
    import uno
except ImportError:
    uno = None


class HttpClient:
    """Thin adapter around urllib with MIrAI proxy and CA rules."""

    def __init__(
        self,
        *,
        config_getter,
        proxy_config_getter,
        user_config_dir_getter,
        relay_headers_getter=None,
        with_user_agent=None,
        log_fn=None,
        base_dir=None,
    ):
        self._config_getter = config_getter
        self._proxy_config_getter = proxy_config_getter
        self._user_config_dir_getter = user_config_dir_getter
        self._relay_headers_getter = relay_headers_getter or (lambda: {})
        self._with_user_agent = with_user_agent or (lambda headers=None: dict(headers or {}))
        self._log = log_fn or (lambda _message: None)
        self._base_dir = base_dir or os.getcwd()
        self._last_loaded_ca_bundle = None
        self._last_ca_bundle_error = None
        self._last_logged_ca_bundle_error = None

    def _config(self, key, default=None):
        return self._config_getter(key, default)

    def build_proxy_opener(self, proxy_cfg, context=None):
        return build_proxy_opener(proxy_cfg, context=context, log_func=self._log)

    def get_ssl_context(self):
        """Create an SSL context with bundled/user CA support."""
        allow_insecure = as_bool(self._config("proxy_allow_insecure_ssl", False))
        ssl_context = ssl.create_default_context()
        if allow_insecure:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            return ssl_context

        loaded_bundle = None
        configured_bundle = str(self._config("ca_bundle_path", "") or "").strip()
        candidate_paths = []
        if configured_bundle:
            if configured_bundle.startswith("file://") and uno is not None:
                try:
                    configured_bundle = str(uno.fileUrlToSystemPath(configured_bundle))
                except Exception:
                    pass
            if os.path.isabs(configured_bundle):
                candidate_paths.append(configured_bundle)
            else:
                candidate_paths.append(os.path.join(self._user_config_dir_getter(), configured_bundle))
                candidate_paths.append(os.path.join(self._base_dir, configured_bundle))

        candidate_paths.append(
            os.path.join(self._base_dir, "CAbundle", "scaleway-bootstrap-ca-chain.pem")
        )

        seen = set()
        for path in candidate_paths:
            candidate = str(path or "").strip()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            if not os.path.isfile(candidate):
                continue
            try:
                ssl_context.load_verify_locations(cafile=candidate)
                loaded_bundle = candidate
                break
            except Exception as exc:
                self._last_ca_bundle_error = str(exc)

        if loaded_bundle and loaded_bundle != self._last_loaded_ca_bundle:
            self._last_loaded_ca_bundle = loaded_bundle
            self._last_ca_bundle_error = None
            self._last_logged_ca_bundle_error = None
            self._log(f"SSL CA bundle loaded: {loaded_bundle}")
        elif not loaded_bundle and self._last_ca_bundle_error:
            if self._last_ca_bundle_error != self._last_logged_ca_bundle_error:
                self._log(f"SSL CA bundle load failed: {self._last_ca_bundle_error}")
                self._last_logged_ca_bundle_error = self._last_ca_bundle_error

        return ssl_context

    def urlopen(self, request, *, context=None, timeout=None, use_proxy=True):
        try:
            req_url = str(getattr(request, "full_url", "") or "")
            if "/relay-assistant/" in req_url:
                for header_name, header_value in self._relay_headers_getter().items():
                    try:
                        request.add_header(header_name, header_value)
                    except Exception:
                        pass
        except Exception:
            pass

        proxy_cfg = self._proxy_config_getter() if use_proxy else {
            "enabled": False,
            "proxy_url": "",
            "username": "",
            "password": "",
            "allow_insecure_ssl": False,
        }
        allow_insecure = bool(proxy_cfg.get("allow_insecure_ssl"))

        try:
            url = request.full_url if hasattr(request, "full_url") else str(request)
        except Exception:
            url = "<unknown>"

        if proxy_cfg.get("enabled"):
            username = proxy_cfg.get("username", "")
            password = proxy_cfg.get("password", "")
            if username and password:
                try:
                    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                    if not request.has_header("Proxy-Authorization"):
                        request.add_header("Proxy-Authorization", f"Basic {token}")
                except Exception:
                    pass

        if context is None:
            context = self.get_ssl_context()
        opener = self.build_proxy_opener(proxy_cfg, context=context)
        self._log(
            f"[PROXY] request url={url} enabled={proxy_cfg.get('enabled')} "
            f"insecure_ssl={allow_insecure} use_proxy={use_proxy}"
        )
        if timeout is None:
            return opener.open(request)
        return opener.open(request, timeout=timeout)

    def _call(self, method, request, timeout=10, use_proxy=True):
        request.get_method = lambda: str(method or "GET").upper()
        try:
            with self.urlopen(request, timeout=timeout, use_proxy=use_proxy) as response:
                payload = response.read()
                status = int(getattr(response, "status", 0) or 0)
                headers = dict(response.headers.items()) if hasattr(response, "headers") else {}
                return status, headers, payload
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read()
            except Exception:
                payload = b""
            headers = dict(exc.headers.items()) if hasattr(exc, "headers") and exc.headers else {}
            return int(exc.code), headers, payload

    def get(self, url, headers=None, timeout=10, use_proxy=True):
        request = urllib.request.Request(url, headers=self._with_user_agent(headers or {}))
        return self._call("GET", request, timeout=timeout, use_proxy=use_proxy)

    def post_json(self, url, payload, headers=None, timeout=10, use_proxy=True):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request_headers = {"Content-Type": "application/json"}
        request_headers.update(headers or {})
        request = urllib.request.Request(
            url,
            data=data,
            headers=self._with_user_agent(request_headers),
        )
        return self._call("POST", request, timeout=timeout, use_proxy=use_proxy)
