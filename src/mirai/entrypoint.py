import sys
import unohelper
import officehelper
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
from com.sun.star.task import XJobExecutor
from com.sun.star.awt import MessageBoxButtons as MSG_BUTTONS
from com.sun.star.awt import XActionListener, XItemListener, XMouseListener, XWindowListener, XTopWindowListener
import uno
import os 
import logging
import re
import uuid
import time
import base64
import hashlib
import threading
import socket

from com.sun.star.beans import PropertyValue
from com.sun.star.container import XNamed
from .menu_actions.writer import handle_writer_action
from .menu_actions.calc import handle_calc_action
from .security_flow import (
    SecureBootstrapFlow,
    FileJsonStore,
    FileQueueStore,
    default_vault,
    Ed25519Provider,
)


USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/120.0"

# Configure logging once at module level (thread-safe, not per-call)
_log_file_path = os.path.join(os.path.expanduser('~'), 'log.txt')
logging.basicConfig(filename=_log_file_path, level=logging.INFO, format='%(asctime)s - %(message)s')

def _with_user_agent(headers=None):
    result = dict(headers) if headers else {}
    if "User-Agent" not in result:
        result["User-Agent"] = USER_AGENT
    return result

def _redact_header_value(name, value):
    key = str(name or "").strip().lower()
    if key in ("authorization", "x-api-key", "api-key", "proxy-authorization", "x-relay-key"):
        return "<redacted>"
    return value

def _redacted_headers(headers):
    safe = {}
    for key, value in (headers or {}).items():
        safe[key] = _redact_header_value(key, value)
    return safe

def _curl_headers_for_log(headers):
    parts = []
    for key, value in (headers or {}).items():
        safe_value = _redact_header_value(key, value)
        parts.append(f"-H '{key}: {safe_value}'")
    return " ".join(parts)

def log_to_file(message):
    logging.info(message)


def generate_trace_id():
    """Generate a random 16-byte trace ID in hexadecimal format."""
    return uuid.uuid4().hex[:32]


def generate_span_id():
    """Generate a random 8-byte span ID in hexadecimal format."""
    return uuid.uuid4().hex[:16]


def send_telemetry_trace_async(config, span_name, attributes=None):
    """
    Send OpenTelemetry trace asynchronously in a separate thread.
    This function returns immediately and does not block the extension execution.
    
    Args:
        config: Configuration object with telemetry settings
        span_name: Name of the span (e.g., "ExtendSelection", "EditSelection")
        attributes: Optional dictionary of additional attributes
    """
    thread = threading.Thread(
        target=_send_telemetry_trace_impl,
        args=(config, span_name, attributes),
        daemon=True  # Daemon thread won't prevent the program from exiting
    )
    thread.start()
    log_to_file(f"Telemetry trace '{span_name}' scheduled asynchronously")


def _send_telemetry_trace_impl(config, span_name, attributes=None):
    """
    Internal implementation of telemetry trace sending.
    This runs in a separate thread to avoid blocking the extension.
    
    Args:
        config: MainJob object with get_config() method
        span_name: Name of the span (e.g., "ExtendSelection", "EditSelection")
        attributes: Optional dictionary of additional attributes
    """
    endpoint = "unknown"  # Initialize endpoint for error handling
    try:
        telemetry_enabled = config.get_config("telemetryEnabled", True)
        if not telemetry_enabled:
            log_to_file("Telemetry disabled, skipping trace")
            return
        
        endpoint = config.get_config("telemetryEndpoint", None)
        auth_type = config.get_config("telemetryAuthorizationType", None)
        auth_key = config.get_config("telemetryKey", None)
        log_json = config.get_config("telemetrylogJson", None)
        
        # Generate or retrieve extension UUID
        extension_uuid = config.get_config("extensionUUID", "")
        if not extension_uuid:
            extension_uuid = str(uuid.uuid4())
            config.set_config("extensionUUID", extension_uuid)
            log_to_file(f"Generated new extension UUID: {extension_uuid}")
        
        # Generate trace and span IDs
        trace_id = generate_trace_id()
        span_id = generate_span_id()
        
        # Get current timestamp in nanoseconds
        timestamp_ns = int(time.time() * 1e9)
        
        # Build span attributes
        span_attributes = {
            "extension.uuid": extension_uuid,
            "extension.name": "mirai",
            "extension.version": "1.0.0"
        }
        
        if attributes:
            span_attributes.update(attributes)
        
        # Convert attributes to OpenTelemetry format
        otel_attributes = []
        for key, value in span_attributes.items():
            otel_attributes.append({
                "key": key,
                "value": {"stringValue": str(value)}
            })
        
        # Build OpenTelemetry JSON payload
        payload = {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "mirai-libreoffice"}},
                            {"key": "service.version", "value": {"stringValue": "1.0.0"}},
                            {"key": "extension.uuid", "value": {"stringValue": extension_uuid}}
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {
                                "name": "mirai-extension",
                                "version": "1.0.0"
                            },
                            "spans": [
                                {
                                    "traceId": trace_id,
                                    "spanId": span_id,
                                    "name": span_name,
                                    "kind": 1,  # SPAN_KIND_INTERNAL
                                    "startTimeUnixNano": str(timestamp_ns),
                                    "endTimeUnixNano": str(timestamp_ns + 1000000),  # Add 1ms duration
                                    "attributes": otel_attributes,
                                    "status": {"code": 1}  # STATUS_CODE_OK
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        # Preferred secure telemetry pipeline (bootstrap/enroll/token rotation + offline queue).
        if hasattr(config, "_secure_send_telemetry_payload"):
            try:
                handled = bool(config._secure_send_telemetry_payload(payload, span_name))
                if handled:
                    return
            except Exception as e:
                log_to_file(f"Secure telemetry pipeline unavailable, fallback legacy sender: {str(e)}")
        
        if log_json:
            log_to_file(f"=== Telemetry Request ===")
            log_to_file(f"URL: {endpoint}")
            log_to_file(f"Method: POST")
            log_to_file(f"Span Name: {span_name}")
            log_to_file(f"Trace ID: {trace_id}")
            log_to_file(f"Span ID: {span_id}")
            log_to_file(f"Payload: {json.dumps(payload, indent=2)}")
        
        # Send the request
        json_data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(endpoint, data=json_data, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', USER_AGENT)
        
        # Add authentication header
        if auth_key:
            if auth_type == "Basic":
                req.add_header('Authorization', f'Basic {auth_key}')
            elif auth_type == "Bearer":
                req.add_header('Authorization', f'Bearer {auth_key}')
        
        # Log request headers
        if log_json:
            log_to_file(f"=== Request Headers ===")
            for header_name, header_value in req.headers.items():
                if header_name.lower() == 'authorization':
                    log_to_file(f"{header_name}: <redacted>")
                else:
                    log_to_file(f"{header_name}: {header_value}")
            log_to_file(f"Content-Length: {len(json_data)}")
            log_to_file(f"===")
        
        ssl_context = config.get_ssl_context() if hasattr(config, "get_ssl_context") else ssl.create_default_context()

        if hasattr(config, "_urlopen"):
            response = config._urlopen(req, context=ssl_context, timeout=5)
        else:
            response = urllib.request.urlopen(req, context=ssl_context, timeout=5)
        with response as response:
            response_status = response.status
            response_headers = dict(response.headers)
            response_body = response.read().decode('utf-8') if response.readable() else ""
            
            if log_json:
                log_to_file(f"=== Telemetry Response ===")
                log_to_file(f"Status: {response_status}")
                log_to_file(f"Headers: {json.dumps(response_headers, indent=2)}")
                log_to_file(f"Body: {response_body if response_body else '(empty)'}")
                log_to_file(f"=== End Telemetry Response ===")
            
            log_to_file(f"Telemetry trace sent successfully: {span_name}, status: {response_status}")
            
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if hasattr(e, 'read') else ""
        log_to_file(f"=== Telemetry HTTP Error ===")
        log_to_file(f"URL: {endpoint}")
        log_to_file(f"Status: {e.code}")
        log_to_file(f"Reason: {e.reason}")
        log_to_file(f"Headers: {dict(e.headers) if hasattr(e, 'headers') else 'N/A'}")
        log_to_file(f"Body: {error_body if error_body else '(empty)'}")
        log_to_file(f"=== End Telemetry Error ===")
    except Exception as e:
        log_to_file(f"=== Telemetry Exception ===")
        log_to_file(f"URL: {endpoint}")
        log_to_file(f"Error: {str(e)}")
        log_to_file(f"Type: {type(e).__name__}")
        log_to_file(f"=== End Telemetry Exception ===")


# The MainJob is a UNO component derived from unohelper.Base class
# and also the XJobExecutor, the implemented interface
class MainJob(unohelper.Base, XJobExecutor):
    def __init__(self, ctx):
        log_to_file("=== MainJob.__init__ called ===")
        self.ctx = ctx
        self.config_cache = None
        self.config_loaded_at = 0
        self.config_ttl = 300
        self._config_last_failure_at = 0
        self._config_failure_backoff = 30
        self._models_cache = None
        self._models_cache_key = None
        self._models_cache_loaded_at = 0
        self._models_cache_ttl = 60
        self._fetching_config = False
        self._config_refresh_lock = threading.RLock()
        self._config_refresh_in_progress = False
        self._config_refresh_last_started_at = 0
        self._config_async_min_interval = 20
        self._auth_prompt_lock = threading.Lock()
        self._auth_prompt_in_progress = False
        self._auth_prompted_at = 0
        self._config_write_lock = threading.Lock()
        self._edit_dialog = None
        self._secure_flow = None
        self._secure_flow_lock = threading.RLock()
        self._secure_flow_init_error = None
        self._secure_legacy_fallback_logged = False
        self._last_loaded_ca_bundle = None
        self._last_ca_bundle_error = None
        self._last_logged_ca_bundle_error = None
        # handling different situations (inside LibreOffice or other process)
        try:
            self.sm = ctx.getServiceManager()
            self.desktop = XSCRIPTCONTEXT.getDesktop()
            self.document = XSCRIPTCONTEXT.getDocument()
            log_to_file("MainJob initialized with XSCRIPTCONTEXT")
        except NameError:
            self.sm = ctx.ServiceManager
            self.desktop = self.ctx.getServiceManager().createInstanceWithContext(
                "com.sun.star.frame.Desktop", self.ctx)
            log_to_file("MainJob initialized without XSCRIPTCONTEXT")

        try:
            path_settings = self.sm.createInstanceWithContext('com.sun.star.util.PathSettings', self.ctx)
            user_config_path = getattr(path_settings, "UserConfig")
            if user_config_path.startswith('file://'):
                user_config_path = str(uno.fileUrlToSystemPath(user_config_path))
            config_file_path = os.path.join(user_config_path, "config.json")
            log_to_file(f"Profile config path: {config_file_path}")
        except Exception as e:
            log_to_file(f"Failed to resolve profile config path: {str(e)}")
        
        # Send telemetry trace on extension load
        try:
            self._ensure_extension_uuid()
            self._ensure_plugin_uuid()
            self._warmup_secure_flow_async()
            send_telemetry_trace_async(self, "ExtensionLoaded", {
                "event.type": "extension_loaded",
                "extension.context": "libreoffice_writer"
            })
        except Exception as e:
            log_to_file(f"Failed to send extension load telemetry: {str(e)}")

        try:
            self._ensure_device_management_state_async()
        except Exception as e:
            log_to_file(f"Failed to initialize device management: {str(e)}")

        try:
            self._check_proxy_consistency()
        except Exception as e:
            log_to_file(f"Failed to check proxy consistency: {str(e)}")
    
    def _log(self, message):
        log_to_file(message)

    def _send_telemetry(self, span_name, attributes=None):
        send_telemetry_trace_async(self, span_name, attributes)

    def _get_user_config_dir(self):
        path_settings = self.sm.createInstanceWithContext('com.sun.star.util.PathSettings', self.ctx)
        user_config_path = getattr(path_settings, "UserConfig")
        if user_config_path.startswith('file://'):
            user_config_path = str(uno.fileUrlToSystemPath(user_config_path))
        return user_config_path

    def _ensure_extension_uuid(self):
        """Ensure extension has a unique UUID, generate if missing."""
        extension_uuid = self.get_config("extensionUUID", "")
        if not extension_uuid:
            extension_uuid = str(uuid.uuid4())
            self.set_config("extensionUUID", extension_uuid)
            log_to_file(f"Generated new extension UUID: {extension_uuid}")
        return extension_uuid

    def _ensure_plugin_uuid(self):
        plugin_uuid = str(self._get_config_from_file("plugin_uuid", "") or "").strip()
        if plugin_uuid:
            return plugin_uuid
        extension_uuid = str(self._get_config_from_file("extensionUUID", "") or "").strip()
        if not extension_uuid:
            extension_uuid = str(uuid.uuid4())
            self.set_config("extensionUUID", extension_uuid)
        self.set_config("plugin_uuid", extension_uuid)
        return extension_uuid

    def _secure_http_call(self, method, url, headers=None, body=None, timeout=10, use_proxy=True):
        request = urllib.request.Request(url, data=body, headers=_with_user_agent(headers or {}))
        request.get_method = lambda: str(method or "GET").upper()
        try:
            with self._urlopen(request, context=self.get_ssl_context(), timeout=timeout, use_proxy=use_proxy) as response:
                payload = response.read()
                status = int(getattr(response, "status", 0) or 0)
                response_headers = dict(response.headers.items()) if hasattr(response, "headers") else {}
                return status, response_headers, payload
        except urllib.error.HTTPError as exc:
            try:
                payload = exc.read()
            except Exception:
                payload = b""
            response_headers = dict(exc.headers.items()) if hasattr(exc, "headers") and exc.headers else {}
            return int(exc.code), response_headers, payload

    def _get_secure_flow(self):
        with self._secure_flow_lock:
            if self._secure_flow is not None:
                return self._secure_flow
            if self._secure_flow_init_error:
                return None
            bootstrap_url = str(self._get_config_from_file("bootstrap_url", "") or "").strip()
            if not bootstrap_url:
                return None
            plugin_uuid = self._ensure_plugin_uuid()
            device_name = str(self._get_config_from_file("device_name", "mirai-libreoffice") or "").strip() or "mirai-libreoffice"
            user_config_dir = self._get_user_config_dir()
            state_path = os.path.join(user_config_dir, "secure_bootstrap_state.json")
            queue_path = os.path.join(user_config_dir, "telemetry_queue.json")
            try:
                flow = SecureBootstrapFlow(
                    bootstrap_base_url=bootstrap_url.rstrip("/"),
                    plugin_uuid=plugin_uuid,
                    device_name=device_name,
                    http_call=self._secure_http_call,
                    log_func=lambda m: log_to_file(m),
                    state_store=FileJsonStore(state_path),
                    queue_store=FileQueueStore(queue_path),
                    vault=default_vault(),
                    signer=Ed25519Provider(),
                )
            except Exception as exc:
                log_to_file(f"Secure flow init failed: {str(exc)}")
                self._secure_flow_init_error = str(exc)
                return None
            self._secure_flow = flow
            return flow

    def _warmup_secure_flow_async(self):
        def _worker():
            try:
                flow = self._get_secure_flow()
                if not flow:
                    return
                flow.ensure_identity()
                try:
                    flow.fetch_bootstrap_config()
                except Exception as exc:
                    log_to_file(f"Secure flow bootstrap fetch failed: {str(exc)}")
            except Exception as exc:
                log_to_file(f"Secure flow warmup failed: {str(exc)}")

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()

    def _secure_send_telemetry_payload(self, payload, _span_name=None):
        flow = self._get_secure_flow()
        if not flow:
            bootstrap_url = str(self._get_config_from_file("bootstrap_url", "") or "").strip()
            if bootstrap_url:
                if not self._secure_legacy_fallback_logged:
                    self._secure_legacy_fallback_logged = True
                    log_to_file("Secure telemetry unavailable; fallback to legacy sender")
                return False
            return False
        try:
            current_kind = flow.telemetry_kind()
            access_token = str(self._get_config_from_file("access_token", "") or "").strip()
            has_valid_login = bool(access_token) and (not self._token_is_expired(access_token))
            if current_kind != "user":
                technical_events = {
                    "ExtensionLoaded",
                    "OpenSettings",
                    "OpenmiraiWebsite",
                    "OpenWebsite",
                    "ReloadConfig",
                    "ProxyCheck",
                    "ProxyTest",
                }
                if not has_valid_login:
                    return True
                if _span_name and _span_name not in technical_events:
                    return True
            handled = bool(flow.send_trace(payload))
            if flow.rebind_required():
                if access_token and not self._token_is_expired(access_token):
                    self._secure_bind_identity(access_token)
                else:
                    log_to_file("Secure telemetry requires user rebind/login")
            return handled
        except Exception as exc:
            log_to_file(f"Secure telemetry pipeline failure: {str(exc)}")
            return True

    def _secure_bind_identity(self, access_token):
        flow = self._get_secure_flow()
        if not flow:
            return ""
        try:
            return flow.bind_identity(access_token)
        except Exception as exc:
            log_to_file(f"Secure identity bind failed: {str(exc)}")
            return ""
    
    def _decode_default_key(self):
        """
        Decode the default telemetry key using base64 decoding.
        The key is stored in an obfuscated format and decoded at runtime.
        """
        # Obfuscated key - reversed string then base64 encoded
        obfuscated = "PT13WXBKWFp0UTNjbFJuT2psbWNsMUNkelZHZA=="
        try:
            # Decode the obfuscated string
            decoded = base64.b64decode(obfuscated).decode('utf-8')
            # Reverse the string to get the original key
            return decoded[::-1]
        except Exception as e:
            log_to_file(f"Error decoding telemetry key: {str(e)}")
            return ""
    
    def _get_telemetry_defaults(self):
        """Return default values for telemetry configuration."""
        return {
            "telemetryEnabled": True,
            "telemetryEndpoint": "https://traces.cpin.numerique-interieur.com/v1/traces",
            "telemetrySel": "mirai_salt",
            "telemetryAuthorizationType": "Basic",
            "telemetryKey": self._decode_default_key(),
            "telemetryHost": "",
            "telemetrylogJson": False,
            "telemetryFormatProtobuf": False
        }

    def _get_config_from_file(self, key, default, telemetry_defaults=None):
        name_file = "config.json"
        package_file = "config.default.json"
        path_settings = self.sm.createInstanceWithContext('com.sun.star.util.PathSettings', self.ctx)

        user_config_path = getattr(path_settings, "UserConfig")

        if user_config_path.startswith('file://'):
            user_config_path = str(uno.fileUrlToSystemPath(user_config_path))

        # Ensure the path ends with the filename
        config_file_path = os.path.join(user_config_path, name_file)

        user_config_data = None
        package_config_data = None

        # Load user config (if present)
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r', encoding='utf-8') as file:
                    user_config_data = json.load(file)
            except (IOError, json.JSONDecodeError):
                user_config_data = None
        else:
            log_to_file(f"Config file not found in user profile: {config_file_path}")

        # Load packaged config.default.json (inside extension)
        package_config_candidates = [
            os.path.join(os.path.dirname(__file__), package_file),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', package_file)),
        ]
        for package_config_path in package_config_candidates:
            if os.path.exists(package_config_path):
                try:
                    with open(package_config_path, 'r', encoding='utf-8') as file:
                        package_config_data = json.load(file)
                    break
                except (IOError, json.JSONDecodeError):
                    package_config_data = None

        # If user config missing or invalid, initialize from package defaults
        if not isinstance(user_config_data, dict) or not user_config_data:
            if isinstance(package_config_data, dict) and package_config_data:
                try:
                    with open(config_file_path, 'w', encoding='utf-8') as file:
                        json.dump(package_config_data, file, indent=4, ensure_ascii=False)
                    user_config_data = dict(package_config_data)
                    log_to_file(f"Config initialized from package defaults: {config_file_path}")
                except Exception:
                    user_config_data = None

        # Merge: packaged defaults overridden by user config
        config_data = {}
        if isinstance(package_config_data, dict):
            config_data.update(package_config_data)
        if isinstance(user_config_data, dict):
            config_data.update(user_config_data)

        # Debug: log where token is read from (masked)
        if key == "llm_api_tokens":
            try:
                raw_value = config_data.get(key, default)
                masked = ""
                if raw_value:
                    text = str(raw_value)
                    masked = text[:2] + "***" + text[-2:] if len(text) > 4 else "*" * len(text)
                log_to_file(
                    "Config read llm_api_tokens "
                    f"path={config_file_path} "
                    f"user_present={bool(user_config_data)} "
                    f"package_present={bool(package_config_data)} "
                    f"value={masked}"
                )
            except Exception:
                pass

        # Upgrade user config if package has higher configVersion
        pkg_version = None
        user_version = None
        try:
            pkg_version = int(config_data.get("configVersion")) if "configVersion" in config_data else None
        except Exception:
            pkg_version = None
        try:
            user_version = int(user_config_data.get("configVersion")) if isinstance(user_config_data, dict) and "configVersion" in user_config_data else None
        except Exception:
            user_version = None
        if pkg_version is not None and (user_version is None or user_version < pkg_version):
            try:
                merged = {}
                if isinstance(package_config_data, dict):
                    merged.update(package_config_data)
                if isinstance(user_config_data, dict):
                    merged.update(user_config_data)
                merged["configVersion"] = pkg_version
                with open(config_file_path, 'w') as file:
                    json.dump(merged, file, indent=4)
                config_data = merged
                log_to_file(f"Config upgraded to version {pkg_version}: {config_file_path}")
            except Exception:
                pass

        if not config_data:
            return default

        # Get the value from config file
        value = config_data.get(key, default)

        # If telemetry key is empty string and we have a default from telemetry_defaults, use it
        if telemetry_defaults and key == "telemetryKey" and (value == "" or value is None) and key in telemetry_defaults:
            return telemetry_defaults[key]

        return value

    def _device_management_enabled(self):
        return self._as_bool(self._get_config_from_file("enabled", False))

    def _select_settings(self, config_data):
        if not isinstance(config_data, dict):
            return None
        for candidate in ("config", "settings", "parameters", "mirai", "mirai_config", "miraiConfig"):
            value = config_data.get(candidate)
            if isinstance(value, dict):
                return value
        return None

    def _schedule_config_refresh(self, force=False, reason="background"):
        if not self._device_management_enabled():
            return False
        now = time.time()
        with self._config_refresh_lock:
            if self._config_refresh_in_progress:
                return False
            if not force and (now - self._config_refresh_last_started_at) < self._config_async_min_interval:
                return False
            self._config_refresh_in_progress = True
            self._config_refresh_last_started_at = now

        def _worker():
            try:
                self._fetch_config(force=force)
            except Exception as exc:
                log_to_file(f"DM config async refresh failed ({reason}): {str(exc)}")
            finally:
                with self._config_refresh_lock:
                    self._config_refresh_in_progress = False

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def _fetch_config(self, force=False):
        if not force and not self._device_management_enabled():
            log_to_file("DM config fetch skipped: device management disabled")
            return None
        if self._fetching_config:
            log_to_file("DM config fetch skipped: recursion guard active")
            return None
        now = time.time()
        if self.config_cache and (now - self.config_loaded_at) < self.config_ttl:
            return self.config_cache
        if (
            not force
            and self._config_last_failure_at
            and (now - self._config_last_failure_at) < self._config_failure_backoff
        ):
            if self.config_cache:
                log_to_file("DM config fetch skipped: backoff active, using stale cache")
                return self.config_cache
            log_to_file("DM config fetch skipped: backoff active after recent failure")
            return None

        base_url = str(self._get_config_from_file("bootstrap_url", "")).strip()
        if not base_url:
            log_to_file("DM config fetch skipped: bootstrap_url is empty")
            return None
        config_path = str(self._get_config_from_file("config_path", "/config/config.json"))
        url = base_url.rstrip("/") + "/" + config_path.lstrip("/")
        log_to_file(f"DM bootstrap URL: {url}")

        self._fetching_config = True
        try:
            proxy_enabled = self._as_bool(self._get_config_from_file("proxy_enabled", False))
            attempts = [("direct", False)]
            if proxy_enabled:
                attempts.append(("proxy", True))
            else:
                log_to_file("DM config fetch: proxy disabled, skipping proxy retry")

            last_error = "unknown"
            for mode, use_proxy in attempts:
                try:
                    log_to_file(f"DM config fetch attempt: mode={mode} url={url}")
                    headers = {"Accept": "application/json"}
                    headers.update(self._relay_headers())
                    request = urllib.request.Request(url, headers=_with_user_agent(headers))
                    with self._urlopen(request, context=self.get_ssl_context(), timeout=10, use_proxy=use_proxy) as response:
                        payload = response.read().decode("utf-8")
                    log_to_file(f"DM bootstrap raw response ({mode}): {payload[:2000]}")
                    config_data = json.loads(payload)
                    if isinstance(config_data, dict):
                        self.config_cache = config_data
                        self.config_loaded_at = now
                        self._config_last_failure_at = 0
                        return config_data
                    last_error = f"Invalid JSON root type: {type(config_data).__name__}"
                    log_to_file(f"Failed to fetch device management config ({mode}): {last_error}")
                except urllib.error.HTTPError as e:
                    try:
                        body = e.read().decode("utf-8")
                    except Exception:
                        body = ""
                    last_error = f"HTTP {e.code} {e.reason}"
                    log_to_file(
                        f"Failed to fetch device management config ({mode}): "
                        f"HTTP {e.code} {e.reason} body={body[:500]}"
                    )
                except urllib.error.URLError as e:
                    last_error = f"URL error {e.reason}"
                    log_to_file(f"Failed to fetch device management config ({mode}): URL error {e.reason}")
                except Exception as e:
                    last_error = str(e)
                    log_to_file(f"Failed to fetch device management config ({mode}): {str(e)}")

            self._config_last_failure_at = now
            log_to_file(f"Failed to fetch device management config: all attempts failed ({last_error})")
        finally:
            self._fetching_config = False
        if self.config_cache:
            log_to_file("DM config fetch failed: using stale cache")
            return self.config_cache
        return None

    def _get_setting(self, key):
        now = time.time()
        cache_fresh = bool(self.config_cache and (now - self.config_loaded_at) < self.config_ttl)
        if not cache_fresh:
            self._schedule_config_refresh(force=not bool(self.config_cache), reason=f"get_setting:{key}")
        config_data = self.config_cache if isinstance(self.config_cache, dict) else None
        if not config_data:
            return None
        settings = self._select_settings(config_data)
        if isinstance(settings, dict) and key in settings:
            return settings.get(key)
        return None

    def get_config(self, key, default):
        # Check for telemetry defaults first
        telemetry_defaults = self._get_telemetry_defaults()
        if key in telemetry_defaults and default is None:
            default = telemetry_defaults[key]

        if key == "llm_base_urls":
            config_value = self._get_setting("llm_base_urls")
            if config_value is not None:
                if len(str(config_value)) >= 6:
                    return config_value
            return self._get_config_from_file("llm_base_urls", default, telemetry_defaults=telemetry_defaults)

        if key == "llm_api_tokens":
            config_value = self._get_setting("llm_api_tokens")
            if config_value is not None:
                if len(str(config_value)) >= 6:
                    return config_value
            return self._get_config_from_file("llm_api_tokens", default, telemetry_defaults=telemetry_defaults)

        if key == "llm_default_models":
            local_model = str(self._get_config_from_file("llm_default_models", "", telemetry_defaults=telemetry_defaults)).strip()
            config_model = self._get_setting("llm_default_models")
            config_model = str(config_model).strip() if config_model is not None else ""
            if config_model and len(config_model) < 6:
                config_model = ""

            endpoint = self.get_config("llm_base_urls", "http://127.0.0.1:5000")
            api_key = self.get_config("llm_api_tokens", "")
            is_openwebui = True
            if not is_openwebui:
                endpoint_lower = str(endpoint).lower()
                if "/api" in endpoint_lower and "/v1" not in endpoint_lower:
                    is_openwebui = True

            models = self._get_cached_models(str(endpoint), str(api_key), is_openwebui)

            if local_model:
                if not models or local_model in models:
                    log_to_file(f"Model selection (local): {local_model}")
                    return local_model
                log_to_file(f"Model not found in list (local): {local_model}")

            if config_model:
                if not models or config_model in models:
                    log_to_file(f"Model selection (dm): {config_model}")
                    return config_model
                log_to_file(f"Model not found in list (dm): {config_model}")

            if models:
                log_to_file(f"Model selection (fallback first): {models[0]}")
                return models[0]

            fallback = local_model or config_model or default
            if fallback:
                log_to_file(f"Model selection (fallback): {fallback}")
            return fallback

        config_value = self._get_setting(key)
        if config_value is not None:
            return config_value

        return self._get_config_from_file(key, default, telemetry_defaults=telemetry_defaults)

    def set_config(self, key, value):
        name_file = "config.json"

        path_settings = self.sm.createInstanceWithContext('com.sun.star.util.PathSettings', self.ctx)
        user_config_path = getattr(path_settings, "UserConfig")

        if user_config_path.startswith('file://'):
            user_config_path = str(uno.fileUrlToSystemPath(user_config_path))

        config_file_path = os.path.join(user_config_path, name_file)

        with self._config_write_lock:
            if os.path.exists(config_file_path):
                try:
                    with open(config_file_path, 'r', encoding='utf-8') as file:
                        config_data = json.load(file)
                except (IOError, json.JSONDecodeError):
                    config_data = {}
            else:
                config_data = {}

            config_data[key] = value
            if key == "llm_default_models":
                log_to_file(f"Model saved (local): {value}")

            try:
                with open(config_file_path, 'w', encoding='utf-8') as file:
                    json.dump(config_data, file, indent=4, ensure_ascii=False)
            except IOError as e:
                log_to_file(f"Error writing to {config_file_path}: {e}")

    def _jwt_payload(self, token):
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return {}
            payload = parts[1]
            padding = "=" * (-len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload + padding).decode("utf-8")
            return json.loads(decoded)
        except Exception:
            return {}

    def _token_is_expired(self, token, skew_seconds=60):
        payload = self._jwt_payload(token)
        exp = payload.get("exp")
        if not isinstance(exp, (int, float)):
            return False
        return time.time() >= (exp - skew_seconds)

    def _show_message(self, title, message):
        try:
            toolkit = self.ctx.getServiceManager().createInstanceWithContext(
                "com.sun.star.awt.Toolkit", self.ctx
            )
            frame = self.desktop.getCurrentFrame() if self.desktop else None
            window = frame.getContainerWindow() if frame else None
            if not window:
                return
            from com.sun.star.awt.MessageBoxType import MESSAGEBOX
            try:
                box = toolkit.createMessageBox(
                    window,
                    uno.createUnoStruct("com.sun.star.awt.Rectangle"),
                    MESSAGEBOX,
                    MSG_BUTTONS.BUTTONS_OK,
                    str(title),
                    str(message)
                )
            except Exception:
                box = toolkit.createMessageBox(
                    window,
                    MESSAGEBOX,
                    MSG_BUTTONS.BUTTONS_OK,
                    str(title),
                    str(message)
                )
            box.execute()
            box.dispose()
        except Exception as e:
            log_to_file(f"Failed to show message box: {str(e)}")

    def _confirm_message(self, title, message):
        try:
            toolkit = self.ctx.getServiceManager().createInstanceWithContext(
                "com.sun.star.awt.Toolkit", self.ctx
            )
            frame = self.desktop.getCurrentFrame() if self.desktop else None
            window = frame.getContainerWindow() if frame else None
            if not window:
                return False
            from com.sun.star.awt.MessageBoxType import MESSAGEBOX
            try:
                box = toolkit.createMessageBox(
                    window,
                    uno.createUnoStruct("com.sun.star.awt.Rectangle"),
                    MESSAGEBOX,
                    MSG_BUTTONS.BUTTONS_OK_CANCEL,
                    str(title),
                    str(message)
                )
            except Exception:
                box = toolkit.createMessageBox(
                    window,
                    MESSAGEBOX,
                    MSG_BUTTONS.BUTTONS_OK_CANCEL,
                    str(title),
                    str(message)
                )
            result = box.execute()
            box.dispose()
            return result == 1
        except Exception as e:
            log_to_file(f"Failed to show confirm box: {str(e)}")
        return False

    def _show_message_and_open_settings(self, title, message):
        try:
            toolkit = self.ctx.getServiceManager().createInstanceWithContext(
                "com.sun.star.awt.Toolkit", self.ctx
            )
            frame = self.desktop.getCurrentFrame() if self.desktop else None
            window = frame.getContainerWindow() if frame else None
            if not window:
                return
            from com.sun.star.awt.MessageBoxType import MESSAGEBOX
            try:
                box = toolkit.createMessageBox(
                    window,
                    uno.createUnoStruct("com.sun.star.awt.Rectangle"),
                    MESSAGEBOX,
                    MSG_BUTTONS.BUTTONS_OK_CANCEL,
                    str(title),
                    str(message)
                )
            except Exception:
                box = toolkit.createMessageBox(
                    window,
                    MESSAGEBOX,
                    MSG_BUTTONS.BUTTONS_OK_CANCEL,
                    str(title),
                    str(message)
                )
            result = box.execute()
            box.dispose()
            if result == 1:
                try:
                    self.settings_box("Settings")
                except Exception:
                    pass
        except Exception as e:
            log_to_file(f"Failed to show message box: {str(e)}")

    def _keycloak_config(self, config_data):
        if not isinstance(config_data, dict):
            return {}

        def _flat_keycloak(source):
            if not isinstance(source, dict):
                return None
            flat = {
                "issuerUrl": (
                    source.get("keycloakIssuerUrl")
                    or source.get("issuerUrl")
                    or source.get("issuerURL")
                    or source.get("issuer_url")
                    or source.get("keycloak_base_url")
                    or source.get("issuer")
                ),
                "realm": (
                    source.get("keycloakRealm")
                    or source.get("keycloak_realm")
                    or source.get("realm")
                ),
                "clientId": (
                    source.get("keycloakClientId")
                    or source.get("keycloak_client_id")
                    or source.get("clientId")
                    or source.get("client_id")
                ),
                "clientSecret": (
                    source.get("keycloak_client_secret")
                    or source.get("clientSecret")
                    or source.get("client_secret")
                ),
                "authorization_endpoint": (
                    source.get("authorization_endpoint")
                    or source.get("authorizationEndpoint")
                    or source.get("keycloakAuthorizationEndpoint")
                    or source.get("keycloak_authorization_endpoint")
                    or source.get("auth_endpoint")
                    or source.get("authEndpoint")
                    or source.get("auth_url")
                    or source.get("authUrl")
                    or source.get("auth")
                ),
                "token_endpoint": (
                    source.get("token_endpoint")
                    or source.get("tokenEndpoint")
                    or source.get("keycloakTokenEndpoint")
                    or source.get("keycloak_token_endpoint")
                    or source.get("token_url")
                    or source.get("tokenUrl")
                    or source.get("token")
                ),
                "userinfo_endpoint": (
                    source.get("userinfo_endpoint")
                    or source.get("userinfoEndpoint")
                    or source.get("keycloakUserinfoEndpoint")
                    or source.get("keycloak_userinfo_endpoint")
                    or source.get("user_info_endpoint")
                    or source.get("userInfoEndpoint")
                    or source.get("userinfo")
                ),
            }
            if any(v is not None and str(v).strip() for v in flat.values()):
                return flat
            return None

        settings = self._select_settings(config_data)
        if isinstance(settings, dict):
            if isinstance(settings.get("keycloak"), dict):
                return settings.get("keycloak")
            settings_endpoints = settings.get("endpoints", {})
            if isinstance(settings_endpoints, dict) and isinstance(settings_endpoints.get("keycloak"), dict):
                return settings_endpoints.get("keycloak")
            flat_settings = _flat_keycloak(settings)
            if flat_settings:
                return flat_settings

        endpoints = config_data.get("endpoints", {})
        if not isinstance(endpoints, dict):
            endpoints = {}
        keycloak = config_data.get("keycloak") or endpoints.get("keycloak") or {}
        if isinstance(keycloak, dict):
            return keycloak

        flat_top_level = _flat_keycloak(config_data)
        if flat_top_level:
            return flat_top_level
        return {}

    def _keycloak_endpoint(self, keycloak_config, *names):
        for name in names:
            value = keycloak_config.get(name)
            if value:
                return value
        return ""

    def _normalize_keycloak_realm_base(self, base_url, realm):
        base_url = (base_url or "").strip()
        if not base_url:
            return ""
        base = base_url.rstrip("/")
        if "/realms/" in base:
            return base
        if realm:
            realm_value = str(realm).strip().strip("/")
            if realm_value:
                return f"{base}/realms/{realm_value}"
        return base

    def _keycloak_endpoints(self, config_data):
        keycloak = self._keycloak_config(config_data)
        auth_endpoint = self._keycloak_endpoint(
            keycloak,
            "authorization_endpoint",
            "authorizationEndpoint",
            "auth_endpoint",
            "authEndpoint",
            "auth_url",
            "authUrl",
            "auth"
        )
        token_endpoint = self._keycloak_endpoint(
            keycloak,
            "token_endpoint",
            "tokenEndpoint",
            "token_url",
            "tokenUrl",
            "token"
        )
        if auth_endpoint and token_endpoint:
            return auth_endpoint, token_endpoint

        auth_endpoint = (
            self._get_config_from_file("keycloakAuthorizationEndpoint", "")
            or self._get_config_from_file("keycloak_authorization_endpoint", "")
            or self._get_config_from_file("authorization_endpoint", "")
            or self._get_config_from_file("authorizationEndpoint", "")
        )
        token_endpoint = (
            self._get_config_from_file("keycloakTokenEndpoint", "")
            or self._get_config_from_file("keycloak_token_endpoint", "")
            or self._get_config_from_file("token_endpoint", "")
            or self._get_config_from_file("tokenEndpoint", "")
        )
        if auth_endpoint and token_endpoint:
            return auth_endpoint, token_endpoint

        base_url = self._get_config_from_file("keycloakIssuerUrl", "") or self._get_config_from_file("keycloak_base_url", "")
        realm = self._get_config_from_file("keycloakRealm", "") or self._get_config_from_file("keycloak_realm", "")
        realm_base = self._normalize_keycloak_realm_base(base_url, realm)
        if realm_base:
            auth_endpoint = f"{realm_base}/protocol/openid-connect/auth"
            token_endpoint = f"{realm_base}/protocol/openid-connect/token"
        return auth_endpoint, token_endpoint

    def _request_token(self, token_endpoint, data):
        if not token_endpoint:
            return None
        try:
            log_to_file(
                "Keycloak token request: "
                f"url={token_endpoint} "
                f"grant_type={data.get('grant_type','')} "
                f"client_id={data.get('client_id','')} "
                f"redirect_uri={data.get('redirect_uri','')}"
            )
            encoded = urllib.parse.urlencode(data).encode("utf-8")
            request = urllib.request.Request(
                token_endpoint,
                data=encoded,
                headers=_with_user_agent({"Content-Type": "application/x-www-form-urlencoded"})
            )
            with self._urlopen(request, context=self.get_ssl_context(), timeout=20) as response:
                payload = response.read().decode("utf-8")
            return json.loads(payload)
        except Exception as e:
            log_to_file(f"Token request failed: {str(e)}")
            return None

    def _store_tokens(self, token_response):
        if not isinstance(token_response, dict):
            return
        access_token = token_response.get("access_token", "")
        refresh_token = token_response.get("refresh_token", "")
        if access_token:
            self.set_config("access_token", access_token)
        if refresh_token:
            self.set_config("refresh_token", refresh_token)
        expires_in = token_response.get("expires_in")
        if isinstance(expires_in, (int, float)):
            self.set_config("access_token_expires_at", int(time.time() + int(expires_in)))

    def _clear_tokens(self):
        try:
            self.set_config("access_token", "")
            self.set_config("refresh_token", "")
            self.set_config("access_token_expires_at", 0)
            log_to_file("Keycloak tokens cleared")
        except Exception:
            pass

    def _token_email(self, access_token, userinfo_endpoint=None, allow_network=True):
        payload = self._jwt_payload(access_token)
        email = payload.get("email") or payload.get("preferred_username")
        verified = payload.get("email_verified", payload.get("emailVerified"))
        if email and (verified is None or verified is True):
            return email
        if userinfo_endpoint and allow_network:
            try:
                request = urllib.request.Request(
                    userinfo_endpoint,
                    headers=_with_user_agent({"Authorization": f"Bearer {access_token}"})
                )
                with self._urlopen(request, context=self.get_ssl_context(), timeout=10) as response:
                    payload = response.read().decode("utf-8")
                info = json.loads(payload)
                email = info.get("email") or info.get("preferred_username")
                verified = info.get("email_verified", info.get("emailVerified"))
                if email and (verified is None or verified is True):
                    return email
            except Exception as e:
                log_to_file(f"Userinfo request failed: {str(e)}")
        return None

    def _pkce_code_verifier(self):
        # RFC 7636 recommends 32-96 bytes of entropy; 96 bytes → 128-char base64url verifier
        raw = base64.urlsafe_b64encode(os.urandom(96)).decode("utf-8")
        return raw.rstrip("=")

    def _pkce_code_challenge(self, verifier):
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    def _wait_for_auth_code(self, redirect_uri, timeout_seconds=120, tick=None, cancel_event=None):
        try:
            parsed = urllib.parse.urlparse(redirect_uri)
            if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1"):
                return None, "redirect_uri_invalid"
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or "/"
        except Exception:
            return None, "redirect_uri_invalid"

        if cancel_event is None:
            cancel_event = threading.Event()

        done_event = threading.Event()
        result = {"code": None, "error": None}

        from http.server import BaseHTTPRequestHandler, HTTPServer
        try:
            from http.server import ThreadingHTTPServer as CallbackHTTPServer
        except Exception:
            CallbackHTTPServer = HTTPServer

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                parsed_path = urllib.parse.urlparse(self.path)
                request_path = parsed_path.path or "/"
                expected_path = path or "/"
                log_to_file(f"PKCE callback received: path={request_path} query={parsed_path.query}")
                if request_path.rstrip("/") != expected_path.rstrip("/"):
                    self.send_response(404)
                    self.end_headers()
                    return
                params = urllib.parse.parse_qs(parsed_path.query)
                code = params.get("code", [None])[0]
                error = params.get("error", [None])[0]
                log_to_file(f"PKCE callback parsed: code={'set' if code else 'none'} error={error or 'none'}")
                result["code"] = code
                result["error"] = error
                if code or error:
                    done_event.set()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                html = """<!doctype html>
<html lang="fr">
  <head>
    <meta charset="utf-8"/>
    <title>Authentification terminée</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 28px; color: #222; background: #f7f8fb; }
      .card { background: #fff; border: 1px solid #e3e6ef; border-radius: 10px; padding: 18px 20px; max-width: 560px; box-shadow: 0 2px 10px rgba(0,0,0,0.04); }
      .muted { color: #666; }
      .ok { display: inline-block; margin-top: 6px; padding: 6px 10px; background: #e8f5e9; color: #1b5e20; border-radius: 6px; font-weight: 600; }
      .small { font-size: 12px; color: #778; margin-top: 10px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h2>Authentification terminée</h2>
      <div class="ok">Connexion validée</div>
      <p>Vous pouvez fermer cet onglet et revenir à LibreOffice.</p>
      <p class="muted">Si LibreOffice ne réagit pas, attendez quelques secondes puis relancez l’action.</p>
      <div class="small">Aucune action supplémentaire n’est requise ici.</div>
    </div>
  </body>
</html>
"""
                self.wfile.write(html.encode("utf-8"))

        bind_host = "" if host in ("localhost", "127.0.0.1") else host
        try:
            httpd = CallbackHTTPServer((bind_host, port), Handler)
            if hasattr(httpd, "daemon_threads"):
                httpd.daemon_threads = True
        except Exception as e:
            log_to_file(f"Failed to start local callback server: {str(e)}")
            return None, "callback_server_error"
        log_to_file(f"Local callback server listening on http://{bind_host or '0.0.0.0'}:{port}{path}")

        server_thread = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True
        )
        server_thread.start()

        start = time.time()
        try:
            while (
                time.time() - start < timeout_seconds
                and not done_event.is_set()
                and not cancel_event.is_set()
            ):
                if tick:
                    try:
                        tick()
                    except Exception:
                        pass
                time.sleep(0.1)
        finally:
            try:
                httpd.shutdown()
            except Exception:
                pass
            httpd.server_close()
            if server_thread.is_alive():
                try:
                    server_thread.join(timeout=1)
                except Exception:
                    pass

        if cancel_event.is_set() and not result["code"] and not result["error"]:
            return None, "cancelled_by_user"
        if result["error"]:
            return None, result["error"]
        if not result["code"]:
            return None, "timeout"
        return result["code"], None

    def _validate_redirect_uri(self, redirect_uri):
        try:
            parsed = urllib.parse.urlparse(redirect_uri)
            if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1"):
                return redirect_uri
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or "/"
        except Exception:
            return redirect_uri
        return f"http://{host}:{port}{path}"

    def _select_redirect_uri(self):
        redirect_uri = self._get_config_from_file("keycloak_redirect_uri", "")
        if not redirect_uri:
            return None
        allowed = self._get_config_from_file("keycloak_allowed_redirect_uri", [])
        if isinstance(allowed, str):
            allowed = [u.strip() for u in allowed.split(",") if u.strip()]
        if isinstance(allowed, list) and allowed:
            if redirect_uri not in allowed:
                self._show_message(
                    "Configuration Keycloak invalide",
                    "redirect_uri n'est pas autorisé.\n\n"
                    "Vérifiez keycloak_allowed_redirect_uri."
                )
                return None
        valid = self._validate_redirect_uri(redirect_uri)
        if valid:
            log_to_file(f"Keycloak redirect_uri selected: {valid}")
        return valid

    def _authorization_code_flow(self, config_data):
        auth_endpoint, token_endpoint = self._keycloak_endpoints(config_data)
        if not auth_endpoint or not token_endpoint:
            log_to_file("Keycloak auth endpoints missing; cannot open browser")
            self._show_message(
                "Configuration Keycloak incomplète",
                "Impossible d'ouvrir la page d'authentification : endpoints Keycloak manquants.\n\n"
                "Vérifiez keycloakIssuerUrl / keycloakRealm."
            )
            return None

        client_id = self._get_config_from_file("keycloakClientId", "")
        if not client_id:
            log_to_file("Keycloak client_id missing; cannot open browser")
            self._show_message(
                "Configuration Keycloak incomplète",
                "Impossible d'ouvrir la page d'authentification : client_id manquant."
            )
            return None

        redirect_uri = self._select_redirect_uri()
        if not redirect_uri:
            log_to_file("Keycloak redirect_uri missing; cannot open browser")
            self._show_message(
                "Configuration Keycloak incomplète",
                "Impossible d'ouvrir la page d'authentification : redirect_uri manquant.\n\n"
                "Exemple : http://localhost:28443/callback"
            )
            return None

        proceed = self._confirm_message(
            "Connexion MIrAI requise",
            "Vous allez être redirigé vers la page de connexion MIrAI dans votre navigateur.\n\n"
            "Pourquoi : le plugin doit obtenir un jeton de session sécurisé pour accéder à l'API et à la configuration.\n\n"
            "Après la connexion, revenez à LibreOffice.\n\n"
            "Voulez-vous continuer ?"
        )
        if not proceed:
            log_to_file("Keycloak auth canceled by user before browser open")
            return None

        code_verifier = self._pkce_code_verifier()
        code_challenge = self._pkce_code_challenge(code_verifier)
        state = uuid.uuid4().hex

        query = urllib.parse.urlencode({
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state
        })
        auth_url = f"{auth_endpoint}?{query}"
        log_to_file(
            "Keycloak auth URL built: "
            f"auth_endpoint={auth_endpoint} client_id={client_id} redirect_uri={redirect_uri} "
            f"code_challenge={code_challenge} state={state} url={auth_url}"
        )
        try:
            import webbrowser
            webbrowser.open(auth_url)
        except Exception:
            try:
                from com.sun.star.system import XSystemShellExecute
                shell = self.ctx.getServiceManager().createInstanceWithContext(
                    "com.sun.star.system.SystemShellExecute", self.ctx
                )
                if isinstance(shell, XSystemShellExecute):
                    shell.execute(auth_url, "", 0)
            except Exception as e:
                log_to_file(f"Failed to open browser: {str(e)}")

        auth_cancel_event = threading.Event()

        def _show_auth_wait_dialog():
            try:
                from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
                ctx = uno.getComponentContext()
                create = ctx.getServiceManager().createInstanceWithContext
                dialog = create("com.sun.star.awt.UnoControlDialog")
                dialog_model = create("com.sun.star.awt.UnoControlDialogModel")
                dialog.setModel(dialog_model)
                dialog.setVisible(False)
                dialog.setTitle("")
                dialog.setPosSize(0, 0, 300, 120, SIZE)

                label_model = dialog_model.createInstance("com.sun.star.awt.UnoControlFixedTextModel")
                dialog_model.insertByName("auth_wait_label", label_model)
                label_model.Label = "Authentification Keycloak..."
                label_model.NoLabel = True
                label = dialog.getControl("auth_wait_label")
                label.setPosSize(10, 24, 280, 20, POSSIZE)

                btn_model = dialog_model.createInstance("com.sun.star.awt.UnoControlButtonModel")
                dialog_model.insertByName("auth_wait_cancel", btn_model)
                btn_model.Label = "Annuler"
                btn = dialog.getControl("auth_wait_cancel")
                btn.setPosSize(100, 72, 100, 26, POSSIZE)

                frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
                window = frame.getContainerWindow() if frame else None
                toolkit = create("com.sun.star.awt.Toolkit")
                dialog.createPeer(toolkit, window)
                if window:
                    ps = window.getPosSize()
                    _x = ps.Width / 2 - 150
                    _y = ps.Height / 2 - 60
                    dialog.setPosSize(_x, _y, 0, 0, POS)
                dialog.setVisible(True)
                return dialog, label, btn, toolkit
            except Exception:
                return None, None, None, None

        class CancelAuthListener(unohelper.Base, XActionListener):
            def actionPerformed(self, event):
                auth_cancel_event.set()
            def disposing(self, event):
                return

        wait_dialog, wait_label, wait_cancel_btn, wait_toolkit = _show_auth_wait_dialog()
        if wait_cancel_btn:
            try:
                wait_cancel_btn.addActionListener(CancelAuthListener())
            except Exception:
                pass
        tick_state = {"i": 0}
        def _tick():
            if not wait_label or not wait_toolkit:
                return
            tick_state["i"] += 1
            dots = "." * ((tick_state["i"] % 3) + 1)
            try:
                if auth_cancel_event.is_set():
                    wait_label.getModel().Label = "Annulation..."
                else:
                    wait_label.getModel().Label = f"Authentification Keycloak{dots}"
                wait_toolkit.processEventsToIdle()
            except Exception:
                pass

        auth_timeout_seconds = 180
        try:
            auth_timeout_seconds = int(self._get_config_from_file("keycloak_auth_timeout_seconds", 180))
        except Exception:
            auth_timeout_seconds = 180
        if auth_timeout_seconds < 60:
            auth_timeout_seconds = 60

        code, error = self._wait_for_auth_code(
            redirect_uri,
            timeout_seconds=auth_timeout_seconds,
            tick=_tick,
            cancel_event=auth_cancel_event
        )
        if wait_dialog:
            try:
                wait_dialog.setVisible(False)
                wait_dialog.dispose()
            except Exception:
                pass
        if error == "cancelled_by_user":
            log_to_file("Authorization code flow cancelled by user")
            return None
        if not code:
            log_to_file(f"Authorization code flow failed: {error}")
            if error == "timeout":
                self._show_message(
                    "Connexion expirée",
                    "Le login Keycloak a expiré avant le retour navigateur.\n\n"
                    f"Redirection attendue:\n{redirect_uri}\n\n"
                    "Vérifiez la redirection et relancez Login."
                )
            return None
        log_to_file("Authorization code received, exchanging for token")

        token_payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier
        }
        token_response = self._request_token(token_endpoint, token_payload)
        if isinstance(token_response, dict) and token_response.get("access_token"):
            self._store_tokens(token_response)
            access_token = token_response.get("access_token")
            try:
                self._secure_bind_identity(access_token)
            except Exception as exc:
                log_to_file(f"Post-SSO identity bind failed: {str(exc)}")
            try:
                self._ensure_device_management_state_async()
            except Exception as exc:
                log_to_file(f"Post-SSO enroll scheduling failed: {str(exc)}")
            return access_token
        return None

    def _ensure_access_token(self, config_data, interactive=True):
        access_token = str(self._get_config_from_file("access_token", "")).strip()
        if access_token and not self._token_is_expired(access_token):
            return access_token

        refresh_token = str(self._get_config_from_file("refresh_token", "")).strip()
        keycloak = self._keycloak_config(config_data)
        _, token_endpoint = self._keycloak_endpoints(config_data)
        client_id = (
            keycloak.get("client_id")
            or keycloak.get("clientId")
            or self._get_config_from_file("keycloakClientId", "")
            or self._get_config_from_file("keycloak_client_id", "")
            or self._get_config_from_file("client_id", "")
        )
        client_secret = (
            keycloak.get("client_secret")
            or keycloak.get("clientSecret")
            or self._get_config_from_file("keycloak_client_secret", "")
            or self._get_config_from_file("client_secret", "")
        )

        if refresh_token:
            refresh_payload = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id
            }
            if client_secret:
                refresh_payload["client_secret"] = client_secret
            token_response = self._request_token(token_endpoint, refresh_payload)
            if isinstance(token_response, dict) and token_response.get("access_token"):
                self._store_tokens(token_response)
                return token_response.get("access_token")

        if not interactive:
            log_to_file("Access token unavailable (interactive login disabled for this flow)")
            return None

        now = time.time()
        with self._auth_prompt_lock:
            if self._auth_prompt_in_progress or (now - self._auth_prompted_at) < 30:
                log_to_file("Auth prompt suppressed (already shown recently)")
                return None
            self._auth_prompt_in_progress = True
            self._auth_prompted_at = now
        try:
            auth_code_token = self._authorization_code_flow(config_data)
        finally:
            with self._auth_prompt_lock:
                self._auth_prompt_in_progress = False
        if auth_code_token:
            return auth_code_token

        log_to_file("Authentication aborted: no token obtained from browser SSO flow")
        return None

    def _ensure_device_management_state_async(self):
        def _worker():
            try:
                self._ensure_device_management_state()
            except Exception as exc:
                log_to_file(f"Failed to initialize device management (async): {str(exc)}")

        threading.Thread(target=_worker, daemon=True).start()

    def _ensure_device_management_state(self):
        if not self._device_management_enabled():
            return
        config_data = self._fetch_config()
        if not config_data:
            return
        try:
            self._sync_keycloak_from_config(config_data)
        except Exception:
            pass

        access_token = self._ensure_access_token(config_data, interactive=False)
        keycloak = self._keycloak_config(config_data)
        userinfo_endpoint = self._keycloak_endpoint(
            keycloak,
            "userinfo_endpoint",
            "userinfoEndpoint",
            "user_info_endpoint",
            "userInfoEndpoint",
            "userinfo"
        )
        email = self._token_email(access_token, userinfo_endpoint) if access_token else None
        if not email:
            log_to_file("Device management token email verification failed")
            return

        bootstrap_url = str(self._get_config_from_file("bootstrap_url", "") or "").strip().rstrip("/")
        settings = self._select_settings(config_data) if isinstance(config_data, dict) else {}

        enroll_endpoint = ""
        sources = []
        if isinstance(settings, dict):
            sources.append(settings)
        if isinstance(config_data, dict):
            sources.append(config_data)

        for source in sources:
            endpoints = source.get("endpoints", {})
            if isinstance(endpoints, dict):
                enroll_endpoint = str(
                    endpoints.get("enroll")
                    or endpoints.get("enroll_endpoint")
                    or endpoints.get("enrollEndpoint")
                    or ""
                ).strip()
            if enroll_endpoint:
                break
            enroll_endpoint = str(
                source.get("enroll")
                or source.get("enroll_endpoint")
                or source.get("enrollEndpoint")
                or ""
            ).strip()
            if enroll_endpoint:
                break

        if enroll_endpoint.startswith("/") and bootstrap_url:
            enroll_endpoint = bootstrap_url + enroll_endpoint
        if not enroll_endpoint and bootstrap_url:
            enroll_endpoint = bootstrap_url + "/enroll"
            log_to_file(f"Device management enroll endpoint fallback applied: {enroll_endpoint}")

        if not enroll_endpoint:
            return

        if self._as_bool(self._get_config_from_file("enrolled", False)):
            return

        device_name = config_data.get("device_name") or config_data.get("deviceName") or self._get_config_from_file("device_name", "")
        plugin_uuid = self._ensure_extension_uuid()

        enroll_payload = {
            "device_name": device_name,
            "plugin_uuid": plugin_uuid,
            "email": email
        }
        try:
            json_data = json.dumps(enroll_payload).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if access_token:
                headers["Authorization"] = f"Bearer {access_token}"
            request = urllib.request.Request(enroll_endpoint, data=json_data, headers=_with_user_agent(headers))
            request.get_method = lambda: 'POST'
            with self._urlopen(request, context=self.get_ssl_context(), timeout=10) as response:
                raw = response.read().decode("utf-8", errors="ignore")
            relay_client_id = ""
            relay_client_key = ""
            relay_expires_at = 0
            try:
                payload = json.loads(raw) if raw else {}
                if isinstance(payload, dict):
                    relay = payload.get("relay") if isinstance(payload.get("relay"), dict) else {}
                    relay_client_id = str(
                        payload.get("relayClientId")
                        or relay.get("client_id")
                        or ""
                    ).strip()
                    relay_client_key = str(
                        payload.get("relayClientKey")
                        or relay.get("client_key")
                        or ""
                    ).strip()
                    relay_expires = payload.get("relayKeyExpiresAt") or relay.get("expires_at") or 0
                    try:
                        relay_expires_at = int(relay_expires)
                    except Exception:
                        relay_expires_at = 0
            except Exception:
                pass
            if relay_client_id and relay_client_key:
                self.set_config("relay_client_id", relay_client_id)
                self.set_config("relay_client_key", relay_client_key)
                if relay_expires_at > 0:
                    self.set_config("relay_key_expires_at", relay_expires_at)
                log_to_file("Device management enroll succeeded with relay credentials")
            else:
                log_to_file("Device management enroll succeeded without relay credentials")
            self.set_config("enrolled", True)
        except Exception as e:
            log_to_file(f"Device management enroll failed: {str(e)}")

    def _get_openwebui_access_token(self):
        if not self._device_management_enabled():
            return ""
        config_data = self._fetch_config() or {}
        token = self._ensure_access_token(config_data, interactive=False) or ""
        if token:
            return token
        fallback_token = str(self._get_config_from_file("access_token", "")).strip()
        if fallback_token and not self._token_is_expired(fallback_token):
            log_to_file("Using local cached access_token (DM config unavailable)")
            return fallback_token
        return ""

    def _effective_api_token(self, preferred_token=""):
        token = str(preferred_token or "").strip()
        if token:
            return token
        return str(self._get_openwebui_access_token() or "").strip()

    def _auth_header(self):
        name = str(self.get_config("authHeaderName", "Authorization")).strip() or "Authorization"
        prefix = str(self.get_config("authHeaderPrefix", "Bearer ")).strip() or "Bearer"
        if prefix and not prefix.endswith(" "):
            prefix = prefix + " "
        return name, prefix

    def _relay_headers(self):
        relay_client_id = str(self._get_config_from_file("relay_client_id", "") or "").strip()
        relay_client_key = str(self._get_config_from_file("relay_client_key", "") or "").strip()
        if not relay_client_id or not relay_client_key:
            return {}
        return {
            "X-Relay-Client": relay_client_id,
            "X-Relay-Key": relay_client_key,
        }

    def _as_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        if isinstance(value, (int, float)):
            return value != 0
        return False

    def _get_proxy_config(self):
        enabled = self._as_bool(self._get_config_from_file("proxy_enabled", False))
        proxy_url = str(self._get_config_from_file("proxy_url", "")).strip()
        username = str(self._get_config_from_file("proxy_username", "")).strip()
        password = str(self._get_config_from_file("proxy_password", ""))
        allow_insecure = self._as_bool(self._get_config_from_file("proxy_allow_insecure_ssl", False))
        return {
            "enabled": enabled,
            "proxy_url": proxy_url,
            "username": username,
            "password": password,
            "allow_insecure_ssl": allow_insecure,
        }

    def _normalize_proxy_url(self, proxy_url):
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

    def _build_proxy_opener(self, proxy_cfg, context=None):
        if not proxy_cfg.get("enabled"):
            log_to_file("[PROXY] disabled")
            handlers = []
            if context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=context))
            return urllib.request.build_opener(*handlers)
        proxy_url = self._normalize_proxy_url(proxy_cfg.get("proxy_url", ""))
        if not proxy_url:
            log_to_file("[PROXY] enabled but proxy_url is empty/invalid")
            handlers = []
            if context is not None:
                handlers.append(urllib.request.HTTPSHandler(context=context))
            return urllib.request.build_opener(*handlers)
        handlers = []
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        proxy_map = {"http": proxy_url, "https": proxy_url}
        handlers.append(urllib.request.ProxyHandler(proxy_map))
        username = proxy_cfg.get("username", "")
        password = proxy_cfg.get("password", "")
        if username and password:
            try:
                pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                pwd_mgr.add_password(None, proxy_url, username, password)
                handlers.append(urllib.request.ProxyBasicAuthHandler(pwd_mgr))
                handlers.append(urllib.request.ProxyDigestAuthHandler(pwd_mgr))
                log_to_file("[PROXY] auth enabled (username+password)")
            except Exception:
                pass
        else:
            log_to_file("[PROXY] auth disabled (empty username or password)")
        try:
            if username and password:
                parsed = urllib.parse.urlparse(proxy_url)
                host = parsed.hostname or ""
                port = f":{parsed.port}" if parsed.port else ""
                proxy_url_auth = f"{parsed.scheme}://{username}:{password}@{host}{port}"
                proxy_map = {"http": proxy_url_auth, "https": proxy_url_auth}
                handlers[-1] = urllib.request.ProxyHandler(proxy_map)
        except Exception:
            pass
        log_to_file(f"[PROXY] using {proxy_url}")
        return urllib.request.build_opener(*handlers)

    def _urlopen(self, request, context=None, timeout=None, use_proxy=True):
        try:
            req_url = str(getattr(request, "full_url", "") or "")
            if "/relay-assistant/" in req_url:
                for header_name, header_value in self._relay_headers().items():
                    try:
                        request.add_header(header_name, header_value)
                    except Exception:
                        pass
        except Exception:
            pass
        proxy_cfg = self._get_proxy_config() if use_proxy else {
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
        opener = self._build_proxy_opener(proxy_cfg, context=context)
        log_to_file(
            f"[PROXY] request url={url} enabled={proxy_cfg.get('enabled')} "
            f"insecure_ssl={allow_insecure} use_proxy={use_proxy}"
        )
        if timeout is None:
            return opener.open(request)
        return opener.open(request, timeout=timeout)

    def _test_proxy_connection(self, proxy_cfg):
        test_url = "https://example.com"
        try:
            log_to_file(f"[PROXY][TEST] start url={test_url}")
            request = urllib.request.Request(test_url, headers=_with_user_agent({"Accept": "application/json"}))
            context = self.get_ssl_context() if proxy_cfg.get("allow_insecure_ssl") else ssl.create_default_context()
            opener = self._build_proxy_opener(proxy_cfg, context=context)
            log_to_file(f"[PROXY][TEST] connect allow_insecure_ssl={bool(proxy_cfg.get('allow_insecure_ssl'))}")
            with opener.open(request, timeout=8) as response:
                log_to_file(f"[PROXY][TEST] success status={response.status} url={test_url}")
                return True, f"Connexion OK ({response.status}) - URL: {test_url}"
        except Exception as e:
            log_to_file(f"[PROXY][TEST] error url={test_url} err={str(e)}")
            return False, f"Erreur: {str(e)} - URL: {test_url}"

    def _lo_proxy_settings(self):
        settings = {
            "enabled": False,
            "host": "",
            "port": "",
            "username": "",
            "password": "",
            "type": 0,
        }
        try:
            provider = self.ctx.getServiceManager().createInstanceWithContext(
                "com.sun.star.configuration.ConfigurationProvider", self.ctx
            )
            node = PropertyValue()
            node.Name = "nodepath"
            node.Value = "/org.openoffice.Inet/Settings"
            access = provider.createInstanceWithArguments(
                "com.sun.star.configuration.ConfigurationAccess", (node,)
            )
            proxy_type = getattr(access, "ooInetProxyType", 0)
            settings["type"] = int(proxy_type) if proxy_type is not None else 0
            settings["enabled"] = settings["type"] == 1
            http_host = getattr(access, "ooInetProxyHTTPName", "") or ""
            http_port = getattr(access, "ooInetProxyHTTPPort", "") or ""
            https_host = getattr(access, "ooInetProxyHTTPSName", "") or ""
            https_port = getattr(access, "ooInetProxyHTTPSPort", "") or ""
            host = http_host or https_host or ""
            port = http_port or https_port or ""
            settings["host"] = str(host)
            settings["port"] = str(port)
            settings["username"] = str(getattr(access, "ooInetProxyUser", "") or "")
            settings["password"] = str(getattr(access, "ooInetProxyPassword", "") or "")
        except Exception as e:
            log_to_file(f"Failed to read LibreOffice proxy settings: {str(e)}")
        return settings

    def _proxy_mismatch(self):
        cfg = self._get_proxy_config()
        lo = self._lo_proxy_settings()
        mismatches = []
        if cfg["enabled"] != lo["enabled"]:
            mismatches.append("enabled")
        cfg_host = ""
        cfg_port = ""
        if cfg["proxy_url"]:
            normalized = self._normalize_proxy_url(cfg["proxy_url"])
            try:
                parsed = urllib.parse.urlparse(normalized)
                cfg_host = parsed.hostname or ""
                cfg_port = str(parsed.port) if parsed.port else ""
            except Exception:
                pass
        if cfg["enabled"] and lo["enabled"]:
            if cfg_host and lo["host"] and cfg_host != lo["host"]:
                mismatches.append("host")
            if cfg_port and lo["port"] and cfg_port != lo["port"]:
                mismatches.append("port")
            if cfg["username"] and lo["username"] and cfg["username"] != lo["username"]:
                mismatches.append("username")
        return mismatches, cfg, lo

    def _check_proxy_consistency(self):
        checked_once = self._as_bool(self._get_config_from_file("proxy_consistency_checked_once", False))
        if checked_once:
            log_to_file("[PROXY] consistency check skipped (already checked)")
            return
        mismatches, cfg, lo = self._proxy_mismatch()
        if not mismatches:
            try:
                self.set_config("proxy_consistency_checked_once", True)
            except Exception:
                pass
            return
        msg = (
            "Les paramètres proxy de LibreOffice sont différents des préférences de MIrAI.\n\n"
            "Voulez-vous vérifier et valider les informations de proxy ?"
        )
        if self._confirm_message("Proxy", msg):
            try:
                self.proxy_settings_box("Proxy")
            except Exception:
                pass
        try:
            self.set_config("proxy_consistency_checked_once", True)
        except Exception:
            pass

    def proxy_settings_box(self, title="Proxy", x=None, y=None):
        WIDTH = 620
        HORI_MARGIN = VERT_MARGIN = 10
        LABEL_HEIGHT = 18
        EDIT_HEIGHT = 24
        BUTTON_WIDTH = 130
        BUTTON_HEIGHT = 26
        HORI_SEP = 8
        VERT_SEP = 6
        import uno
        from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
        from com.sun.star.awt.PushButtonType import OK, CANCEL
        from com.sun.star.util.MeasureUnit import TWIP
        ctx = uno.getComponentContext()
        def create(name):
            return ctx.getServiceManager().createInstanceWithContext(name, ctx)
        dialog = create("com.sun.star.awt.UnoControlDialog")
        dialog_model = create("com.sun.star.awt.UnoControlDialogModel")
        dialog.setModel(dialog_model)
        dialog.setVisible(False)
        dialog.setTitle(title)

        def add(name, type, x_, y_, width_, height_, props):
            try:
                model = dialog_model.createInstance("com.sun.star.awt.UnoControl" + type + "Model")
            except Exception as e:
                log_to_file(f"Dialog control type unsupported: name={name} type={type} error={str(e)}")
                return None
            try:
                dialog_model.insertByName(name, model)
            except Exception as e:
                log_to_file(f"Dialog insert failed: name={name} type={type} error={str(e)}")
                return None
            control = dialog.getControl(name)
            try:
                control.setPosSize(x_, y_, width_, height_, POSSIZE)
            except Exception as e:
                log_to_file(f"Dialog size failed: name={name} type={type} error={str(e)}")
            for key, value in props.items():
                try:
                    setattr(model, key, value)
                except Exception as e:
                    log_to_file(f"Dialog prop unsupported: control={name} type={type} prop={key} error={str(e)}")
            return control

        cfg = self._get_proxy_config()
        lo = self._lo_proxy_settings()
        proxy_url_value = cfg["proxy_url"]
        if not proxy_url_value and lo["host"]:
            proxy_url_value = f"{lo['host']}:{lo['port']}" if lo["port"] else lo["host"]

        HEIGHT = VERT_MARGIN * 2 + (LABEL_HEIGHT + EDIT_HEIGHT + VERT_SEP) * 5 + BUTTON_HEIGHT * 2 + VERT_SEP * 6 + 20
        dialog.setPosSize(0, 0, WIDTH, HEIGHT, SIZE)

        current_y = VERT_MARGIN
        add("label_proxy", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": "Paramètres proxy MIrAI", "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP

        add("label_enabled", "FixedText", HORI_MARGIN, current_y, 180, LABEL_HEIGHT,
            {"Label": "Utiliser un proxy:", "NoLabel": True})
        chk_enabled = add("chk_enabled", "CheckBox", HORI_MARGIN + 190, current_y, 50, LABEL_HEIGHT,
            {"State": 1 if cfg["enabled"] else 0})
        current_y += LABEL_HEIGHT + VERT_SEP

        add("label_url", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": "Proxy (host:port):", "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP
        edit_url = add("edit_url", "Edit", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT,
            {"Text": proxy_url_value})
        current_y += EDIT_HEIGHT + VERT_SEP * 2

        add("label_user", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": "Login proxy (optionnel):", "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP
        edit_user = add("edit_user", "Edit", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT,
            {"Text": cfg["username"]})
        current_y += EDIT_HEIGHT + VERT_SEP * 2

        add("label_pass", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": "Mot de passe proxy (optionnel):", "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP
        edit_pass = add("edit_pass", "Edit", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT,
            {"Text": cfg["password"], "EchoChar": ord("*")})
        current_y += EDIT_HEIGHT + VERT_SEP * 2

        add("label_insecure", "FixedText", HORI_MARGIN, current_y, 240, LABEL_HEIGHT,
            {"Label": "Autoriser HTTPS sans vérification (-k):", "NoLabel": True})
        chk_insecure = add("chk_insecure", "CheckBox", HORI_MARGIN + 250, current_y, 50, LABEL_HEIGHT,
            {"State": 1 if cfg["allow_insecure_ssl"] else 0})
        current_y += LABEL_HEIGHT + VERT_SEP * 2

        lo_text = "LibreOffice: "
        if lo["enabled"] and lo["host"]:
            lo_text += f"{lo['host']}:{lo['port']}" if lo["port"] else lo["host"]
        else:
            lo_text += "Proxy désactivé"
        add("label_lo", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": lo_text, "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP * 2

        btn_test = add("btn_test", "Button", HORI_MARGIN, current_y, BUTTON_WIDTH + 20, BUTTON_HEIGHT,
            {"Label": "Tester connexion", "Name": "test_proxy"})
        btn_copy = add("btn_copy", "Button", HORI_MARGIN + BUTTON_WIDTH + 30, current_y, BUTTON_WIDTH + 30, BUTTON_HEIGHT,
            {"Label": "Copier LibreOffice", "Name": "copy_lo"})
        current_y += BUTTON_HEIGHT + VERT_SEP * 2

        add("btn_ok", "Button", HORI_MARGIN, current_y, BUTTON_WIDTH, BUTTON_HEIGHT,
            {"PushButtonType": OK, "DefaultButton": True, "Label": "OK"})
        add("btn_cancel", "Button", HORI_MARGIN + BUTTON_WIDTH + HORI_SEP, current_y, BUTTON_WIDTH, BUTTON_HEIGHT,
            {"PushButtonType": CANCEL, "Label": "Annuler"})

        frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
        window = frame.getContainerWindow() if frame else None
        dialog.createPeer(create("com.sun.star.awt.Toolkit"), window)
        if not x is None and not y is None:
            ps = dialog.convertSizeToPixel(uno.createUnoStruct("com.sun.star.awt.Size", x, y), TWIP)
            _x, _y = ps.Width, ps.Height
        elif window:
            ps = window.getPosSize()
            _x = ps.Width / 2 - WIDTH / 2
            _y = ps.Height / 2 - HEIGHT / 2
        dialog.setPosSize(_x, _y, 0, 0, POS)

        class ProxyActionListener(unohelper.Base, XActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                try:
                    command = getattr(event, "ActionCommand", "") or ""
                except Exception:
                    command = ""
                if not command:
                    try:
                        source = getattr(event, "Source", None)
                        command = getattr(source.getModel(), "Name", "") if source else ""
                    except Exception:
                        command = ""
                if command == "copy_lo":
                    try:
                        if lo["enabled"] and lo["host"]:
                            url = f"{lo['host']}:{lo['port']}" if lo["port"] else lo["host"]
                            edit_url.getModel().Text = url
                            chk_enabled.getModel().State = 1
                        else:
                            chk_enabled.getModel().State = 0
                    except Exception:
                        pass
                elif command == "test_proxy":
                    try:
                        proxy_cfg = {
                            "enabled": bool(chk_enabled.getModel().State),
                            "proxy_url": str(edit_url.getModel().Text).strip(),
                            "username": str(edit_user.getModel().Text).strip(),
                            "password": str(edit_pass.getModel().Text),
                            "allow_insecure_ssl": bool(chk_insecure.getModel().State),
                        }
                        ok, message = self.outer._test_proxy_connection(proxy_cfg)
                        self.outer._show_message("Test proxy", message if ok else f"Échec: {message}")
                    except Exception as e:
                        self.outer._show_message("Test proxy", f"Échec: {str(e)}")
            def disposing(self, event):
                return

        listener = ProxyActionListener(self)
        if btn_test:
            try:
                btn_test.addActionListener(listener)
                btn_test.getModel().ActionCommand = "test_proxy"
            except Exception:
                pass
        if btn_copy:
            try:
                btn_copy.addActionListener(listener)
                btn_copy.getModel().ActionCommand = "copy_lo"
            except Exception:
                pass

        result = {}
        if dialog.execute():
            try:
                result["proxy_enabled"] = bool(chk_enabled.getModel().State)
                result["proxy_url"] = str(edit_url.getModel().Text).strip()
                result["proxy_username"] = str(edit_user.getModel().Text).strip()
                result["proxy_password"] = str(edit_pass.getModel().Text)
                result["proxy_allow_insecure_ssl"] = bool(chk_insecure.getModel().State)
                self.set_config("proxy_enabled", result["proxy_enabled"])
                self.set_config("proxy_url", result["proxy_url"])
                self.set_config("proxy_username", result["proxy_username"])
                self.set_config("proxy_password", result["proxy_password"])
                self.set_config("proxy_allow_insecure_ssl", result["proxy_allow_insecure_ssl"])
            except Exception:
                pass
        dialog.dispose()
        return result

    def _split_endpoint_api_path(self, endpoint, is_openwebui):
        endpoint = (endpoint or "").rstrip("/")
        if endpoint.endswith("/api") or endpoint.endswith("/v1"):
            return endpoint, ""
        api_path = "/api" if is_openwebui else "/v1"
        return endpoint, api_path

    def _build_auth_headers(self, api_key):
        """Build standard JSON + auth headers for API calls."""
        headers = {"Content-Type": "application/json"}
        if api_key:
            header_name, header_prefix = self._auth_header()
            headers[header_name] = f"{header_prefix}{api_key}"
        return headers

    def _fetch_models(self, endpoint, api_key, is_openwebui, include_info=False):
        """
        Fetch models from the API endpoint.

        Returns a list of model IDs when include_info=False,
        or a (list, dict) tuple of (model_ids, descriptions) when include_info=True.
        """
        endpoint, api_path = self._split_endpoint_api_path(endpoint, is_openwebui)
        api_key = self._effective_api_token(api_key)
        url = endpoint + api_path + "/models" if api_path else endpoint + "/models"
        headers = self._build_auth_headers(api_key)

        try:
            log_to_file(f"Models fetch curl: curl -i {_curl_headers_for_log(headers)} '{url}'")
        except Exception:
            pass

        try:
            request = urllib.request.Request(url, headers=_with_user_agent(headers))
            with self._urlopen(request, context=self.get_ssl_context(), timeout=10) as response:
                payload = response.read().decode("utf-8")
            data = json.loads(payload)
        except Exception as e:
            log_to_file(f"Failed to fetch models: {str(e)}")
            return ([], {}) if include_info else []

        if include_info:
            log_to_file(f"Models API raw response: {payload[:2000]}")

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

    def _fetch_models_list(self, endpoint, api_key, is_openwebui):
        return self._fetch_models(endpoint, api_key, is_openwebui, include_info=False)

    def _fetch_models_info(self, endpoint, api_key, is_openwebui):
        return self._fetch_models(endpoint, api_key, is_openwebui, include_info=True)

    def _refresh_config_to_local(self, cancel_flag=None):
        if cancel_flag and cancel_flag.get("cancel"):
            log_to_file("Reload config: canceled before fetch")
            return {}
        config_data = self._fetch_config(force=True)
        if not config_data:
            log_to_file("Reload config: failed to fetch config_data")
            return {}
        if cancel_flag and cancel_flag.get("cancel"):
            log_to_file("Reload config: canceled after fetch")
            return {}
        config_obj = config_data.get("config") if isinstance(config_data, dict) else None
        if isinstance(config_obj, dict):
            settings = config_obj
            log_to_file("Reload config: using config object")
        else:
            settings = self._select_settings(config_data)

        if not isinstance(settings, dict):
            if isinstance(config_data, dict):
                settings = config_data
                log_to_file("Reload config: using top-level config (no settings wrapper)")
            else:
                log_to_file(f"Reload config: no settings dict found (type={type(config_data).__name__})")
                return {}
        if "model" in settings:
            settings.pop("model", None)
        if "owuiEndpoint" in settings:
            settings.pop("owuiEndpoint", None)
        if "tokenOWUI" in settings:
            settings.pop("tokenOWUI", None)
        self._sync_keycloak_from_settings(settings, config_data)
        # Normalize keycloak fields if provided at top-level settings
        try:
            if "keycloakRealm" not in settings:
                for k in ("realm", "keycloak_realm"):
                    if k in settings and str(settings.get(k) or "").strip():
                        settings["keycloakRealm"] = str(settings.get(k)).strip()
                        break
            if "keycloakIssuerUrl" not in settings:
                for k in ("issuerUrl", "issuerURL", "issuer_url", "baseUrl", "base_url", "keycloakIssuerUrl"):
                    if k in settings and str(settings.get(k) or "").strip():
                        settings["keycloakIssuerUrl"] = str(settings.get(k)).strip()
                        break
            if "keycloakClientId" not in settings:
                for k in ("client_id", "clientId", "clientID", "keycloakClientId"):
                    if k in settings and str(settings.get(k) or "").strip():
                        settings["keycloakClientId"] = str(settings.get(k)).strip()
                        break
        except Exception:
            pass
        config_path = str(self._get_config_from_file("config_path", "/config/config.json"))
        bootstrap_url = str(self._get_config_from_file("bootstrap_url", "")).strip()
        normalized_url = f"{bootstrap_url.rstrip('/')}/{config_path.lstrip('/')}"
        log_to_file(f"Reload config URL computed: {normalized_url}")
        log_to_file(f"Reload config: url={normalized_url} keys={list(settings.keys())}")
        synced = []
        skipped = []
        for meta_key in ("lastversion", "updateUrl", "configVersion", "environment"):
            if isinstance(config_data, dict) and meta_key in config_data:
                meta_val = config_data.get(meta_key)
                if meta_val is None or (isinstance(meta_val, str) and meta_val.strip() == ""):
                    continue
                try:
                    self.set_config(meta_key, meta_val)
                    synced.append(meta_key)
                except Exception:
                    pass
        for key, value in settings.items():
            if value is None or (isinstance(value, str) and value.strip() == ""):
                skipped.append(key)
                continue
            if key in ("proxy_url", "proxy_username", "proxy_password"):
                try:
                    if isinstance(value, str) and len(value.strip()) < 5:
                        skipped.append(key)
                        continue
                except Exception:
                    pass
            try:
                self.set_config(key, value)
                synced.append(key)
            except Exception:
                pass
        log_to_file(f"Device management config synced locally: {synced}")
        if skipped:
            log_to_file(f"Device management config skipped empty values: {skipped}")
        return settings

    def _sync_keycloak_from_settings(self, settings, config_data=None):
        keycloak_src = None

        def _flat_keycloak(source):
            if not isinstance(source, dict):
                return None
            flat = {
                "issuerUrl": (
                    source.get("keycloakIssuerUrl")
                    or source.get("issuerUrl")
                    or source.get("issuerURL")
                    or source.get("issuer_url")
                    or source.get("keycloak_base_url")
                    or source.get("issuer")
                ),
                "realm": (
                    source.get("keycloakRealm")
                    or source.get("keycloak_realm")
                    or source.get("realm")
                ),
                "clientId": (
                    source.get("keycloakClientId")
                    or source.get("keycloak_client_id")
                    or source.get("clientId")
                    or source.get("client_id")
                ),
                "clientSecret": (
                    source.get("keycloak_client_secret")
                    or source.get("clientSecret")
                    or source.get("client_secret")
                ),
                "authorization_endpoint": (
                    source.get("keycloakAuthorizationEndpoint")
                    or source.get("keycloak_authorization_endpoint")
                    or source.get("authorization_endpoint")
                    or source.get("authorizationEndpoint")
                    or source.get("auth_endpoint")
                    or source.get("authEndpoint")
                    or source.get("auth_url")
                    or source.get("authUrl")
                    or source.get("auth")
                ),
                "token_endpoint": (
                    source.get("keycloakTokenEndpoint")
                    or source.get("keycloak_token_endpoint")
                    or source.get("token_endpoint")
                    or source.get("tokenEndpoint")
                    or source.get("token_url")
                    or source.get("tokenUrl")
                    or source.get("token")
                ),
                "userinfo_endpoint": (
                    source.get("keycloakUserinfoEndpoint")
                    or source.get("keycloak_userinfo_endpoint")
                    or source.get("userinfo_endpoint")
                    or source.get("userinfoEndpoint")
                    or source.get("user_info_endpoint")
                    or source.get("userInfoEndpoint")
                    or source.get("userinfo")
                ),
                "redirect_uri": (
                    source.get("keycloak_redirect_uri")
                    or source.get("redirect_uri")
                    or source.get("redirectUri")
                ),
                "allowed_redirect_uri": (
                    source.get("keycloak_allowed_redirect_uri")
                    or source.get("allowed_redirect_uri")
                    or source.get("allowedRedirectUri")
                ),
            }
            if any(v is not None and str(v).strip() for v in flat.values()):
                return flat
            return None

        if isinstance(settings, dict):
            if isinstance(settings.get("keycloak"), dict):
                keycloak_src = settings.get("keycloak")
            elif isinstance(settings.get("endpoints"), dict) and isinstance(settings.get("endpoints", {}).get("keycloak"), dict):
                keycloak_src = settings.get("endpoints", {}).get("keycloak")
            if keycloak_src is None:
                keycloak_src = _flat_keycloak(settings)
        if keycloak_src is None and isinstance(config_data, dict):
            candidate = config_data.get("keycloak")
            if not isinstance(candidate, dict):
                endpoints = config_data.get("endpoints", {}) if isinstance(config_data.get("endpoints", {}), dict) else {}
                candidate = endpoints.get("keycloak")
            if isinstance(candidate, dict):
                keycloak_src = candidate
            if keycloak_src is None:
                keycloak_src = _flat_keycloak(config_data)
        if not isinstance(keycloak_src, dict):
            return
        keycloak_map = {
            "keycloakIssuerUrl": (
                keycloak_src.get("issuerUrl")
                or keycloak_src.get("issuerURL")
                or keycloak_src.get("keycloakIssuerUrl")
                or keycloak_src.get("issuer_url")
                or keycloak_src.get("issuerUri")
                or keycloak_src.get("issuerURI")
                or keycloak_src.get("issuer")
                or keycloak_src.get("baseUrl")
                or keycloak_src.get("base_url")
                or keycloak_src.get("url")
            ),
            "keycloakRealm": (
                keycloak_src.get("realm")
                or keycloak_src.get("keycloakRealm")
                or keycloak_src.get("keycloak_realm")
            ),
            "keycloakClientId": (
                keycloak_src.get("client_id")
                or keycloak_src.get("clientId")
                or keycloak_src.get("clientID")
                or keycloak_src.get("keycloakClientId")
            ),
            "keycloak_client_secret": (
                keycloak_src.get("client_secret")
                or keycloak_src.get("clientSecret")
                or keycloak_src.get("keycloakClientSecret")
            ),
            "keycloakAuthorizationEndpoint": (
                keycloak_src.get("authorization_endpoint")
                or keycloak_src.get("authorizationEndpoint")
                or keycloak_src.get("keycloakAuthorizationEndpoint")
                or keycloak_src.get("auth_endpoint")
                or keycloak_src.get("authEndpoint")
                or keycloak_src.get("auth_url")
                or keycloak_src.get("authUrl")
                or keycloak_src.get("auth")
            ),
            "keycloakTokenEndpoint": (
                keycloak_src.get("token_endpoint")
                or keycloak_src.get("tokenEndpoint")
                or keycloak_src.get("keycloakTokenEndpoint")
                or keycloak_src.get("token_url")
                or keycloak_src.get("tokenUrl")
                or keycloak_src.get("token")
            ),
            "keycloakUserinfoEndpoint": (
                keycloak_src.get("userinfo_endpoint")
                or keycloak_src.get("userinfoEndpoint")
                or keycloak_src.get("keycloakUserinfoEndpoint")
                or keycloak_src.get("user_info_endpoint")
                or keycloak_src.get("userInfoEndpoint")
                or keycloak_src.get("userinfo")
            ),
            "keycloak_redirect_uri": (
                keycloak_src.get("redirect_uri")
                or keycloak_src.get("redirectUri")
                or keycloak_src.get("keycloak_redirect_uri")
            ),
            "keycloak_allowed_redirect_uri": (
                keycloak_src.get("allowed_redirect_uri")
                or keycloak_src.get("allowedRedirectUri")
                or keycloak_src.get("keycloak_allowed_redirect_uri")
            ),
        }
        for target_key, value in keycloak_map.items():
            if value is None:
                continue
            text = str(value).strip()
            if not text:
                continue
            try:
                current = str(self._get_config_from_file(target_key, "") or "").strip()
            except Exception:
                current = ""
            if not current:
                try:
                    self.set_config(target_key, text)
                except Exception:
                    pass

    def _sync_keycloak_from_config(self, config_data):
        settings = None
        if isinstance(config_data, dict):
            config_obj = config_data.get("config")
            if isinstance(config_obj, dict):
                settings = config_obj
            else:
                settings = self._select_settings(config_data)
        self._sync_keycloak_from_settings(settings if isinstance(settings, dict) else {}, config_data=config_data)

    def _get_cached_models(self, endpoint, api_key, is_openwebui):
        key = (endpoint, api_key, bool(is_openwebui))
        now = time.time()
        if self._models_cache and self._models_cache_key == key:
            if (now - self._models_cache_loaded_at) < self._models_cache_ttl:
                return self._models_cache
        models = self._fetch_models_list(endpoint, api_key, is_openwebui)
        self._models_cache = models
        self._models_cache_key = key
        self._models_cache_loaded_at = now
        return models

    def _api_reachable(self, endpoint, headers, is_openwebui, path):
        endpoint = (endpoint or "").rstrip("/")
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            if path.startswith("/"):
                url = endpoint + path
            else:
                url = endpoint + "/" + path
        try:
            request = urllib.request.Request(url, headers=_with_user_agent(headers))
            with self._urlopen(request, context=self.get_ssl_context(), timeout=5) as response:
                if response.status < 200 or response.status >= 300:
                    return False
                payload = response.read().decode("utf-8")
            json.loads(payload)
            return True
        except Exception:
            return False

    def _api_probe(self, endpoint, headers, path):
        endpoint = (endpoint or "").rstrip("/")
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            if path.startswith("/"):
                url = endpoint + path
            else:
                url = endpoint + "/" + path
        try:
            request = urllib.request.Request(url, headers=_with_user_agent(headers))
            with self._urlopen(request, context=self.get_ssl_context(), timeout=5) as response:
                response.read()
                status = getattr(response, "status", None)
            return True, {"url": url, "status": status, "error": ""}
        except urllib.error.HTTPError as e:
            return True, {"url": url, "status": e.code, "error": f"http_{e.code}"}
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            return False, {"url": url, "status": None, "error": str(reason)}
        except socket.timeout:
            return False, {"url": url, "status": None, "error": "timeout"}
        except Exception as e:
            return False, {"url": url, "status": None, "error": str(e)}

    def _endpoint_connectivity_status(self, endpoint, is_openwebui):
        headers = {"Content-Type": "application/json"}
        endpoint_base, api_path = self._split_endpoint_api_path(endpoint, is_openwebui)
        checks = []
        if is_openwebui:
            checks.append("/health")
        models_path = (api_path + "/models") if api_path else "/models"
        checks.append(models_path)
        checks.append("/")
        last_detail = {"url": endpoint_base, "status": None, "error": "unknown"}
        for path in checks:
            ok, detail = self._api_probe(endpoint_base, headers, path)
            if ok:
                return True, detail
            last_detail = detail
        return False, last_detail

    def _api_status(self, endpoint, api_key, is_openwebui):
        anon_ok, _ = self._endpoint_connectivity_status(endpoint, is_openwebui)

        api_key = self._effective_api_token(api_key)
        auth_headers = {"Content-Type": "application/json"}
        if is_openwebui:
            header_name, header_prefix = self._auth_header()
            if api_key:
                auth_headers[header_name] = f"{header_prefix}{api_key}"
        elif api_key:
            header_name, header_prefix = self._auth_header()
            auth_headers[header_name] = f"{header_prefix}{api_key}"

        auth_ok = False
        if api_key:
            endpoint_base, api_path = self._split_endpoint_api_path(endpoint, is_openwebui)
            models_path = (api_path + "/models") if api_path else "/models"
            _, detail = self._api_probe(endpoint_base, auth_headers, models_path)
            status = detail.get("status")
            if status in (401, 403):
                auth_ok = False
                log_to_file(f"API auth probe rejected: status={status} url={detail.get('url')}")
            elif status is not None:
                # Accept non-auth errors (e.g. 404) as "auth reachable":
                # some providers do not expose /models despite valid credentials.
                auth_ok = True
            else:
                auth_ok = False

        return anon_ok, auth_ok

    def _choose_model_via_ai(self, description, endpoint, api_key, is_openwebui):
        api_key = self._effective_api_token(api_key)
        models = self._fetch_models_list(endpoint, api_key, is_openwebui)
        if not models:
            return None

        current_model = str(self.get_config("llm_default_models", "")).strip()
        model_for_request = current_model or models[0]
        endpoint, api_path = self._split_endpoint_api_path(endpoint, is_openwebui)
        if api_path:
            url = endpoint + api_path + "/chat/completions"
        else:
            url = endpoint + "/chat/completions"

        headers = {"Content-Type": "application/json"}
        if is_openwebui:
            header_name, header_prefix = self._auth_header()
            if api_key:
                headers[header_name] = f"{header_prefix}{api_key}"
        elif api_key:
            header_name, header_prefix = self._auth_header()
            headers[header_name] = f"{header_prefix}{api_key}"

        system_prompt = (
            "Select the best model id from the provided list. "
            "Return exactly one model id from the list and nothing else."
        )
        user_prompt = f"Use case: {description}\n\nModel list:\n" + "\n".join(models)
        data = {
            "model": model_for_request,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": 32,
            "temperature": 0,
            "stream": False
        }

        try:
            json_data = json.dumps(data).encode("utf-8")
            request = urllib.request.Request(url, data=json_data, headers=_with_user_agent(headers))
            request.get_method = lambda: 'POST'
            with self._urlopen(request, context=self.get_ssl_context(), timeout=20) as response:
                payload = response.read().decode("utf-8")
            response_data = json.loads(payload)
            choice = None
            if isinstance(response_data, dict) and response_data.get("choices"):
                first = response_data["choices"][0]
                if isinstance(first, dict):
                    message = first.get("message", {})
                    if isinstance(message, dict):
                        choice = message.get("content")
                    if not choice:
                        choice = first.get("text")
            if choice:
                candidate = choice.strip()
                if candidate in models:
                    return candidate
                for model_id in models:
                    if candidate.lower() in model_id.lower():
                        return model_id
        except Exception as e:
            log_to_file(f"Model AI search failed: {str(e)}")

        return models[0] if models else None


    def _is_openai_compatible(self):
        endpoint = str(self.get_config("llm_base_urls", "http://127.0.0.1:5000"))
        compatibility_flag = self._as_bool(self.get_config("openai_compatibility", False))
        return compatibility_flag or ("api.openai.com" in endpoint.lower())

    def make_api_request(self, prompt, system_prompt="", max_tokens=15000, api_type=None):
        """
        Build a streaming completion/chat request that can target local or OpenAI-compatible endpoints.
        """
        try:
            max_tokens = int(max_tokens)
        except (TypeError, ValueError):
            max_tokens = 15000

        endpoint = str(self.get_config("llm_base_urls", "http://127.0.0.1:5000")).rstrip("/")
        api_key = self._effective_api_token(self.get_config("llm_api_tokens", ""))
        if api_type is None:
            api_type = str(self.get_config("api_type", "completions")).lower()
        api_type = "chat" if api_type == "chat" else "completions"
        model = str(self.get_config("llm_default_models", ""))
        
        # Add default system prompt to ensure plain text output
        default_system_prompt = "Return only plain text. Do not use markdown, code blocks, or formatting symbols like **, *, _, or #. French characters and punctuation are allowed (accents, apostrophes, guillemets « », etc.). Return natural, simple text only."
        if system_prompt:
            system_prompt = default_system_prompt + " " + system_prompt
        else:
            system_prompt = default_system_prompt
        
        log_to_file(f"=== API Request Debug ===")
        log_to_file(f"Endpoint: {endpoint}")
        log_to_file(f"API Type: {api_type}")
        log_to_file(f"Model: {model}")
        log_to_file(f"Max Tokens: {max_tokens}")

        headers = {
            'Content-Type': 'application/json'
        }

        # Detect OpenWebUI endpoints (they use /api/ instead of /v1/)
        is_openwebui = True
        endpoint, api_path = self._split_endpoint_api_path(endpoint, is_openwebui)
        if is_openwebui:
            header_name, header_prefix = self._auth_header()
            if api_key:
                headers[header_name] = f'{header_prefix}{api_key}'
        elif api_key:
            header_name, header_prefix = self._auth_header()
            headers[header_name] = f'{header_prefix}{api_key}'
        
        log_to_file(f"Is OpenWebUI: {is_openwebui}")
        log_to_file(f"API Path: {api_path}")

        if api_type == "chat":
            url = endpoint + api_path + "/chat/completions"
            log_to_file(f"Full URL: {url}")
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            data = {
                'messages': messages,
                'max_tokens': max_tokens,
                'temperature': 1,
                'top_p': 0.9,
                'stream': True
            }
        else:
            url = endpoint + api_path + "/completions"
            full_prompt = prompt
            if system_prompt:
                full_prompt = f"SYSTEM PROMPT\n{system_prompt}\nEND SYSTEM PROMPT\n{prompt}"
            data = {
                'prompt': full_prompt,
                'max_tokens': max_tokens,
                'temperature': 1,
                'top_p': 0.9,
                'stream': True
            }
            if not self._is_openai_compatible():
                data['seed'] = 10

        if model:
            data["model"] = model
            try:
                model_lower = model.lower()
                model_limits = {
                    "deepseek-r1-distill-llama-70b": 8196,
                    "llama-3.3-70b-instruct": 4096,
                }
                limit = None
                for key, value in model_limits.items():
                    if key in model_lower:
                        limit = value
                        break
                if limit:
                    if max_tokens > limit:
                        max_tokens = limit
                        data["max_tokens"] = limit
                    data["max_completion_tokens"] = min(int(data.get("max_tokens", limit)), limit)
                    log_to_file(f"Max tokens clamped for {model}: {data['max_completion_tokens']}")
            except Exception:
                pass

        json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
        log_to_file(f"Request data: {json.dumps(data, ensure_ascii=False, indent=2)}")
        log_to_file(f"Headers: {_redacted_headers(headers)}")
        try:
            curl_headers = _curl_headers_for_log(headers)
            log_to_file(f"Chat completions curl: curl -i -X POST {curl_headers} '{url}' -d '{json.dumps(data)}'")
        except Exception:
            pass
        
        # Note: method='POST' is implicit when data is provided
        request = urllib.request.Request(url, data=json_data, headers=_with_user_agent(headers))
        request.get_method = lambda: 'POST'
        return request

    def extract_content_from_response(self, chunk, api_type="completions"):
        """
        Extract text content from API response chunk based on API type.
        """
        if api_type == "chat":
            # OpenAI chat completions format
            if "choices" in chunk and len(chunk["choices"]) > 0:
                delta = chunk["choices"][0].get("delta", {})
                return delta.get("content", ""), chunk["choices"][0].get("finish_reason")
        else:
            # Legacy completions format
            if "choices" in chunk and len(chunk["choices"]) > 0:
                return chunk["choices"][0].get("text", ""), chunk["choices"][0].get("finish_reason")
        
        return "", None

    def get_ssl_context(self):
        """
        Create an SSL context for HTTP calls.
        If available, load the bundled CA chain used by bootstrap endpoints.
        """
        allow_insecure = self._as_bool(self._get_config_from_file("proxy_allow_insecure_ssl", False))
        ssl_context = ssl.create_default_context()
        if allow_insecure:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            return ssl_context

        loaded_bundle = None
        configured_bundle = str(self._get_config_from_file("ca_bundle_path", "") or "").strip()
        candidate_paths = []
        if configured_bundle:
            if configured_bundle.startswith("file://"):
                try:
                    configured_bundle = str(uno.fileUrlToSystemPath(configured_bundle))
                except Exception:
                    pass
            if os.path.isabs(configured_bundle):
                candidate_paths.append(configured_bundle)
            else:
                candidate_paths.append(os.path.join(self._get_user_config_dir(), configured_bundle))
                candidate_paths.append(os.path.join(os.path.dirname(__file__), configured_bundle))

        candidate_paths.append(
            os.path.join(
                os.path.dirname(__file__),
                "CAbundle",
                "scaleway-bootstrap-ca-chain.pem",
            )
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
            log_to_file(f"SSL CA bundle loaded: {loaded_bundle}")
        elif not loaded_bundle and self._last_ca_bundle_error:
            if self._last_ca_bundle_error != self._last_logged_ca_bundle_error:
                log_to_file(f"SSL CA bundle load failed: {self._last_ca_bundle_error}")
                self._last_logged_ca_bundle_error = self._last_ca_bundle_error

        return ssl_context

    def stream_request(self, request, api_type, append_callback):
        """
        Stream a completion/chat response and append incremental chunks via the provided callback.
        """
        toolkit = self.ctx.getServiceManager().createInstanceWithContext(
            "com.sun.star.awt.Toolkit", self.ctx
        )
        ssl_context = self.get_ssl_context()
        try:
            request_timeout = int(self.get_config("llm_request_timeout_seconds", 45))
        except Exception:
            request_timeout = 45
        if request_timeout < 5:
            request_timeout = 5
        
        log_to_file(f"=== Starting stream request ===")
        log_to_file(f"Request URL: {request.full_url}")
        log_to_file(f"Request method: {request.get_method()}")
        log_to_file(f"Request timeout: {request_timeout}s")
        
        try:
            with self._urlopen(request, context=ssl_context, timeout=request_timeout) as response:
                log_to_file(f"Response status: {response.status}")
                log_to_file(f"Response headers: {response.headers}")
                
                for line in response:
                    try:
                        if line.strip() and line.startswith(b"data: "):
                            payload = line[len(b"data: "):].decode("utf-8").strip()
                            if payload == "[DONE]":
                                break
                            chunk = json.loads(payload)
                            content, finish_reason = self.extract_content_from_response(chunk, api_type)
                            if content:
                                append_callback(content)
                                toolkit.processEventsToIdle()
                            if finish_reason:
                                break
                    except Exception as e:
                        log_to_file(f"Error processing line: {str(e)}")
                        append_callback(str(e))
                        toolkit.processEventsToIdle()
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8")
            except Exception:
                body = ""
            if e.code == 401 or ("\"401\"" in body or "status\":401" in body or "code\":401" in body):
                try:
                    self._show_message_and_open_settings(
                        "Token invalide",
                        "Votre token n'est plus valide.\n\n"
                        "Voulez-vous ouvrir les préférences pour le vérifier ?"
                    )
                except Exception:
                    pass
            log_to_file(f"ERROR in stream_request: HTTP {e.code} {e.reason} body={body[:2000]}")
            toolkit.processEventsToIdle()
        except Exception as e:
            log_to_file(f"ERROR in stream_request: {str(e)}")
            toolkit.processEventsToIdle()

    #retrieved from https://wiki.documentfoundation.org/Macros/General/IO_to_Screen
    #License: Creative Commons Attribution-ShareAlike 3.0 Unported License,
    #License: The Document Foundation  https://creativecommons.org/licenses/by-sa/3.0/
    #begin sharealike section 
    def input_box(self,message, title="", default="", x=None, y=None, ok_label="OK", cancel_label="Annuler", always_on_top=False):
        """ Shows dialog with input box.
            @param message message to show on the dialog
            @param title window title
            @param default default value
            @param x optional dialog position in twips
            @param y optional dialog position in twips
            @return string if OK button pushed, otherwise zero length string
        """
        WIDTH = 720
        HORI_MARGIN = VERT_MARGIN = 8
        BUTTON_WIDTH = 100
        BUTTON_HEIGHT = 26
        HORI_SEP = VERT_SEP = 8
        LABEL_HEIGHT = 26
        EDIT_HEIGHT = 80
        HEIGHT = VERT_MARGIN * 2 + LABEL_HEIGHT + VERT_SEP + EDIT_HEIGHT + VERT_SEP + BUTTON_HEIGHT
        import uno
        from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
        from com.sun.star.awt.PushButtonType import OK, CANCEL
        from com.sun.star.util.MeasureUnit import TWIP
        ctx = uno.getComponentContext()
        def create(name):
            return ctx.getServiceManager().createInstanceWithContext(name, ctx)
        dialog = create("com.sun.star.awt.UnoControlDialog")
        dialog_model = create("com.sun.star.awt.UnoControlDialogModel")
        dialog.setModel(dialog_model)
        try:
            dialog_model.BackgroundColor = 0xFFFFFF
        except Exception:
            pass
        if always_on_top:
            try:
                dialog_model.AlwaysOnTop = True
            except Exception:
                pass
            try:
                dialog_model.Closeable = True
            except Exception:
                pass
        dialog.setVisible(False)
        dialog.setTitle(title)
        dialog.setPosSize(0, 0, WIDTH, HEIGHT, SIZE)
        try:
            dialog.getModel().Sizeable = True
        except Exception:
            pass
        def add(name, type, x_, y_, width_, height_, props):
            try:
                model = dialog_model.createInstance("com.sun.star.awt.UnoControl" + type + "Model")
            except Exception as e:
                log_to_file(f"Dialog control type unsupported: name={name} type={type} error={str(e)}")
                return None
            try:
                dialog_model.insertByName(name, model)
            except Exception as e:
                log_to_file(f"Dialog insert failed: name={name} type={type} error={str(e)}")
                return None
            control = dialog.getControl(name)
            try:
                control.setPosSize(x_, y_, width_, height_, POSSIZE)
            except Exception as e:
                log_to_file(f"Dialog size failed: name={name} type={type} error={str(e)}")
            for key, value in props.items():
                try:
                    setattr(model, key, value)
                except Exception as e:
                    log_to_file(f"Dialog prop unsupported: control={name} type={type} prop={key} error={str(e)}")
            return control

        edit_y = VERT_MARGIN + LABEL_HEIGHT + VERT_SEP
        btn_y = edit_y + EDIT_HEIGHT + VERT_SEP
        add("label", "FixedText", HORI_MARGIN, VERT_MARGIN, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": str(message), "NoLabel": True})
        add("edit", "Edit", HORI_MARGIN, edit_y,
                WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT, {"Text": str(default), "MultiLine": True})
        add("btn_ok", "Button", HORI_MARGIN, btn_y,
                BUTTON_WIDTH, BUTTON_HEIGHT, {"PushButtonType": OK, "DefaultButton": True, "Label": ok_label})
        add("btn_cancel", "Button", HORI_MARGIN + BUTTON_WIDTH + HORI_SEP, btn_y,
                BUTTON_WIDTH, BUTTON_HEIGHT, {"PushButtonType": CANCEL, "Label": cancel_label})
        frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
        window = frame.getContainerWindow() if frame else None
        dialog.createPeer(create("com.sun.star.awt.Toolkit"), window)
        if not x is None and not y is None:
            ps = dialog.convertSizeToPixel(uno.createUnoStruct("com.sun.star.awt.Size", x, y), TWIP)
            _x, _y = ps.Width, ps.Height
        elif window:
            ps = window.getPosSize()
            _x = ps.Width / 2 - WIDTH / 2
            _y = ps.Height / 2 - HEIGHT / 2
        dialog.setPosSize(_x, _y, 0, 0, POS)
        edit = dialog.getControl("edit")
        edit.setSelection(uno.createUnoStruct("com.sun.star.awt.Selection", 0, len(str(default))))
        edit.setFocus()
        ret = edit.getModel().Text if dialog.execute() else ""
        dialog.dispose()
        return ret

    def _run_edit_selection(self, text, text_range, user_input):
        original_text = text_range.getString()
        if len(original_text.strip()) == 0:
            original_text = ""

        wait_dialog = {"dialog": None, "bg": None, "toolkit": None}
        wait_buffer = {"text": "Contacte MIrAI..."}
        cancelled = {"value": False}
        def _show_wait():
            try:
                from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
                WIDTH = 420
                BUTTON_HEIGHT = 26
                HORI_MARGIN = VERT_MARGIN = 8
                LABEL_HEIGHT = 18
                VERT_SEP = 8
                BG_HEIGHT = 96
                HEIGHT = VERT_MARGIN * 2 + LABEL_HEIGHT + VERT_SEP + BG_HEIGHT + VERT_SEP + BUTTON_HEIGHT
                ctx = uno.getComponentContext()
                def create(name):
                    return ctx.getServiceManager().createInstanceWithContext(name, ctx)
                dialog = create("com.sun.star.awt.UnoControlDialog")
                dialog_model = create("com.sun.star.awt.UnoControlDialogModel")
                dialog.setModel(dialog_model)
                dialog.setVisible(False)
                dialog.setTitle("MIrAI")
                dialog.setPosSize(0, 0, WIDTH, HEIGHT, SIZE)
                try:
                    dialog_model.BackgroundColor = 0xE6F7E6
                except Exception:
                    pass
                def add(name, type, x_, y_, width_, height_, props):
                    try:
                        model = dialog_model.createInstance("com.sun.star.awt.UnoControl" + type + "Model")
                        dialog_model.insertByName(name, model)
                        control = dialog.getControl(name)
                        control.setPosSize(x_, y_, width_, height_, POSSIZE)
                        for key, value in props.items():
                            try:
                                setattr(model, key, value)
                            except Exception:
                                pass
                        return control
                    except Exception:
                        return None
                add("label_wait", "FixedText", HORI_MARGIN, VERT_MARGIN,
                    WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
                    {"Label": "MIrAI réfléchi...", "NoLabel": True})
                bg_y = VERT_MARGIN + LABEL_HEIGHT + VERT_SEP
                bg = add("edit_wait_bg", "Edit", HORI_MARGIN, bg_y,
                    WIDTH - HORI_MARGIN * 2, BG_HEIGHT,
                    {"Text": wait_buffer["text"], "MultiLine": True, "ReadOnly": True})
                if bg:
                    try:
                        bg.getModel().BackgroundColor = 0xE6F7E6
                        bg.getModel().TextColor = 0x2F5D2F
                        bg.getModel().FontHeight = 6
                        bg.getModel().Border = 0
                    except Exception:
                        pass
                btn_cancel_y = bg_y + BG_HEIGHT + VERT_SEP
                CANCEL_BTN_WIDTH = 100
                btn_cancel_wait = add(
                    "btn_cancel_wait", "Button",
                    WIDTH // 2 - CANCEL_BTN_WIDTH // 2, btn_cancel_y,
                    CANCEL_BTN_WIDTH, BUTTON_HEIGHT,
                    {"Label": "Annuler"}
                )

                class CancelWaitListener(unohelper.Base, XActionListener):
                    def actionPerformed(self, event):
                        cancelled["value"] = True
                    def disposing(self, event):
                        return

                if btn_cancel_wait:
                    try:
                        btn_cancel_wait.addActionListener(CancelWaitListener())
                    except Exception:
                        pass

                frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
                window = frame.getContainerWindow() if frame else None
                toolkit = create("com.sun.star.awt.Toolkit")
                dialog.createPeer(toolkit, window)
                if window:
                    ps = window.getPosSize()
                    _x = ps.Width / 2 - WIDTH / 2 + int(ps.Width * 0.15)
                    _y = ps.Height / 2 - HEIGHT / 2
                    dialog.setPosSize(_x, _y, 0, 0, POS)
                dialog.setVisible(True)
                wait_dialog["dialog"] = dialog
                wait_dialog["bg"] = bg
                wait_dialog["toolkit"] = toolkit
                if bg:
                    try:
                        bg.getModel().Text = wait_buffer["text"]
                    except Exception:
                        pass
                try:
                    toolkit.processEventsToIdle()
                except Exception:
                    pass
                time.sleep(0.05)
            except Exception:
                pass

        def _update_wait(chunk_text):
            if not wait_dialog["bg"]:
                return
            try:
                wait_buffer["text"] += chunk_text
                if len(wait_buffer["text"]) > 1200:
                    wait_buffer["text"] = wait_buffer["text"][-1200:]
                wait_dialog["bg"].getModel().Text = wait_buffer["text"]
                if wait_dialog.get("toolkit"):
                    wait_dialog["toolkit"].processEventsToIdle()
                time.sleep(0.01)
            except Exception:
                pass

        def _close_wait():
            try:
                if wait_dialog["dialog"]:
                    wait_dialog["dialog"].setVisible(False)
                    wait_dialog["dialog"].dispose()
            except Exception:
                pass

        try:
            path_settings = self.sm.createInstanceWithContext('com.sun.star.util.PathSettings', self.ctx)
            user_config_path = getattr(path_settings, "UserConfig")
            if user_config_path.startswith('file://'):
                user_config_path = str(uno.fileUrlToSystemPath(user_config_path))
            prompt_log_path = os.path.join(user_config_path, "prompt.txt")
            with open(prompt_log_path, "a", encoding="utf-8") as f:
                f.write(user_input.strip() + "\n")
                f.write("-" * 40 + "\n")
        except Exception:
            pass

        system_prompt = self.get_config(
            "edit_selection_system_prompt",
            "Tu es un éditeur de texte. Tu dois appliquer les instructions sans poser de questions. Interdiction totale de poser une question, de demander des précisions ou de commenter. Tu dois produire uniquement le texte modifié, sans préambule, sans explication et sans guillemets. Ne répète pas les instructions."
        )
        api_type = str(self.get_config("api_type", "completions")).lower()

        # If selection is empty, insert at the current cursor position
        try:
            if text_range.getString() == "":
                model = self.ctx.ServiceManager.createInstanceWithContext(
                    "com.sun.star.frame.Desktop", self.ctx
                ).getCurrentComponent()
                controller = model.getCurrentController() if model else None
                view_cursor = controller.getViewCursor() if controller else None
                if view_cursor:
                    text_range = view_cursor
        except Exception:
            pass

        accumulated_text = ""
        stop_phrases = [
            "end of document",
            "end of the document",
            "[END]",
            "---END---"
        ]
        question_patterns = [
            "would you like",
            "do you want",
            "should i",
            "can i help",
            "what would you prefer",
            "could you clarify",
            "please specify",
            "here is",
            "here's",
            "i've made",
            "i have made",
            "voulez-vous",
            "souhaitez-vous",
            "aimeriez-vous",
            "préférez-vous",
            "dois-je",
            "devrais-je",
            "puis-je",
            "est-ce que vous",
            "pouvez-vous préciser",
            "pourriez-vous clarifier",
            "veuillez préciser",
            "voici",
            "voilà",
            "j'ai modifié",
            "j'ai changé",
            "j'ai fait",
            "que souhaitez",
            "quelle version",
            "quel style"
        ]

        aborted = {"value": False}

        def append_text(chunk_text):
            nonlocal accumulated_text
            if cancelled["value"]:
                return
            accumulated_text += chunk_text
            _update_wait(chunk_text)
            lower_text = accumulated_text.lower()
            for pattern in question_patterns:
                if pattern in lower_text:
                    aborted["value"] = True
                    return
            for stop_phrase in stop_phrases:
                if stop_phrase.lower() in accumulated_text.lower():
                    pos = accumulated_text.lower().find(stop_phrase.lower())
                    accumulated_text = accumulated_text[:pos].rstrip()
                    return

        def _edit_segment(segment_text):
            prompt = """ORIGINAL VERSION:
""" + segment_text + """

INSTRUCTIONS: """ + user_input + """

IMPORTANT RULES:
- Do NOT ask any questions
- Do NOT add explanations or comments
- Do NOT include phrases like "Here is..." or "I've made..."
- Output ONLY the edited text directly
- Start immediately with the edited content
- Edit ONLY the ORIGINAL VERSION. Do not add any extra text.

EDITED VERSION:
"""
            max_tokens = len(segment_text) + self.get_config("edit_selection_max_new_tokens", 15000)
            request = self.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)
            return request

        try:
            text_obj = text_range.getText()
            start = text_range.getStart()
            end = text_range.getEnd()
            old_len = len(original_text)
            base_char_style = ""
            base_para_style = ""
            try:
                base_char_style = text_range.getPropertyValue("CharStyleName")
            except Exception:
                pass
            try:
                base_para_style = text_range.getPropertyValue("ParaStyleName")
            except Exception:
                pass

            # Edit selection as a single block (no segmentation)
            _show_wait()
            request = _edit_segment(original_text)
            self.stream_request(request, api_type, append_text)
            _close_wait()
            if cancelled["value"]:
                return
            if aborted["value"]:
                self._show_message(
                    "Modification",
                    "Le modèle a tenté de poser une question. Reformulez la demande de manière plus directive."
                )
                return
            if not accumulated_text.strip():
                self._show_message(
                    "Modification",
                    "Aucune réponse reçue du modèle. Vérifiez le token et réessayez."
                )
                return

            new_len = len(accumulated_text)

            log_to_file(f"EditSelection insert: old_len={old_len} new_len={new_len} segments=1")
            # Delete original selection (if any)
            delete_cursor = text_obj.createTextCursorByRange(start)
            delete_cursor.gotoRange(end, True)
            delete_cursor.setString("")
            insert_point = delete_cursor.getStart()

            # Insert new text at cursor position
            insert_cursor = text_obj.createTextCursorByRange(insert_point)
            if original_text == "":
                try:
                    insert_cursor.setPropertyValue("CharStyleName", "Default")
                except Exception:
                    pass
                try:
                    insert_cursor.setPropertyValue("ParaStyleName", "Standard")
                except Exception:
                    pass
            text_obj.insertString(insert_cursor, accumulated_text, False)
            log_to_file("EditSelection insert: done")

            # Reapply base styles to the whole inserted block
            if old_len > 0 and new_len > 0:
                try:
                    style_cursor = text_obj.createTextCursorByRange(insert_point)
                    style_cursor.goRight(new_len, True)
                    if base_char_style:
                        style_cursor.setPropertyValue("CharStyleName", base_char_style)
                    if base_para_style:
                        style_cursor.setPropertyValue("ParaStyleName", base_para_style)
                except Exception:
                    pass

            # Reselect inserted text
            try:
                model = self.ctx.ServiceManager.createInstanceWithContext(
                    "com.sun.star.frame.Desktop", self.ctx
                ).getCurrentComponent()
                controller = model.getCurrentController() if model else None
                if controller:
                    sel_cursor = text_obj.createTextCursorByRange(insert_point)
                    sel_cursor.goRight(new_len, True)
                    controller.select(sel_cursor)
            except Exception:
                pass
        except Exception as e:
            log_to_file(f"EditSelection insert failed: {str(e)}")

    def _show_edit_selection_dialog(self, text, text_range):
        if self._edit_dialog:
            try:
                self._edit_dialog.setVisible(True)
            except Exception:
                pass
            return

        current_selection = {"range": text_range}

        WIDTH = 720
        HORI_MARGIN = VERT_MARGIN = 8
        BUTTON_WIDTH = 130
        BUTTON_HEIGHT = 26
        HORI_SEP = VERT_SEP = 8
        LABEL_HEIGHT = 22
        EDIT_HEIGHT = 120
        SUGGEST_LABEL_HEIGHT = 16
        SUGGEST_LIST_HEIGHT = 70
        SUGGEST_BTN_WIDTH = int((WIDTH - HORI_MARGIN * 2 - HORI_SEP) / 2)
        HEIGHT = (
            VERT_MARGIN * 2
            + LABEL_HEIGHT + VERT_SEP
            + EDIT_HEIGHT + VERT_SEP
            + BUTTON_HEIGHT + VERT_SEP
            + SUGGEST_LABEL_HEIGHT + VERT_SEP
            + SUGGEST_LIST_HEIGHT + VERT_SEP
            + BUTTON_HEIGHT
        )

        from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
        ctx = uno.getComponentContext()
        def create(name):
            return ctx.getServiceManager().createInstanceWithContext(name, ctx)

        dialog = create("com.sun.star.awt.UnoControlDialog")
        dialog_model = create("com.sun.star.awt.UnoControlDialogModel")
        dialog.setModel(dialog_model)
        dialog.setVisible(False)
        dialog.setTitle("Modifier la sélection")
        dialog.setPosSize(0, 0, WIDTH, HEIGHT, SIZE)
        try:
            dialog_model.BackgroundColor = 0xFFFFFF
        except Exception:
            pass
        try:
            dialog_model.AlwaysOnTop = True
        except Exception:
            pass
        try:
            dialog_model.Sizeable = True
        except Exception:
            pass
        try:
            dialog_model.Closeable = True
        except Exception:
            pass

        def add(name, type, x_, y_, width_, height_, props):
            try:
                model = dialog_model.createInstance("com.sun.star.awt.UnoControl" + type + "Model")
            except Exception as e:
                log_to_file(f"Dialog control type unsupported: name={name} type={type} error={str(e)}")
                return None
            try:
                dialog_model.insertByName(name, model)
            except Exception as e:
                log_to_file(f"Dialog insert failed: name={name} type={type} error={str(e)}")
                return None
            control = dialog.getControl(name)
            try:
                control.setPosSize(x_, y_, width_, height_, POSSIZE)
            except Exception as e:
                log_to_file(f"Dialog size failed: name={name} type={type} error={str(e)}")
            for key, value in props.items():
                try:
                    setattr(model, key, value)
                except Exception as e:
                    log_to_file(f"Dialog prop unsupported: control={name} type={type} prop={key} error={str(e)}")
            return control

        def _refresh_selection_range():
            try:
                desktop = self.ctx.ServiceManager.createInstanceWithContext(
                    "com.sun.star.frame.Desktop", self.ctx)
                model = desktop.getCurrentComponent()
                if model is None or not hasattr(model, "Text"):
                    return
                selection = model.CurrentController.getSelection()
                if selection and selection.getCount() > 0:
                    current_selection["range"] = selection.getByIndex(0)
            except Exception:
                pass

        def _has_multiple_styles():
            try:
                selected = current_selection["range"].getString()
            except Exception:
                return False
            if not selected:
                return False
            try:
                text_obj = current_selection["range"].getText()
                cursor = text_obj.createTextCursorByRange(current_selection["range"].getStart())
                cursor.goRight(1, True)
                try:
                    base_char = cursor.getPropertyValue("CharStyleName")
                except Exception:
                    base_char = ""
                cursor.collapseToEnd()
                max_scan = min(len(selected), 2000)
                for _ in range(max_scan):
                    cursor.goRight(1, True)
                    try:
                        char_style = cursor.getPropertyValue("CharStyleName")
                    except Exception:
                        char_style = base_char
                    cursor.collapseToEnd()
                    if char_style != base_char:
                        return True
            except Exception:
                return False
            return False

        def _selection_info():
            _refresh_selection_range()
            try:
                selected = current_selection["range"].getString()
            except Exception:
                selected = ""
            if not selected:
                return "Sélectionner une portion de texte à modifier... ou placer le curseur à l'emplacement où vous souhaitez insérer le nouveau texte"
            snippet = " ".join(selected.split())
            max_len = 90
            if len(snippet) > max_len:
                head_len = (max_len - 9) // 2
                tail_len = max_len - 9 - head_len
                head = snippet[:head_len].rsplit(" ", 1)[0] or snippet[:head_len]
                tail = snippet[-tail_len:].split(" ", 1)[-1] or snippet[-tail_len:]
                snippet = head.rstrip() + " ... ... ... " + tail.lstrip()
            warning = " ⚠ plusieurs styles fusionnés" if _has_multiple_styles() else ""
            return f"Sélection {snippet}{warning}"

        PROMPT_BTN_WIDTH = 150
        label_max_width = WIDTH - HORI_MARGIN * 2 - PROMPT_BTN_WIDTH - HORI_SEP
        add("label_edit", "FixedText", HORI_MARGIN, VERT_MARGIN, label_max_width, LABEL_HEIGHT,
            {"Label": "Saisissez votre prompt d'édition :", "NoLabel": True})
        OFFSET_BELOW = 20
        selection_width = label_max_width
        label_selection_control = add(
            "label_selection_info",
            "FixedText",
            HORI_MARGIN,
            VERT_MARGIN + LABEL_HEIGHT - 6 + OFFSET_BELOW,
            selection_width,
            SUGGEST_LABEL_HEIGHT,
            {"Label": _selection_info(), "NoLabel": True, "FontHeight": 8, "TextColor": 0x777777}
        )
        if label_selection_control:
            try:
                if _has_multiple_styles():
                    label_selection_control.getModel().TextColor = 0xFF8800
                else:
                    label_selection_control.getModel().TextColor = 0x777777
            except Exception:
                pass
        edit_control = add("edit_prompt", "Edit", HORI_MARGIN, VERT_MARGIN + LABEL_HEIGHT + VERT_SEP + OFFSET_BELOW,
            WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT, {"Text": "", "MultiLine": True})
        if edit_control:
            try:
                edit_control.getModel().BackgroundColor = 0xF2F2F2
            except Exception:
                pass

        send_y = VERT_MARGIN + LABEL_HEIGHT + VERT_SEP + OFFSET_BELOW + EDIT_HEIGHT + VERT_SEP
        btn_send = add(
            "btn_send",
            "Button",
            WIDTH - HORI_MARGIN - BUTTON_WIDTH,
            send_y,
            BUTTON_WIDTH,
            BUTTON_HEIGHT,
            {"Label": "Envoyer 🤖✨"}
        )

        suggest_y = send_y + BUTTON_HEIGHT + VERT_SEP
        original_suggest_y = suggest_y - OFFSET_BELOW
        add(
            "line_suggestions",
            "FixedLine",
            HORI_MARGIN,
            suggest_y - (VERT_SEP // 2),
            WIDTH - HORI_MARGIN * 2,
            6,
            {}
        )
        add(
            "label_suggestions",
            "FixedText",
            HORI_MARGIN,
            suggest_y + 5,
            WIDTH - HORI_MARGIN * 2,
            SUGGEST_LABEL_HEIGHT,
            {"Label": "Suggestion de prompts", "NoLabel": True, "FontHeight": 8}
        )
        suggest_y += SUGGEST_LABEL_HEIGHT + VERT_SEP + 5

        suggest_list_height = max(10, SUGGEST_LIST_HEIGHT - OFFSET_BELOW)
        suggestions_list = add(
            "list_suggestions",
            "ListBox",
            HORI_MARGIN,
            suggest_y + 5,
            WIDTH - HORI_MARGIN * 2,
            suggest_list_height,
            {"Dropdown": True}
        )
        suggest_btn_y = original_suggest_y + SUGGEST_LABEL_HEIGHT + VERT_SEP + SUGGEST_LIST_HEIGHT + VERT_SEP - 5
        btn_regen_suggestions = add(
            "btn_regen_suggestions",
            "Button",
            HORI_MARGIN,
            suggest_btn_y,
            WIDTH - HORI_MARGIN * 2,
            BUTTON_HEIGHT,
            {"Label": "🔁 Nouveaux"}
        )

        link_control = add(
            "link_prompt_file",
            "Button",
            WIDTH - HORI_MARGIN - PROMPT_BTN_WIDTH,
            VERT_MARGIN + 4,
            PROMPT_BTN_WIDTH,
            LABEL_HEIGHT,
            {"Label": "📄 Ouvrir prompt", "FontHeight": 8, "Tabstop": True}
        )
        if link_control is None:
            log_to_file("Open prompt button not created")

        frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
        window = frame.getContainerWindow() if frame else None
        dialog.createPeer(create("com.sun.star.awt.Toolkit"), window)
        if window:
            ps = window.getPosSize()
            saved_x = self.get_config("edit_dialog_x", None)
            saved_y = self.get_config("edit_dialog_y", None)
            if isinstance(saved_x, (int, float)) and isinstance(saved_y, (int, float)):
                _x = int(saved_x)
                _y = int(saved_y)
            else:
                _x = ps.Width / 2 - WIDTH / 2
                _y = ps.Height / 2 - HEIGHT / 2
            dialog.setPosSize(_x, _y, 0, 0, POS)

        def _extract_snippet(text_value, limit=180):
            value = " ".join((text_value or "").split())
            return value[:limit].rstrip()

        def _generate_prompt_suggestions(text_value):
            prompts = [
                "Corrige l’orthographe et la grammaire.",
                "Reformule en style formel et concis.",
                "Simplifie pour un public non spécialiste.",
                "Rends le texte plus clair avec des phrases courtes.",
                "Transforme en style administratif.",
                "Rends la formulation plus positive et professionnelle.",
                "Réorganise pour améliorer la logique et la structure.",
                "Supprime les répétitions et les tournures lourdes.",
                "Rends le texte plus convaincant sans changer le sens.",
                "Résume le contenu en gardant l’essentiel.",
            ]
            return prompts

        def _load_suggestions():
            try:
                _refresh_selection_range()
                suggestions = _generate_prompt_suggestions(current_selection["range"].getString())
            except Exception:
                suggestions = []
            if suggestions_list:
                try:
                    suggestions_list.removeItems(0, suggestions_list.getItemCount())
                except Exception:
                    pass
                if suggestions:
                    try:
                        suggestions_list.addItems(tuple(suggestions), 0)
                        suggestions_list.selectItemPos(0, True)
                    except Exception:
                        pass

        _load_suggestions()

        def _refresh_selection_label():
            if label_selection_control:
                try:
                    label_selection_control.getModel().Label = _selection_info()
                    if _has_multiple_styles():
                        label_selection_control.getModel().TextColor = 0xFF8800
                    else:
                        label_selection_control.getModel().TextColor = 0x777777
                except Exception:
                    pass

        class SuggestionsItemListener(unohelper.Base, XItemListener):
            def __init__(self, outer):
                self.outer = outer
            def itemStateChanged(self, event):
                try:
                    suggestion = suggestions_list.getSelectedItem() if suggestions_list else ""
                    if suggestion:
                        edit_control.getModel().Text = suggestion
                except Exception:
                    pass
            def disposing(self, event):
                return

        class EditDialogListener(unohelper.Base, XActionListener):
            def actionPerformed(self, event):
                source = getattr(event, "Source", None)
                if source == btn_send:
                    _refresh_selection_range()
                    try:
                        user_input = edit_control.getModel().Text.strip()
                    except Exception:
                        user_input = ""
                    if not user_input:
                        return
                    try:
                        self.outer._run_edit_selection(text, current_selection["range"], user_input)
                    except Exception as e:
                        log_to_file(f"EditSelection dialog failed: {str(e)}")
                elif source == btn_regen_suggestions:
                    _refresh_selection_label()
                    _load_suggestions()

            def __init__(self, outer):
                self.outer = outer

            def disposing(self, event):
                return

        listener = EditDialogListener(self)
        if btn_send:
            try:
                btn_send.addActionListener(listener)
            except Exception:
                pass
        if btn_regen_suggestions:
            try:
                btn_regen_suggestions.addActionListener(listener)
            except Exception:
                pass
        if suggestions_list:
            try:
                self._suggestions_item_listener = SuggestionsItemListener(self)
                suggestions_list.addItemListener(self._suggestions_item_listener)
            except Exception:
                pass

        class EditDialogWindowListener(unohelper.Base, XWindowListener):
            def __init__(self, outer):
                self.outer = outer
            def _save_pos(self):
                try:
                    ps = dialog.getPosSize()
                    self.outer.set_config("edit_dialog_x", int(ps.X))
                    self.outer.set_config("edit_dialog_y", int(ps.Y))
                except Exception:
                    pass
            def windowClosing(self, event):
                try:
                    self._save_pos()
                    dialog.setVisible(False)
                    dialog.dispose()
                except Exception:
                    pass
                self.outer._edit_dialog = None
            def windowOpened(self, event):
                return
            def windowClosed(self, event):
                return
            def windowMinimized(self, event):
                return
            def windowNormalized(self, event):
                return
            def windowActivated(self, event):
                _refresh_selection_label()
            def windowDeactivated(self, event):
                return
            def disposing(self, event):
                return

        class EditDialogTopWindowListener(unohelper.Base, XTopWindowListener):
            def __init__(self, outer):
                self.outer = outer
            def _save_pos(self):
                try:
                    ps = dialog.getPosSize()
                    self.outer.set_config("edit_dialog_x", int(ps.X))
                    self.outer.set_config("edit_dialog_y", int(ps.Y))
                except Exception:
                    pass
            def windowClosing(self, event):
                try:
                    self._save_pos()
                    dialog.setVisible(False)
                    dialog.dispose()
                except Exception:
                    pass
                self.outer._edit_dialog = None
            def windowOpened(self, event):
                return
            def windowClosed(self, event):
                return
            def windowMinimized(self, event):
                return
            def windowNormalized(self, event):
                return
            def windowActivated(self, event):
                _refresh_selection_label()
            def windowDeactivated(self, event):
                return
            def disposing(self, event):
                return

        try:
            dialog.addWindowListener(EditDialogWindowListener(self))
        except Exception:
            pass
        try:
            peer = dialog.getPeer()
            if peer:
                peer.addTopWindowListener(EditDialogTopWindowListener(self))
        except Exception:
            pass

        class PromptLinkActionListener(unohelper.Base, XActionListener):
            def __init__(self, outer):
                self.outer = outer
            def actionPerformed(self, event):
                try:
                    path_settings = self.outer.sm.createInstanceWithContext(
                        "com.sun.star.util.PathSettings", self.outer.ctx
                    )
                    user_config_path = getattr(path_settings, "UserConfig")
                    if user_config_path.startswith("file://") or user_config_path.startswith("file:"):
                        user_config_path = str(uno.fileUrlToSystemPath(user_config_path))
                    prompt_log_path = os.path.join(user_config_path, "prompt.txt")
                    if not os.path.exists(prompt_log_path):
                        with open(prompt_log_path, "a", encoding="utf-8") as f:
                            f.write("")
                    prompt_url = uno.systemPathToFileUrl(prompt_log_path)
                    shell = self.outer.ctx.getServiceManager().createInstanceWithContext(
                        "com.sun.star.system.SystemShellExecute", self.outer.ctx
                    )
                    shell.execute(prompt_url, "", 0)
                except Exception as e:
                    log_to_file(f"Failed to open prompt.txt: {str(e)}")
            def disposing(self, event):
                return

        if link_control:
            try:
                self._prompt_link_action_listener = PromptLinkActionListener(self)
                link_control.addActionListener(self._prompt_link_action_listener)
            except Exception:
                pass

        dialog.setVisible(True)
        self._edit_dialog = dialog

        def _selection_refresh_loop():
            while True:
                try:
                    if self._edit_dialog is None or not dialog.isVisible():
                        break
                except Exception:
                    break
                _refresh_selection_label()
                time.sleep(3)

        try:
            threading.Thread(target=_selection_refresh_loop, daemon=True).start()
        except Exception:
            pass

    def credentials_box(self, title="Device Management", login_label="Login", password_label="Mot de passe"):
        """Dialog with login + password and a show/hide toggle."""
        WIDTH = 520
        HORI_MARGIN = VERT_MARGIN = 8
        BUTTON_WIDTH = 100
        BUTTON_HEIGHT = 26
        HORI_SEP = VERT_SEP = 8
        LABEL_HEIGHT = 18
        EDIT_HEIGHT = 24
        TOGGLE_WIDTH = 90
        HEIGHT = VERT_MARGIN * 2 + (LABEL_HEIGHT + EDIT_HEIGHT + VERT_SEP) * 2 + BUTTON_HEIGHT + VERT_SEP * 2
        import uno
        from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
        from com.sun.star.awt.PushButtonType import OK, CANCEL
        ctx = uno.getComponentContext()
        def create(name):
            return ctx.getServiceManager().createInstanceWithContext(name, ctx)
        dialog = create("com.sun.star.awt.UnoControlDialog")
        dialog_model = create("com.sun.star.awt.UnoControlDialogModel")
        dialog.setModel(dialog_model)
        try:
            dialog_model.BackgroundColor = 0xFFFFFF
        except Exception:
            pass
        dialog.setVisible(False)
        dialog.setTitle(title)
        dialog.setPosSize(0, 0, WIDTH, HEIGHT, SIZE)

        def add(name, type, x_, y_, width_, height_, props):
            try:
                model = dialog_model.createInstance("com.sun.star.awt.UnoControl" + type + "Model")
            except Exception as e:
                log_to_file(f"Dialog control type unsupported: name={name} type={type} error={str(e)}")
                return None
            try:
                dialog_model.insertByName(name, model)
            except Exception as e:
                log_to_file(f"Dialog insert failed: name={name} type={type} error={str(e)}")
                return None
            control = dialog.getControl(name)
            try:
                control.setPosSize(x_, y_, width_, height_, POSSIZE)
            except Exception as e:
                log_to_file(f"Dialog size failed: name={name} type={type} error={str(e)}")
            for key, value in props.items():
                try:
                    setattr(model, key, value)
                except Exception as e:
                    log_to_file(f"Dialog prop unsupported: control={name} type={type} prop={key} error={str(e)}")
            return control

        current_y = VERT_MARGIN
        add("label_login", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": str(login_label), "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP
        add("edit_login", "Edit", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT, {"Text": ""})
        current_y += EDIT_HEIGHT + VERT_SEP

        add("label_password", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": str(password_label), "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP
        password_width = WIDTH - HORI_MARGIN * 2 - TOGGLE_WIDTH - HORI_SEP
        add("edit_password", "Edit", HORI_MARGIN, current_y, password_width, EDIT_HEIGHT, {"Text": "", "EchoChar": ord("*")})
        add("btn_toggle", "Button", HORI_MARGIN + password_width + HORI_SEP, current_y,
            TOGGLE_WIDTH, EDIT_HEIGHT, {"Label": "Afficher"})

        current_y += EDIT_HEIGHT + VERT_SEP * 2
        add("btn_ok", "Button", HORI_MARGIN, current_y, BUTTON_WIDTH, BUTTON_HEIGHT,
            {"PushButtonType": OK, "DefaultButton": True})
        add("btn_cancel", "Button", HORI_MARGIN + BUTTON_WIDTH + HORI_SEP, current_y,
            BUTTON_WIDTH, BUTTON_HEIGHT, {"PushButtonType": CANCEL, "Label": "Annuler"})

        frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
        window = frame.getContainerWindow() if frame else None
        dialog.createPeer(create("com.sun.star.awt.Toolkit"), window)
        if window:
            ps = window.getPosSize()
            _x = ps.Width / 2 - WIDTH / 2
            _y = ps.Height / 2 - HEIGHT / 2
            dialog.setPosSize(_x, _y, 0, 0, POS)

        edit_login = dialog.getControl("edit_login")
        edit_password = dialog.getControl("edit_password")
        btn_toggle = dialog.getControl("btn_toggle")
        is_masked = {"value": True}

        class ToggleListener(unohelper.Base, XActionListener):
            def actionPerformed(self, event):
                is_masked["value"] = not is_masked["value"]
                try:
                    edit_password.getModel().EchoChar = ord("*") if is_masked["value"] else 0
                except Exception:
                    pass
                try:
                    btn_toggle.getModel().Label = "Afficher" if is_masked["value"] else "Masquer"
                except Exception:
                    pass
            def disposing(self, event):
                return

        try:
            btn_toggle.addActionListener(ToggleListener())
        except Exception:
            pass

        edit_login.setFocus()
        ok = dialog.execute()
        username = edit_login.getModel().Text.strip() if ok else ""
        password = edit_password.getModel().Text if ok else ""
        dialog.dispose()
        return username, password

    def settings_box(self,title="", x=None, y=None):
        """ Settings dialog with configurable backend options """
        WIDTH = 720
        HORI_MARGIN = VERT_MARGIN = 10
        BUTTON_WIDTH = 140
        BUTTON_HEIGHT = 32
        HORI_SEP = 8
        VERT_SEP = 6
        LABEL_HEIGHT = 22
        EDIT_HEIGHT = 24
        IMAGE_HEIGHT = 132
        EXTRA_BOTTOM = 60
        DESC_HEIGHT = EDIT_HEIGHT * 2
        TEST_ROW_HEIGHT = BUTTON_HEIGHT + VERT_SEP
        import uno
        from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
        from com.sun.star.awt.PushButtonType import OK, CANCEL
        from com.sun.star.util.MeasureUnit import TWIP
        ctx = uno.getComponentContext()
        def create(name):
            return ctx.getServiceManager().createInstanceWithContext(name, ctx)
        dialog = create("com.sun.star.awt.UnoControlDialog")
        dialog_model = create("com.sun.star.awt.UnoControlDialogModel")
        dialog.setModel(dialog_model)
        dialog.setVisible(False)
        dialog.setTitle(title)

        def _mask_value(value):
            try:
                text = str(value or "")
            except Exception:
                return ""
            if not text:
                return ""
            if len(text) <= 4:
                return "*" * len(text)
            return f"{text[:2]}***{text[-2:]}"

        def _log_launch_config():
            config_file_path = "unknown"
            package_config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'config.default.json'))
            user_exists = False
            user_size = -1
            package_exists = os.path.exists(package_config_path)
            package_size = os.path.getsize(package_config_path) if package_exists else -1
            try:
                path_settings = self.sm.createInstanceWithContext('com.sun.star.util.PathSettings', self.ctx)
                user_config_path = getattr(path_settings, "UserConfig")
                if user_config_path.startswith('file://'):
                    user_config_path = str(uno.fileUrlToSystemPath(user_config_path))
                config_file_path = os.path.join(user_config_path, "config.json")
                user_exists = os.path.exists(config_file_path)
                user_size = os.path.getsize(config_file_path) if user_exists else -1
            except Exception:
                pass

            system_prompt = self._get_config_from_file("systemPrompt", "")
            log_to_file(
                "Config loaded "
                f"path={config_file_path} user_exists={user_exists} user_size={user_size} "
                f"package_path={package_config_path} package_exists={package_exists} package_size={package_size} "
                f"llm_base_urls={self._get_config_from_file('llm_base_urls','')} "
                f"llm_api_tokens={_mask_value(self._get_config_from_file('llm_api_tokens',''))} "
                f"authHeaderName={self._get_config_from_file('authHeaderName','')} "
                f"authHeaderPrefix={self._get_config_from_file('authHeaderPrefix','')} "
                f"keycloakIssuerUrl={self._get_config_from_file('keycloakIssuerUrl','')} "
                f"keycloakRealm={self._get_config_from_file('keycloakRealm','')} "
                f"keycloakClientId={self._get_config_from_file('keycloakClientId','')} "
                f"systemPromptLen={len(str(system_prompt))} "
                f"telemetryEndpoint={self._get_config_from_file('telemetryEndpoint','')} "
                f"telemetryAuthorizationType={self._get_config_from_file('telemetryAuthorizationType','')} "
                f"telemetryKey={_mask_value(self._get_config_from_file('telemetryKey',''))} "
                f"bootstrap_url={self._get_config_from_file('bootstrap_url','')} "
                f"config_path={self._get_config_from_file('config_path','')} "
                f"enabled={self._get_config_from_file('enabled', False)} "
                f"llm_default_models={self._get_config_from_file('llm_default_models','')}"
            )

        _log_launch_config()

        def show_wait_dialog():
            wait_width = 260
            wait_height = 80
            wait_dialog = create("com.sun.star.awt.UnoControlDialog")
            wait_model = create("com.sun.star.awt.UnoControlDialogModel")
            wait_dialog.setModel(wait_model)
            wait_dialog.setVisible(False)
            wait_dialog.setTitle("")
            wait_dialog.setPosSize(0, 0, wait_width, wait_height, SIZE)

            try:
                label_model = wait_model.createInstance("com.sun.star.awt.UnoControlFixedTextModel")
                wait_model.insertByName("wait_label", label_model)
                label_model.Label = "Contacte MIrAI..."
                label_model.NoLabel = True
                wait_label = wait_dialog.getControl("wait_label")
                wait_label.setPosSize(10, 20, wait_width - 20, 20, POSSIZE)
            except Exception:
                wait_label = None

            frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
            window = frame.getContainerWindow() if frame else None
            toolkit = create("com.sun.star.awt.Toolkit")
            wait_dialog.createPeer(toolkit, window)
            if window:
                ps = window.getPosSize()
                _x = ps.Width / 2 - wait_width / 2
                _y = ps.Height / 2 - wait_height / 2
                wait_dialog.setPosSize(_x, _y, 0, 0, POS)
            wait_dialog.setVisible(True)
            return wait_dialog, wait_label, toolkit

        def animate_wait(label, toolkit, steps=3, delay=0.2):
            if not label or not toolkit:
                return
            for i in range(steps):
                try:
                    dots = "." * ((i % 3) + 1)
                    label.getModel().Label = f"Contacte MIrAI{dots}"
                    toolkit.processEventsToIdle()
                except Exception:
                    pass
                time.sleep(delay)

        wait_dialog, wait_label, wait_toolkit = show_wait_dialog()
        try:
            animate_wait(wait_label, wait_toolkit, steps=4, delay=0.15)
            endpoint_value = str(self.get_config("llm_base_urls","http://127.0.0.1:5000/api"))
            api_key_value = str(self.get_config("llm_api_tokens",""))
            log_to_file(f"Settings open: llm_api_tokens length={len(api_key_value)}")
            current_model = str(self.get_config("llm_default_models","")).strip()
            is_openwebui = True
            models, model_descriptions = self._fetch_models_info(endpoint_value, api_key_value, is_openwebui)
            if current_model and current_model not in models:
                models = [current_model] + models
            if not models and current_model:
                models = [current_model]
            log_to_file(f"Models loaded: {len(models)} -> {models}")
        finally:
            try:
                wait_dialog.setVisible(False)
                wait_dialog.dispose()
            except Exception:
                pass

        field_specs = [
            {"name": "endpoint", "label": "OWUI Endpoint:", "value": endpoint_value, "type": "text"},
            {"name": "api_key", "label": "Token OWUI:", "value": api_key_value, "type": "password"},
            {"name": "model", "label": "Model:", "value": current_model, "type": "list", "items": models},
        ]

        num_fields = len(field_specs)
        total_field_height = num_fields * (LABEL_HEIGHT + EDIT_HEIGHT + VERT_SEP * 2) + TEST_ROW_HEIGHT + (BUTTON_HEIGHT - LABEL_HEIGHT)
        desc_block_height = LABEL_HEIGHT + VERT_SEP + DESC_HEIGHT + VERT_SEP * 2
        HEIGHT = VERT_MARGIN * 2 + IMAGE_HEIGHT + VERT_SEP + total_field_height + desc_block_height + LABEL_HEIGHT + BUTTON_HEIGHT * 2 + VERT_SEP * 6 + EXTRA_BOTTOM
        dialog.setPosSize(0, 0, WIDTH, HEIGHT, SIZE)

        def add(name, type, x_, y_, width_, height_, props):
            try:
                model = dialog_model.createInstance("com.sun.star.awt.UnoControl" + type + "Model")
            except Exception as e:
                log_to_file(f"Dialog control type unsupported: name={name} type={type} error={str(e)}")
                return None
            try:
                dialog_model.insertByName(name, model)
            except Exception as e:
                log_to_file(f"Dialog insert failed: name={name} type={type} error={str(e)}")
                return None
            control = dialog.getControl(name)
            try:
                control.setPosSize(x_, y_, width_, height_, POSSIZE)
            except Exception as e:
                log_to_file(f"Dialog size failed: name={name} type={type} error={str(e)}")
            for key, value in props.items():
                try:
                    setattr(model, key, value)
                except Exception as e:
                    log_to_file(f"Dialog prop unsupported: control={name} type={type} prop={key} error={str(e)}")
            return control

        field_controls = {}
        current_y = VERT_MARGIN

        image_path = os.path.join(os.path.dirname(__file__), "icons", "iassistant.png")
        if os.path.exists(image_path):
            try:
                image_url = uno.systemPathToFileUrl(image_path)
                available_width = WIDTH - HORI_MARGIN * 2
                image_width = int(min(available_width, IMAGE_HEIGHT * (1505.0 / 400.0)))
                image_x = HORI_MARGIN + int((available_width - image_width) / 2)
                add("img_splash", "ImageControl", image_x, current_y,
                    image_width, IMAGE_HEIGHT, {
                        "ImageURL": image_url,
                        "Border": 0,
                        "ScaleImage": True
                    })
                proxy_btn_width = 70
                proxy_btn_height = LABEL_HEIGHT
                proxy_btn_x = WIDTH - HORI_MARGIN - 69
                proxy_btn_y = VERT_MARGIN + IMAGE_HEIGHT + VERT_SEP
                add("btn_proxy", "Button", proxy_btn_x, proxy_btn_y,
                    proxy_btn_width, proxy_btn_height, {
                        "Label": "Proxy",
                        "Name": "proxy_settings",
                        "Tabstop": True,
                        "Enabled": True,
                        "FontHeight": 8
                    })
                current_y += IMAGE_HEIGHT + VERT_SEP * 2
            except Exception:
                pass
        api_key_plain_control = None
        for field in field_specs:
            label_name = f"label_{field['name']}"
            edit_name = f"edit_{field['name']}"
            label_width = WIDTH - HORI_MARGIN * 2
            if field.get("name") == "api_key":
                label_width -= (80 + HORI_SEP)
            add(label_name, "FixedText", HORI_MARGIN, current_y, label_width, LABEL_HEIGHT,
                {"Label": field["label"], "NoLabel": True})
            if field.get("name") == "api_key":
                add("toggle_api_key", "Button", HORI_MARGIN + label_width + HORI_SEP, current_y, 80, BUTTON_HEIGHT,
                    {"Label": "Révéler", "NoLabel": True})
            current_y += (BUTTON_HEIGHT if field.get("name") == "api_key" else LABEL_HEIGHT) + VERT_SEP
            if field.get("type") == "list":
                items = field.get("items") or []
                control = add(edit_name, "ListBox", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT,
                    {"StringItemList": tuple(items), "Dropdown": True})
                if control:
                    try:
                        if field["value"]:
                            control.selectItem(field["value"], True)
                    except Exception:
                        pass
                    field_controls[field["name"]] = control
            else:
                props = {"Text": field["value"]}
                if field.get("type") == "password":
                    props["EchoChar"] = ord("*")
                control = add(edit_name, "Edit", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT,
                    props)
                if control:
                    field_controls[field["name"]] = control
                if field.get("name") == "api_key":
                    api_key_plain_control = add("edit_api_key_plain", "Edit", HORI_MARGIN, current_y,
                        WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT, {"Text": field["value"]})
                    if api_key_plain_control:
                        try:
                            api_key_plain_control.setVisible(False)
                        except Exception:
                            pass
            current_y += EDIT_HEIGHT + VERT_SEP * 2
            if field.get("name") == "api_key":
                add("btn_test_token", "Button", HORI_MARGIN, current_y - VERT_SEP, 140, BUTTON_HEIGHT,
                    {"Label": "♻️ Rafraîchir", "Name": "test_token", "NoLabel": True})
                current_y += TEST_ROW_HEIGHT

        description_label = "Description du modèle:"
        add("label_model_desc", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": description_label, "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP

        add("edit_model_desc", "Edit", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, DESC_HEIGHT,
            {"Text": "", "ReadOnly": True, "MultiLine": True})
        current_y += DESC_HEIGHT + VERT_SEP * 2

        access_token = str(self._get_config_from_file("access_token", "")).strip()
        email = self._token_email(access_token, allow_network=False) if access_token else None
        anon_ok, auth_ok = self._api_status(endpoint_value, api_key_value, is_openwebui)

        def _status_style(anon_ok, auth_ok, email_value):
            if auth_ok:
                return ("Connecté", 0x2ECC71)
            if anon_ok and not auth_ok:
                return ("Anonyme OK", 0xF39C12)
            if not anon_ok and not auth_ok and email_value is None:
                return ("Non testé", 0x888888)
            return ("Non accessible", 0x111111)

        status_label, status_color = _status_style(anon_ok, auth_ok, email)
        status_text = f"{status_label}" + (f" ({email})" if email else "")

        add("label_status_dot", "FixedText", HORI_MARGIN, current_y,
            12, LABEL_HEIGHT, {"Label": "●", "NoLabel": True, "TextColor": status_color})
        add("label_status_text", "FixedText", HORI_MARGIN + 16, current_y,
            WIDTH - HORI_MARGIN * 2 - 16, LABEL_HEIGHT, {"Label": status_text, "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP * 2

        add("btn_ok", "Button", HORI_MARGIN, current_y, BUTTON_WIDTH, BUTTON_HEIGHT,
            {"PushButtonType": OK, "DefaultButton": True, "Label": "OK"})
        add("btn_cancel", "Button", HORI_MARGIN + BUTTON_WIDTH + HORI_SEP, current_y, BUTTON_WIDTH, BUTTON_HEIGHT,
            {"PushButtonType": CANCEL, "Label": "Annuler"})
        keycloak_width = 96
        keycloak_x = HORI_MARGIN + (BUTTON_WIDTH + HORI_SEP) * 2
        reload_x = keycloak_x + keycloak_width + HORI_SEP
        reload_width = WIDTH - HORI_MARGIN - reload_x
        add("btn_keycloak", "Button", keycloak_x, current_y,
            keycloak_width, BUTTON_HEIGHT, {"Label": "🔐 Login", "Name": "keycloak_login", "Tabstop": True, "Enabled": True, "NoLabel": True})
        add("btn_reload_config", "Button", reload_x,
            current_y, reload_width, BUTTON_HEIGHT, {"Label": "🔄 Recharger configuration", "Name": "reload_config", "Tabstop": True, "Enabled": True, "NoLabel": True})
        dialog.setPosSize(0, 0, WIDTH, current_y + BUTTON_HEIGHT + 20, SIZE)

        frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
        window = frame.getContainerWindow() if frame else None
        dialog.createPeer(create("com.sun.star.awt.Toolkit"), window)
        if not x is None and not y is None:
            ps = dialog.convertSizeToPixel(uno.createUnoStruct("com.sun.star.awt.Size", x, y), TWIP)
            _x, _y = ps.Width, ps.Height
        elif window:
            ps = window.getPosSize()
            _x = ps.Width / 2 - WIDTH / 2
            _y = ps.Height / 2 - HEIGHT / 2
        dialog.setPosSize(_x, _y, 0, 0, POS)

        for field in field_specs:
            if field.get("type") == "list":
                continue
            control = field_controls[field["name"]]
            text_value = str(field["value"])
            control.setSelection(uno.createUnoStruct("com.sun.star.awt.Selection", 0, len(text_value)))

        field_controls["endpoint"].setFocus()

        status_dot_label = dialog.getControl("label_status_dot")
        status_text_label = dialog.getControl("label_status_text")
        model_desc_control = dialog.getControl("edit_model_desc")
        btn_keycloak = dialog.getControl("btn_keycloak")
        toggle_api_key = dialog.getControl("toggle_api_key")
        if not api_key_plain_control:
            api_key_plain_control = dialog.getControl("edit_api_key_plain")
        btn_reload_config = dialog.getControl("btn_reload_config")
        btn_proxy = dialog.getControl("btn_proxy")
        btn_test_token = dialog.getControl("btn_test_token")
        if not btn_reload_config:
            log_to_file("Reload config button not found in dialog")
        else:
            log_to_file("Reload config button created")

        def _read_api_key_value():
            try:
                if api_key_plain_control and api_key_plain_control.isVisible():
                    return str(api_key_plain_control.getModel().Text)
            except Exception:
                pass
            try:
                return str(field_controls["api_key"].getModel().Text)
            except Exception:
                return ""

        def _update_api_status_label(endpoint_val, api_key_val, email_value=None):
            anon_ok, auth_ok = self._api_status(endpoint_val, api_key_val, True)
            label, color = _status_style(anon_ok, auth_ok, email_value)
            status_text = label + (f" ({email_value})" if email_value else "")
            if status_dot_label:
                try:
                    status_dot_label.getModel().TextColor = color
                except Exception:
                    pass
            if status_text_label:
                try:
                    status_text_label.getModel().Label = status_text
                except Exception:
                    pass
            return anon_ok, auth_ok

        def _test_token_and_refresh():
            nonlocal model_descriptions
            try:
                endpoint_val = str(field_controls["endpoint"].getModel().Text)
            except Exception:
                endpoint_val = ""
            api_key_val = _read_api_key_value()
            effective_api_key = self._effective_api_token(api_key_val)
            log_to_file("Token test: start")
            conn_ok, conn_detail = self._endpoint_connectivity_status(endpoint_val, True)
            if not conn_ok:
                proxy_cfg = self._get_proxy_config()
                err = conn_detail.get("error", "inconnue")
                url = conn_detail.get("url", endpoint_val)
                if proxy_cfg.get("enabled"):
                    self._show_message(
                        "API",
                        "Endpoint OWUI injoignable via le proxy.\n\n"
                        f"URL testée: {url}\n"
                        f"Détail: {err}\n\n"
                        "Vérifiez le proxy (bouton Proxy > Tester connexion)."
                    )
                else:
                    self._show_message(
                        "API",
                        "Endpoint OWUI injoignable.\n\n"
                        f"URL testée: {url}\n"
                        f"Détail: {err}"
                    )
                log_to_file(f"Token test: connectivity failed url={url} err={err}")
                return
            anon_ok, auth_ok = _update_api_status_label(endpoint_val, effective_api_key)
            if not auth_ok:
                self._show_message(
                    "API",
                    "Token invalide, absent, ou refusé."
                )
                log_to_file("Token test: auth failed")
                return
            try:
                if endpoint_val.startswith("http"):
                    self.set_config("llm_base_urls", endpoint_val)
                if api_key_val:
                    self.set_config("llm_api_tokens", api_key_val)
                    log_to_file("Token test: token saved")
            except Exception:
                pass
            models, model_descriptions_local = self._fetch_models_info(endpoint_val, effective_api_key, True)
            if not models:
                self._show_message(
                    "API",
                    "Aucun modèle disponible (vérifiez l'endpoint et le token)."
                )
                log_to_file("Token test: models empty")
                return
            model_descriptions = model_descriptions_local
            model_control = field_controls.get("model")
            if model_control:
                try:
                    model_control.removeItems(0, model_control.getItemCount())
                except Exception:
                    pass
                try:
                    model_control.addItems(tuple(models), 0)
                except Exception:
                    pass
            selected = models[0]
            try:
                if model_control:
                    model_control.selectItem(selected, True)
            except Exception:
                pass
            try:
                self.set_config("llm_default_models", selected)
            except Exception:
                pass
            desc = model_descriptions.get(selected) or f"ID: {selected}"
            try:
                model_desc_control.getModel().Text = desc
            except Exception:
                pass
            log_to_file(f"Token test: ok, models={len(models)}")

        class SettingsActionListener(unohelper.Base, XActionListener):
            def __init__(self, outer, model_control, desc_control, descriptions, endpoint_control, api_key_control, api_key_plain_control, toggle_control):
                self.outer = outer
                self.model_control = model_control
                self.desc_control = desc_control
                self.descriptions = descriptions
                self.endpoint_control = endpoint_control
                self.api_key_control = api_key_control
                self.api_key_plain_control = api_key_plain_control
                self.toggle_control = toggle_control
                self.api_key_masked = True

            def actionPerformed(self, event):
                try:
                    source = getattr(event, "Source", None)
                except Exception:
                    source = None
                if source and self.toggle_control and source == self.toggle_control:
                    self.api_key_masked = not self.api_key_masked
                    try:
                        if self.api_key_plain_control:
                            if self.api_key_masked:
                                text = self.api_key_plain_control.getModel().Text
                                self.api_key_control.getModel().Text = text
                                self.api_key_plain_control.setVisible(False)
                                self.api_key_control.setVisible(True)
                            else:
                                text = self.api_key_control.getModel().Text
                                self.api_key_plain_control.getModel().Text = text
                                self.api_key_control.setVisible(False)
                                self.api_key_plain_control.setVisible(True)
                        else:
                            model = self.api_key_control.getModel()
                            model.EchoChar = ord("*") if self.api_key_masked else 0
                            current_text = model.Text
                            model.Text = current_text
                    except Exception:
                        pass
                    try:
                        self.toggle_control.getModel().Label = "Révéler" if self.api_key_masked else "Masquer"
                    except Exception:
                        pass
                    return
                try:
                    command = getattr(event, "ActionCommand", "") or ""
                except Exception:
                    command = ""
                if not command:
                    try:
                        if source:
                            command = getattr(source.getModel(), "Name", "") or ""
                    except Exception:
                        command = ""
                if not command:
                    log_to_file("SettingsActionListener: empty ActionCommand")
                if command == "keycloak_login":
                    config_data = self.outer._fetch_config() or {}
                    if not config_data:
                        log_to_file("Keycloak login: DM config unavailable, using local Keycloak settings fallback")
                    self.outer._clear_tokens()
                    access_token = self.outer._authorization_code_flow(config_data)
                    if access_token:
                        try:
                            self.outer._ensure_device_management_state_async()
                        except Exception as exc:
                            log_to_file(f"Post-login enroll scheduling failed: {str(exc)}")
                    email = self.outer._token_email(access_token, allow_network=False) if access_token else None
                    _update_api_status_label(
                        str(self.endpoint_control.getModel().Text) if self.endpoint_control else "",
                        _read_api_key_value(),
                        email_value=email
                    )
                elif command == "toggle_api_key":
                    self.api_key_masked = not self.api_key_masked
                    try:
                        if self.api_key_plain_control:
                            if self.api_key_masked:
                                text = self.api_key_plain_control.getModel().Text
                                self.api_key_control.getModel().Text = text
                                self.api_key_plain_control.setVisible(False)
                                self.api_key_control.setVisible(True)
                            else:
                                text = self.api_key_control.getModel().Text
                                self.api_key_plain_control.getModel().Text = text
                                self.api_key_control.setVisible(False)
                                self.api_key_plain_control.setVisible(True)
                        else:
                            model = self.api_key_control.getModel()
                            model.EchoChar = ord("*") if self.api_key_masked else 0
                            current_text = model.Text
                            model.Text = current_text
                    except Exception:
                        pass
                    try:
                        if self.toggle_control:
                            self.toggle_control.getModel().Label = "Révéler" if self.api_key_masked else "Masquer"
                    except Exception:
                        pass
                elif command == "test_token":
                    _test_token_and_refresh()
                elif command == "reload_config":
                    pass
                elif command == "proxy_settings":
                    try:
                        self.outer.proxy_settings_box("Proxy")
                    except Exception:
                        pass

        def _do_reload_config():
            log_to_file("Reload config: button clicked")
            cancel_flag = {"cancel": False}

            def _show_reload_dialog():
                try:
                    from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
                    ctx = uno.getComponentContext()
                    def create(name):
                        return ctx.getServiceManager().createInstanceWithContext(name, ctx)
                    dialog = create("com.sun.star.awt.UnoControlDialog")
                    dialog_model = create("com.sun.star.awt.UnoControlDialogModel")
                    dialog.setModel(dialog_model)
                    dialog.setVisible(False)
                    dialog.setTitle("")
                    dialog.setPosSize(0, 0, 320, 110, SIZE)
                    try:
                        dialog_model.AlwaysOnTop = True
                    except Exception:
                        pass

                    label_model = dialog_model.createInstance("com.sun.star.awt.UnoControlFixedTextModel")
                    dialog_model.insertByName("reload_label", label_model)
                    label_model.Label = "Connexion à Mirai..."
                    label_model.NoLabel = True
                    label = dialog.getControl("reload_label")
                    label.setPosSize(10, 20, 300, 20, POSSIZE)

                    btn_model = dialog_model.createInstance("com.sun.star.awt.UnoControlButtonModel")
                    dialog_model.insertByName("reload_cancel", btn_model)
                    btn_model.Label = "Annuler"
                    btn = dialog.getControl("reload_cancel")
                    btn.setPosSize(110, 60, 100, 26, POSSIZE)

                    frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
                    window = frame.getContainerWindow() if frame else None
                    toolkit = create("com.sun.star.awt.Toolkit")
                    dialog.createPeer(toolkit, window)
                    if window:
                        ps = window.getPosSize()
                        _x = ps.Width / 2 - 160
                        _y = ps.Height / 2 - 55
                        dialog.setPosSize(_x, _y, 0, 0, POS)
                    dialog.setVisible(True)
                    try:
                        toolkit.processEventsToIdle()
                    except Exception:
                        pass
                    log_to_file("Reload config dialog shown")
                    return dialog, label, btn, toolkit
                except Exception as e:
                    log_to_file(f"Reload config dialog failed: {str(e)}")
                    return None, None, None, None

            class CancelListener(unohelper.Base, XActionListener):
                def actionPerformed(self, event):
                    cancel_flag["cancel"] = True
                def disposing(self, event):
                    return

            dialog, label, btn, toolkit = _show_reload_dialog()
            if btn:
                try:
                    btn.addActionListener(CancelListener())
                except Exception:
                    pass

            result_holder = {"settings": None}

            def _worker():
                    result_holder["settings"] = self._refresh_config_to_local(cancel_flag=cancel_flag)

            worker = threading.Thread(target=_worker, daemon=True)
            worker.start()

            dots_i = 0
            while worker.is_alive():
                try:
                    if cancel_flag["cancel"]:
                        break
                    dots_i += 1
                    dots = "." * ((dots_i % 3) + 1)
                    if label:
                        label.getModel().Label = f"Connexion à Mirai{dots}"
                    if toolkit:
                        toolkit.processEventsToIdle()
                except Exception:
                    pass
                time.sleep(0.2)

            if dialog:
                try:
                    dialog.setVisible(False)
                    dialog.dispose()
                except Exception:
                    pass

            if cancel_flag["cancel"]:
                log_to_file("Reload config: canceled by user")
                return

            settings = result_holder.get("settings")
            if not settings:
                self._show_message(
                    "Configuration",
                    "Impossible de recharger la configuration."
                )
                return
            try:
                endpoint_val = str(self.get_config("llm_base_urls", ""))
                api_key_val = str(self.get_config("llm_api_tokens", ""))
                model_val = str(self.get_config("llm_default_models", ""))
                is_openwebui = True
                models, model_descriptions_local = self._fetch_models_info(endpoint_val, api_key_val, is_openwebui)
                if not models:
                    self._show_message(
                        "API",
                        "Erreur lors de la récupération des modèles (vérifiez l'endpoint et le token)."
                    )
                if field_controls.get("endpoint"):
                    field_controls["endpoint"].getModel().Text = endpoint_val
                if field_controls.get("api_key"):
                    field_controls["api_key"].getModel().Text = api_key_val
                if field_controls.get("model"):
                    model_control = field_controls["model"]
                    try:
                        model_control.removeItems(0, model_control.getItemCount())
                    except Exception:
                        pass
                    if models:
                        try:
                            model_control.addItems(tuple(models), 0)
                        except Exception:
                            pass
                    if model_val:
                        try:
                            model_control.selectItem(model_val, True)
                        except Exception:
                            pass
                desc = model_descriptions_local.get(model_val) if models else model_descriptions.get(model_val)
                if not desc:
                    desc = f"ID: {model_val}" if model_val else "Aucune description disponible"
                model_desc_control.getModel().Text = desc
            except Exception:
                pass

        class ReloadActionListener(unohelper.Base, XActionListener):
            def __init__(self, outer, model_control, desc_control, descriptions, endpoint_control, api_key_control):
                self.outer = outer
                self.model_control = model_control
                self.desc_control = desc_control
                self.descriptions = descriptions
                self.endpoint_control = endpoint_control
                self.api_key_control = api_key_control

            def actionPerformed(self, event):
                _do_reload_config()

            def disposing(self, event):
                return

        listener = SettingsActionListener(
            self,
            field_controls.get("model"),
            model_desc_control,
            model_descriptions,
            field_controls.get("endpoint"),
            field_controls.get("api_key"),
            api_key_plain_control,
            toggle_api_key,
        )
        try:
            btn_keycloak.addActionListener(listener)
            log_to_file("Keycloak listener attached")
        except Exception as e:
            log_to_file(f"Keycloak listener attach failed: {str(e)}")
        try:
            btn_keycloak.getModel().ActionCommand = "keycloak_login"
        except Exception as e:
            log_to_file(f"Keycloak ActionCommand set failed: {str(e)}")
        if toggle_api_key:
            try:
                toggle_api_key.addActionListener(listener)
            except Exception:
                pass
            try:
                toggle_api_key.getModel().Name = "toggle_api_key"
            except Exception:
                pass

        if btn_test_token:
            try:
                btn_test_token.addActionListener(listener)
            except Exception:
                pass
            try:
                btn_test_token.getModel().ActionCommand = "test_token"
            except Exception:
                pass

        if btn_reload_config:
            try:
                btn_reload_config.addActionListener(
                    ReloadActionListener(
                        self,
                        field_controls.get("model"),
                        model_desc_control,
                        model_descriptions,
                        field_controls.get("endpoint"),
                        field_controls.get("api_key"),
                    )
                )
                log_to_file("Reload config action listener attached")
            except Exception as e:
                log_to_file(f"Reload config action listener attach failed: {str(e)}")
            try:
                btn_reload_config.getModel().ActionCommand = "reload_config"
            except Exception as e:
                log_to_file(f"Reload config ActionCommand set failed: {str(e)}")

        if btn_proxy:
            try:
                btn_proxy.addActionListener(listener)
            except Exception:
                pass
            try:
                btn_proxy.getModel().ActionCommand = "proxy_settings"
            except Exception:
                pass

        # Apply model selection after peer creation
        model_control = field_controls.get("model")
        if model_control:
            try:
                if current_model:
                    model_control.selectItem(current_model, True)
                selected = ""
                try:
                    selected = model_control.getSelectedItem()
                except Exception:
                    selected = current_model
                if not selected:
                    selected = current_model
                desc = model_descriptions.get(selected)
                if not desc:
                    desc = f"ID: {selected}"
                model_desc_control.getModel().Text = desc
            except Exception:
                pass

        if model_control:
            class ModelItemListener(unohelper.Base, XItemListener):
                def __init__(self, outer, control, desc_control, descriptions):
                    self.outer = outer
                    self.control = control
                    self.desc_control = desc_control
                    self.descriptions = descriptions

                def itemStateChanged(self, event):
                    try:
                        value = self.control.getSelectedItem()
                        if value:
                            self.outer.set_config("llm_default_models", value)
                            desc = self.descriptions.get(value)
                            if not desc:
                                desc = f"ID: {value}"
                            self.desc_control.getModel().Text = desc
                        else:
                            self.desc_control.getModel().Text = "Aucune description disponible"
                    except Exception:
                        pass

                def disposing(self, event):
                    return

            try:
                model_control.addItemListener(ModelItemListener(self, model_control, model_desc_control, model_descriptions))
            except Exception:
                pass

        if dialog.execute():
            result = {}
            for field in field_specs:
                control = field_controls[field["name"]]
                if field.get("type") == "list":
                    try:
                        selected = control.getSelectedItem()
                    except Exception:
                        selected = ""
                    if not selected:
                        selected = current_model
                    log_to_file(f"Model dialog selection text='{selected}' current='{current_model}'")
                    result[field["name"]] = selected
                    if selected:
                        self.set_config("llm_default_models", selected)
                else:
                    if field.get("name") == "api_key" and api_key_plain_control:
                        try:
                            if api_key_plain_control.isVisible():
                                control = api_key_plain_control
                        except Exception:
                            pass
                    control_text = control.getModel().Text
                    result[field["name"]] = control_text
        else:
            result = {}

        dialog.dispose()
        return result
    #end sharealike section 

    def trigger(self, args):
        self._log(f"=== trigger called with args: {args} ===")
        try:
            self._schedule_config_refresh(force=True, reason=f"trigger:{args}")
        except Exception:
            pass
        desktop = self.ctx.ServiceManager.createInstanceWithContext(
            "com.sun.star.frame.Desktop", self.ctx)
        model = desktop.getCurrentComponent()
        self._log(f"Current component type: {type(model)}")

        if handle_writer_action(self, args, model):
            return

        if handle_calc_action(self, args, model):
            return

# Starting from Python IDE
def main():
    try:
        ctx = XSCRIPTCONTEXT
    except NameError:
        ctx = officehelper.bootstrap()
        if ctx is None:
            print("ERROR: Could not bootstrap default Office.")
            sys.exit(1)
    job = MainJob(ctx)
    job.trigger("hello")
# Starting from command line
if __name__ == "__main__":
    main()
# pythonloader loads a static g_ImplementationHelper variable
log_to_file("=== Loading mirai extension module ===")
g_ImplementationHelper = unohelper.ImplementationHelper()
g_ImplementationHelper.addImplementation(
    MainJob,  # UNO object class
    "fr.gouv.interieur.mirai.do",  # implementation name
    ("com.sun.star.task.JobExecutor",), )  # implemented services
log_to_file("=== mirai extension registered successfully ===")
# vim: set shiftwidth=4 softtabstop=4 expandtab:
