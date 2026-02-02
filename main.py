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


def log_to_file(message):
    # Get the user's home directory
    home_directory = os.path.expanduser('~')
    
    # Define the log file path
    log_file_path = os.path.join(home_directory, 'log.txt')
    
    # Set up logging configuration
    logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(message)s')
    
    # Log the input message
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
                    # Show full authorization header for debugging
                    log_to_file(f"{header_name}: {header_value}")
                    log_to_file(f"  └─ Type: {auth_type}")
                    log_to_file(f"  └─ Key (first 20 chars): {auth_key[:20]}..." if len(auth_key) > 20 else f"  └─ Key: {auth_key}")
                else:
                    log_to_file(f"{header_name}: {header_value}")
            log_to_file(f"Content-Length: {len(json_data)}")
            log_to_file(f"===")
        
        # Create SSL context that doesn't verify certificates (for internal endpoints)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        with urllib.request.urlopen(req, context=ssl_context, timeout=5) as response:
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
        self._models_cache = None
        self._models_cache_key = None
        self._models_cache_loaded_at = 0
        self._models_cache_ttl = 60
        self._auth_prompt_in_progress = False
        self._auth_prompted_at = 0
        self._edit_dialog = None
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
            send_telemetry_trace_async(self, "ExtensionLoaded", {
                "event.type": "extension_loaded",
                "extension.context": "libreoffice_writer"
            })
        except Exception as e:
            log_to_file(f"Failed to send extension load telemetry: {str(e)}")

        try:
            self._ensure_device_management_state()
        except Exception as e:
            log_to_file(f"Failed to initialize device management: {str(e)}")
    
    def _ensure_extension_uuid(self):
        """Ensure extension has a unique UUID, generate if missing."""
        extension_uuid = self.get_config("extensionUUID", "")
        if not extension_uuid:
            extension_uuid = str(uuid.uuid4())
            self.set_config("extensionUUID", extension_uuid)
            log_to_file(f"Generated new extension UUID: {extension_uuid}")
        return extension_uuid
    
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
        package_config_path = os.path.join(os.path.dirname(__file__), package_file)
        if os.path.exists(package_config_path):
            try:
                with open(package_config_path, 'r', encoding='utf-8') as file:
                    package_config_data = json.load(file)
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

    def _fetch_config(self, force=False):
        if not force and not self._device_management_enabled():
            log_to_file("DM config fetch skipped: device management disabled")
            return None
        now = time.time()
        if self.config_cache and (now - self.config_loaded_at) < self.config_ttl:
            return self.config_cache

        base_url = str(self._get_config_from_file("bootstrap_url", "")).strip()
        if not base_url:
            log_to_file("DM config fetch skipped: bootstrap_url is empty")
            return None
        config_path = str(self._get_config_from_file("config_path", "/config/config.json"))
        url = base_url.rstrip("/") + "/" + config_path.lstrip("/")
        log_to_file(f"DM bootstrap URL: {url}")

        try:
            request = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(request, context=self.get_ssl_context(), timeout=10) as response:
                payload = response.read().decode("utf-8")
            log_to_file(f"DM bootstrap raw response: {payload[:2000]}")
            config_data = json.loads(payload)
            if isinstance(config_data, dict):
                self.config_cache = config_data
                self.config_loaded_at = now
                return config_data
        except urllib.error.HTTPError as e:
            try:
                body = e.read().decode("utf-8")
            except Exception:
                body = ""
            log_to_file(f"Failed to fetch device management config: HTTP {e.code} {e.reason} body={body[:500]}")
        except urllib.error.URLError as e:
            log_to_file(f"Failed to fetch device management config: URL error {e.reason}")
        except Exception as e:
            log_to_file(f"Failed to fetch device management config: {str(e)}")
        return None

    def _get_setting(self, key):
        config_data = self._fetch_config()
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

        # Ensure the path ends with the filename
        config_file_path = os.path.join(user_config_path, name_file)

        # Load existing configuration if the file exists
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r', encoding='utf-8') as file:
                    config_data = json.load(file)
            except (IOError, json.JSONDecodeError):
                config_data = {}
        else:
            config_data = {}

        # Update the configuration with the new key-value pair
        config_data[key] = value
        if key == "llm_default_models":
            log_to_file(f"Model saved (local): {value}")

        # Write the updated configuration back to the file
        try:
            with open(config_file_path, 'w', encoding='utf-8') as file:
                json.dump(config_data, file, indent=4, ensure_ascii=False)
        except IOError as e:
            # Handle potential IO errors (optional)
            print(f"Error writing to {config_file_path}: {e}")

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
        endpoints = config_data.get("endpoints", {})
        if not isinstance(endpoints, dict):
            endpoints = {}
        keycloak = config_data.get("keycloak") or endpoints.get("keycloak") or {}
        return keycloak if isinstance(keycloak, dict) else {}

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
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            with urllib.request.urlopen(request, context=self.get_ssl_context(), timeout=20) as response:
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

    def _token_email(self, access_token, userinfo_endpoint=None):
        payload = self._jwt_payload(access_token)
        email = payload.get("email") or payload.get("preferred_username")
        verified = payload.get("email_verified", payload.get("emailVerified"))
        if email and (verified is None or verified is True):
            return email
        if userinfo_endpoint:
            try:
                request = urllib.request.Request(
                    userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                with urllib.request.urlopen(request, context=self.get_ssl_context(), timeout=10) as response:
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
        raw = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        return raw.rstrip("=")

    def _pkce_code_challenge(self, verifier):
        digest = hashlib.sha256(verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    def _wait_for_auth_code(self, redirect_uri, timeout_seconds=120, tick=None):
        try:
            parsed = urllib.parse.urlparse(redirect_uri)
            if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1"):
                return None, "redirect_uri_invalid"
            host = parsed.hostname
            port = parsed.port or 80
            path = parsed.path or "/"
        except Exception:
            return None, "redirect_uri_invalid"

        result = {"code": None, "error": None}

        from http.server import BaseHTTPRequestHandler, HTTPServer

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
            httpd = HTTPServer((bind_host, port), Handler)
            httpd.timeout = 1
        except Exception as e:
            log_to_file(f"Failed to start local callback server: {str(e)}")
            return None, "callback_server_error"
        log_to_file(f"Local callback server listening on http://{bind_host or '0.0.0.0'}:{port}{path}")

        start = time.time()
        while time.time() - start < timeout_seconds and not result["code"] and not result["error"]:
            httpd.handle_request()
            if tick:
                try:
                    tick()
                except Exception:
                    pass
        httpd.server_close()

        if result["error"]:
            return None, result["error"]
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
                dialog.setPosSize(0, 0, 300, 90, SIZE)

                label_model = dialog_model.createInstance("com.sun.star.awt.UnoControlFixedTextModel")
                dialog_model.insertByName("auth_wait_label", label_model)
                label_model.Label = "Authentification Keycloak..."
                label_model.NoLabel = True
                label = dialog.getControl("auth_wait_label")
                label.setPosSize(10, 30, 280, 20, POSSIZE)

                frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
                window = frame.getContainerWindow() if frame else None
                toolkit = create("com.sun.star.awt.Toolkit")
                dialog.createPeer(toolkit, window)
                if window:
                    ps = window.getPosSize()
                    _x = ps.Width / 2 - 150
                    _y = ps.Height / 2 - 45
                    dialog.setPosSize(_x, _y, 0, 0, POS)
                dialog.setVisible(True)
                return dialog, label, toolkit
            except Exception:
                return None, None, None

        wait_dialog, wait_label, wait_toolkit = _show_auth_wait_dialog()
        tick_state = {"i": 0}
        def _tick():
            if not wait_label or not wait_toolkit:
                return
            tick_state["i"] += 1
            dots = "." * ((tick_state["i"] % 3) + 1)
            try:
                wait_label.getModel().Label = f"Authentification Keycloak{dots}"
                wait_toolkit.processEventsToIdle()
            except Exception:
                pass

        code, error = self._wait_for_auth_code(redirect_uri, tick=_tick)
        if wait_dialog:
            try:
                wait_dialog.setVisible(False)
                wait_dialog.dispose()
            except Exception:
                pass
        if not code:
            log_to_file(f"Authorization code flow failed: {error}")
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
            return token_response.get("access_token")
        return None

    def _ensure_access_token(self, config_data):
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

        now = time.time()
        if self._auth_prompt_in_progress or (now - self._auth_prompted_at) < 30:
            log_to_file("Auth prompt suppressed (already shown recently)")
            return None
        self._auth_prompt_in_progress = True
        self._auth_prompted_at = now
        try:
            confirm = self._confirm_message(
                "Session expirée",
                "Votre session a expiré. Vous devez vous reconnecter pour utiliser le service.\n\n"
                "En continuant, vous serez redirigé vers un navigateur.\n\n"
                "Voulez-vous poursuivre ?"
            )
        finally:
            self._auth_prompt_in_progress = False
        if not confirm:
            return None

        auth_code_token = self._authorization_code_flow(config_data)
        if auth_code_token:
            return auth_code_token

        allow_password_fallback = self._as_bool(self._get_config_from_file("password_fallback", False))
        if not allow_password_fallback:
            log_to_file("Password fallback disabled; authentication aborted")
            return None

        username, password = self.credentials_box("Device Management", "Email ou identifiant :", "Mot de passe :")
        if not username or not password:
            return None

        password_payload = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_id
        }
        if client_secret:
            password_payload["client_secret"] = client_secret
        token_response = self._request_token(token_endpoint, password_payload)
        if isinstance(token_response, dict) and token_response.get("access_token"):
            self._store_tokens(token_response)
            return token_response.get("access_token")
        return None

    def _ensure_device_management_state(self):
        if not self._device_management_enabled():
            return
        config_data = self._fetch_config()
        if not config_data:
            return

        access_token = self._ensure_access_token(config_data)
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

        enroll_endpoint = ""
        endpoints = config_data.get("endpoints", {}) if isinstance(config_data, dict) else {}
        if isinstance(endpoints, dict):
            enroll_endpoint = endpoints.get("enroll") or endpoints.get("enroll_endpoint") or endpoints.get("enrollEndpoint") or ""
        if not enroll_endpoint:
            enroll_endpoint = config_data.get("enroll") or config_data.get("enroll_endpoint") or config_data.get("enrollEndpoint") or ""

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
            request = urllib.request.Request(enroll_endpoint, data=json_data, headers=headers)
            request.get_method = lambda: 'POST'
            with urllib.request.urlopen(request, context=self.get_ssl_context(), timeout=10) as response:
                response.read()
            self.set_config("enrolled", True)
        except Exception as e:
            log_to_file(f"Device management enroll failed: {str(e)}")

    def _get_openwebui_access_token(self):
        if not self._device_management_enabled():
            return ""
        config_data = self._fetch_config()
        if not config_data:
            return ""
        return self._ensure_access_token(config_data) or ""

    def _auth_header(self):
        name = str(self.get_config("authHeaderName", "Authorization")).strip() or "Authorization"
        prefix = str(self.get_config("authHeaderPrefix", "Bearer ")).strip() or "Bearer"
        if prefix and not prefix.endswith(" "):
            prefix = prefix + " "
        return name, prefix

    def _as_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        if isinstance(value, (int, float)):
            return value != 0
        return False

    def _split_endpoint_api_path(self, endpoint, is_openwebui):
        endpoint = (endpoint or "").rstrip("/")
        if endpoint.endswith("/api") or endpoint.endswith("/v1"):
            return endpoint, ""
        api_path = "/api" if is_openwebui else "/v1"
        return endpoint, api_path

    def _fetch_models_list(self, endpoint, api_key, is_openwebui):
        endpoint, api_path = self._split_endpoint_api_path(endpoint, is_openwebui)
        if api_path:
            url = endpoint + api_path + "/models"
        else:
            url = endpoint + "/models"
        headers = {"Content-Type": "application/json"}
        if is_openwebui:
            header_name, header_prefix = self._auth_header()
            if api_key:
                headers[header_name] = f"{header_prefix}{api_key}"
        elif api_key:
            header_name, header_prefix = self._auth_header()
            headers[header_name] = f"{header_prefix}{api_key}"

        try:
            curl_headers = " ".join([f"-H '{k}: {v}'" for k, v in headers.items()])
            log_to_file(f"Models list curl: curl -i {curl_headers} '{url}'")
        except Exception:
            pass

        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, context=self.get_ssl_context(), timeout=10) as response:
                payload = response.read().decode("utf-8")
            data = json.loads(payload)
        except Exception as e:
            log_to_file(f"Failed to fetch models list: {str(e)}")
            return []

        models = []
        if isinstance(data, dict):
            if isinstance(data.get("data"), list):
                for item in data["data"]:
                    if isinstance(item, dict):
                        model_id = item.get("id") or item.get("model") or item.get("name")
                        if model_id:
                            models.append(str(model_id))
            elif isinstance(data.get("models"), list):
                for item in data["models"]:
                    if isinstance(item, dict):
                        model_id = item.get("id") or item.get("model") or item.get("name")
                        if model_id:
                            models.append(str(model_id))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    models.append(item)
                elif isinstance(item, dict):
                    model_id = item.get("id") or item.get("model") or item.get("name")
                    if model_id:
                        models.append(str(model_id))
        return models

    def _fetch_models_info(self, endpoint, api_key, is_openwebui):
        endpoint, api_path = self._split_endpoint_api_path(endpoint, is_openwebui)
        if api_path:
            url = endpoint + api_path + "/models"
        else:
            url = endpoint + "/models"
        headers = {"Content-Type": "application/json"}
        if is_openwebui:
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
        elif api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, context=self.get_ssl_context(), timeout=10) as response:
                payload = response.read().decode("utf-8")
            data = json.loads(payload)
        except Exception as e:
            log_to_file(f"Failed to fetch models info: {str(e)}")
            return [], {}

        try:
            log_to_file(f"Models API raw response: {payload[:2000]}")
        except Exception:
            pass

        models = []
        descriptions = {}

        def add_model(item):
            if not isinstance(item, dict):
                return
            model_id = item.get("id") or item.get("model") or item.get("name")
            if not model_id:
                return
            model_id = str(model_id)
            models.append(model_id)
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

        if isinstance(data, dict):
            if isinstance(data.get("data"), list):
                for item in data["data"]:
                    add_model(item)
            elif isinstance(data.get("models"), list):
                for item in data["models"]:
                    add_model(item)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    add_model(item)

        return models, descriptions

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
        config_path = str(self._get_config_from_file("config_path", "/config/config.json"))
        bootstrap_url = str(self._get_config_from_file("bootstrap_url", "")).strip()
        normalized_url = f"{bootstrap_url.rstrip('/')}/{config_path.lstrip('/')}"
        log_to_file(f"Reload config URL computed: {normalized_url}")
        log_to_file(f"Reload config: url={normalized_url} keys={list(settings.keys())}")
        synced = []
        skipped = []
        for meta_key in ("lastversion", "updateUrl", "configVersion"):
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
            try:
                self.set_config(key, value)
                synced.append(key)
            except Exception:
                pass
        log_to_file(f"Device management config synced locally: {synced}")
        if skipped:
            log_to_file(f"Device management config skipped empty values: {skipped}")
        return settings

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
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, context=self.get_ssl_context(), timeout=5) as response:
                if response.status < 200 or response.status >= 300:
                    return False
                payload = response.read().decode("utf-8")
            json.loads(payload)
            return True
        except Exception:
            return False

    def _api_status(self, endpoint, api_key, is_openwebui):
        anon_headers = {"Content-Type": "application/json"}
        anon_ok = self._api_reachable(endpoint, anon_headers, is_openwebui, "https://chat.mirai.interieur.gouv.fr/health")

        auth_headers = {"Content-Type": "application/json"}
        if is_openwebui:
            header_name, header_prefix = self._auth_header()
            if api_key:
                auth_headers[header_name] = f"{header_prefix}{api_key}"
        elif api_key:
            header_name, header_prefix = self._auth_header()
            auth_headers[header_name] = f"{header_prefix}{api_key}"

        auth_ok = False
        if "Authorization" in auth_headers:
            auth_ok = self._api_reachable(endpoint, auth_headers, is_openwebui, "models")

        return anon_ok, auth_ok

    def _choose_model_via_ai(self, description, endpoint, api_key, is_openwebui):
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
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
        elif api_key:
            headers["Authorization"] = f"Bearer {api_key}"

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
            request = urllib.request.Request(url, data=json_data, headers=headers)
            request.get_method = lambda: 'POST'
            with urllib.request.urlopen(request, context=self.get_ssl_context(), timeout=20) as response:
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
        api_key = str(self.get_config("llm_api_tokens", ""))
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
        log_to_file(f"Headers: {headers}")
        try:
            curl_headers = " ".join([f"-H '{k}: {v}'" for k, v in headers.items()])
            log_to_file(f"Chat completions curl: curl -i -X POST {curl_headers} '{url}' -d '{json.dumps(data)}'")
        except Exception:
            pass
        
        # Note: method='POST' is implicit when data is provided
        request = urllib.request.Request(url, data=json_data, headers=headers)
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
        Create an SSL context that doesn't verify certificates.
        This is needed for some environments where SSL certificates are not properly configured.
        """
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context

    def stream_request(self, request, api_type, append_callback):
        """
        Stream a completion/chat response and append incremental chunks via the provided callback.
        """
        toolkit = self.ctx.getServiceManager().createInstanceWithContext(
            "com.sun.star.awt.Toolkit", self.ctx
        )
        ssl_context = self.get_ssl_context()
        
        log_to_file(f"=== Starting stream request ===")
        log_to_file(f"Request URL: {request.full_url}")
        log_to_file(f"Request method: {request.get_method()}")
        
        try:
            with urllib.request.urlopen(request, context=ssl_context) as response:
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
        LABEL_HEIGHT = BUTTON_HEIGHT * 2 + 5
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
        label_width = WIDTH - BUTTON_WIDTH - HORI_SEP - HORI_MARGIN * 2
        add("label", "FixedText", HORI_MARGIN, VERT_MARGIN, label_width, LABEL_HEIGHT, 
            {"Label": str(message), "NoLabel": True})
        add("btn_ok", "Button", HORI_MARGIN + label_width + HORI_SEP, VERT_MARGIN, 
                BUTTON_WIDTH, BUTTON_HEIGHT, {"PushButtonType": OK, "DefaultButton": True, "Label": ok_label})
        add("edit", "Edit", HORI_MARGIN, LABEL_HEIGHT + VERT_MARGIN + VERT_SEP, 
                WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT, {"Text": str(default), "MultiLine": True})
        add("btn_cancel", "Button", HORI_MARGIN + label_width + HORI_SEP, VERT_MARGIN + BUTTON_HEIGHT + VERT_SEP, 
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

        wait_dialog = {"dialog": None, "bg": None}
        wait_buffer = {"text": ""}
        def _show_wait():
            try:
                from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
                WIDTH = 420
                HEIGHT = 140
                HORI_MARGIN = VERT_MARGIN = 8
                LABEL_HEIGHT = 18
                BG_HEIGHT = HEIGHT - VERT_MARGIN * 2 - LABEL_HEIGHT - 6
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
                    dialog_model.BackgroundColor = 0xFFFFFF
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
                bg = add("edit_wait_bg", "Edit", HORI_MARGIN, VERT_MARGIN + LABEL_HEIGHT + 6,
                    WIDTH - HORI_MARGIN * 2, BG_HEIGHT,
                    {"Text": "", "MultiLine": True, "ReadOnly": True})
                if bg:
                    try:
                        bg.getModel().BackgroundColor = 0xFFFFFF
                        bg.getModel().TextColor = 0xDDDDDD
                        bg.getModel().FontHeight = 6
                        bg.getModel().Border = 0
                    except Exception:
                        pass
                frame = create("com.sun.star.frame.Desktop").getCurrentFrame()
                window = frame.getContainerWindow() if frame else None
                dialog.createPeer(create("com.sun.star.awt.Toolkit"), window)
                if window:
                    ps = window.getPosSize()
                    _x = ps.Width / 2 - WIDTH / 2 + int(ps.Width * 0.15)
                    _y = ps.Height / 2 - HEIGHT / 2
                    dialog.setPosSize(_x, _y, 0, 0, POS)
                dialog.setVisible(True)
                wait_dialog["dialog"] = dialog
                wait_dialog["bg"] = bg
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
            if aborted["value"]:
                self._show_message(
                    "Modification",
                    "Le modèle a tenté de poser une question. Reformulez la demande de manière plus directive."
                )
                _close_wait()
                return
            _close_wait()
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
        BUTTON_WIDTH = 110
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
        WIDTH = 660
        HORI_MARGIN = VERT_MARGIN = 10
        BUTTON_WIDTH = 140
        BUTTON_HEIGHT = 26
        HORI_SEP = 8
        VERT_SEP = 6
        LABEL_HEIGHT = 18
        EDIT_HEIGHT = 24
        IMAGE_HEIGHT = 132
        EXTRA_BOTTOM = 30
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
            package_config_path = os.path.join(os.path.dirname(__file__), "config.default.json")
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
        total_field_height = num_fields * (LABEL_HEIGHT + EDIT_HEIGHT + VERT_SEP * 2) + TEST_ROW_HEIGHT
        desc_block_height = LABEL_HEIGHT + VERT_SEP + DESC_HEIGHT + VERT_SEP * 2
        HEIGHT = VERT_MARGIN * 2 + IMAGE_HEIGHT + VERT_SEP + total_field_height + desc_block_height + LABEL_HEIGHT + BUTTON_HEIGHT + VERT_SEP * 4 + EXTRA_BOTTOM
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
                current_y += IMAGE_HEIGHT + VERT_SEP * 2
            except Exception:
                pass
        api_key_plain_control = None
        for field in field_specs:
            label_name = f"label_{field['name']}"
            edit_name = f"edit_{field['name']}"
            label_width = WIDTH - HORI_MARGIN * 2
            if field.get("name") == "api_key":
                label_width -= 60
            add(label_name, "FixedText", HORI_MARGIN, current_y, label_width, LABEL_HEIGHT,
                {"Label": field["label"], "NoLabel": True})
            if field.get("name") == "api_key":
                add("toggle_api_key", "Button", HORI_MARGIN + label_width - 9, current_y, 70, LABEL_HEIGHT,
                    {"Label": "Révéler"})
            current_y += LABEL_HEIGHT + VERT_SEP
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
                add("btn_test_token", "Button", HORI_MARGIN, current_y - VERT_SEP, 120, BUTTON_HEIGHT,
                    {"Label": "♻️ Rafraîchir", "Name": "test_token"})
                current_y += TEST_ROW_HEIGHT

        description_label = "Description du modèle:"
        add("label_model_desc", "FixedText", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, LABEL_HEIGHT,
            {"Label": description_label, "NoLabel": True})
        current_y += LABEL_HEIGHT + VERT_SEP

        add("edit_model_desc", "Edit", HORI_MARGIN, current_y, WIDTH - HORI_MARGIN * 2, DESC_HEIGHT,
            {"Text": "", "ReadOnly": True, "MultiLine": True})
        current_y += DESC_HEIGHT + VERT_SEP * 2

        access_token = str(self._get_config_from_file("access_token", "")).strip()
        email = self._token_email(access_token) if access_token else None
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
        keycloak_width = BUTTON_WIDTH - 12
        reload_width = BUTTON_WIDTH + 52
        keycloak_x = HORI_MARGIN + (BUTTON_WIDTH + HORI_SEP) * 2
        reload_x = keycloak_x + keycloak_width + HORI_SEP
        add("btn_keycloak", "Button", keycloak_x, current_y,
            keycloak_width, BUTTON_HEIGHT, {"Label": "🔐 Login", "Name": "keycloak_login", "Tabstop": True, "Enabled": True})
        add("btn_reload_config", "Button", reload_x,
            current_y, reload_width, BUTTON_HEIGHT, {"Label": "🔄 Recharge configuration", "Name": "reload_config", "Tabstop": True, "Enabled": True})

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
            log_to_file("Token test: start")
            anon_ok, auth_ok = _update_api_status_label(endpoint_val, api_key_val)
            if not auth_ok:
                self._show_message(
                    "API",
                    "Token invalide ou refusé."
                )
                log_to_file("Token test: auth failed")
                return
            try:
                if endpoint_val.startswith("http"):
                    self.set_config("llm_base_urls", endpoint_val)
                self.set_config("llm_api_tokens", api_key_val)
                log_to_file("Token test: token saved")
            except Exception:
                pass
            models, model_descriptions_local = self._fetch_models_info(endpoint_val, api_key_val, True)
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
                    config_data = self.outer._fetch_config()
                    if not config_data:
                        self.outer._show_message(
                            "Device Management",
                            "Impossible de récupérer la configuration Device Management."
                        )
                        return
                    self.outer._clear_tokens()
                    access_token = self.outer._authorization_code_flow(config_data)
                    email = self.outer._token_email(access_token) if access_token else None
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

        def _do_reload_config():
            log_to_file("Reload config: button clicked")
            cancel_flag = {"cancel": False}

            def _show_reload_dialog():
                try:
                    from com.sun.star.awt.PosSize import POS, SIZE, POSSIZE
                    ctx = uno.getComponentContext()
                    create = ctx.getServiceManager().createInstanceWithContext
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
        log_to_file(f"=== trigger called with args: {args} ===")
        desktop = self.ctx.ServiceManager.createInstanceWithContext(
            "com.sun.star.frame.Desktop", self.ctx)
        model = desktop.getCurrentComponent()
        log_to_file(f"Current component type: {type(model)}")
        #if not hasattr(model, "Text"):
        #    model = self.desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())

        if hasattr(model, "Text"):
            log_to_file("Processing Writer document")
            text = model.Text
            selection = model.CurrentController.getSelection()
            text_range = selection.getByIndex(0)

            
            if args == "ExtendSelection":
                # Send telemetry trace
                send_telemetry_trace_async(self, "ExtendSelection", {
                    "action": "extend_selection",
                    "text_length": str(len(text_range.getString()))
                })
                
                # Access the current selection
                if len(text_range.getString()) > 0:
                    try:
                        # Prepare request using the new unified method
                        system_prompt = self.get_config("extend_selection_system_prompt", "")
                        prompt = text_range.getString()
                        max_tokens = self.get_config("extend_selection_max_tokens", 15000)
                        
                        api_type = str(self.get_config("api_type", "completions")).lower()
                        request = self.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)

                        # Create cursor at the end of selection to preserve formatting
                        cursor = text.createTextCursorByRange(text_range)
                        cursor.collapseToEnd()

                        # Add separators around generated text
                        text.insertString(cursor, "\n\n---début-du-texte-généré---\n", False)

                        def append_text(chunk_text):
                            # Insert text at cursor position (preserves formatting)
                            text.insertString(cursor, chunk_text, False)

                        self.stream_request(request, api_type, append_text)
                        text.insertString(cursor, "\n---fin-du-texte-généré---\n", False)
                                      
                    except Exception as e:
                        text_range = selection.getByIndex(0)
                        # Append the user input to the selected text
                        text_range.setString(text_range.getString() + ": " + str(e))

            elif args == "EditSelection":
                # Send telemetry trace
                send_telemetry_trace_async(self, "EditSelection", {
                    "action": "edit_selection",
                    "text_length": str(len(text_range.getString()))
                })
                
                # Access the current selection
                try:
                    self._show_edit_selection_dialog(text, text_range)
                    return
                    
                    # Save the original text range properties for style preservation
                    original_text = text_range.getString()
                    
                    # Prepare the prompt for editing - using a clearer stop instruction
                    # Add explicit instructions to prevent the model from asking questions
                    prompt = """ORIGINAL VERSION:
""" + original_text + """

INSTRUCTIONS: """ + user_input + """

IMPORTANT RULES:
- Do NOT ask any questions
- Do NOT add explanations or comments
- Do NOT include phrases like "Here is..." or "I've made..."
- Output ONLY the edited text directly
- Start immediately with the edited content

EDITED VERSION:
"""
                    
                    system_prompt = self.get_config("edit_selection_system_prompt", "You are a text editor. You follow instructions precisely and output only the edited text without any questions, explanations, or meta-commentary.")
                    max_tokens = len(original_text) + self.get_config("edit_selection_max_new_tokens", 15000)
                    
                    api_type = str(self.get_config("api_type", "completions")).lower()
                    request = self.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)
                    
                    # Get cursor position at the END of selection (not replacing, but adding after)
                    cursor = text.createTextCursorByRange(text_range)
                    cursor.collapseToEnd()
                    
                    # Insert opening delimiter
                    text.insertString(cursor, "\n\n---modification-de-la-sélection---\n", False)
                    
                    # Track accumulated text for stop phrase detection
                    accumulated_text = ""

                    # Stop phrases to detect and remove
                    stop_phrases = [
                        "end of document",
                        "end of the document",
                        "[END]",
                        "---END---"
                    ]
                    
                    # Question patterns that indicate the model is asking instead of editing
                    question_patterns = [
                        # English patterns
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
                        # French patterns
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

                    def append_text(chunk_text):
                        nonlocal accumulated_text
                        accumulated_text += chunk_text
                        
                        # Check if model is asking questions or adding meta-commentary
                        lower_text = accumulated_text.lower()
                        for pattern in question_patterns:
                            if pattern in lower_text:
                                # Stop generation and show warning
                                text.insertString(cursor, "[Le modèle a tenté de poser une question au lieu d'éditer. Veuillez reformuler votre demande de manière plus directive.]", False)
                                accumulated_text = ""
                                return
                        
                        # Check if any stop phrase appears in the text
                        for stop_phrase in stop_phrases:
                            if stop_phrase.lower() in accumulated_text.lower():
                                # Find the position and truncate
                                pos = accumulated_text.lower().find(stop_phrase.lower())
                                accumulated_text = accumulated_text[:pos].rstrip()
                                return
                        
                        # Insert text at cursor position (preserves formatting)
                        text.insertString(cursor, chunk_text, False)

                    self.stream_request(request, api_type, append_text)
                    
                    # Add closing delimiter
                    text.insertString(cursor, "\n---fin-de-modification---\n", False)

                except Exception as e:
                    text_range = selection.getByIndex(0)
                    # Append the user input to the selected text
                    text_range.setString(text_range.getString() + ": " + str(e))
            
            elif args == "SummarizeSelection":
                # Send telemetry trace
                send_telemetry_trace_async(self, "SummarizeSelection", {
                    "action": "summarize_selection",
                    "text_length": str(len(text_range.getString()))
                })
                
                # Create a concise summary of the selected text
                try:
                    # Save the original text
                    original_text = text_range.getString()
                    
                    if len(original_text.strip()) == 0:
                        return
                    
                    # Prepare the prompt for summarization
                    prompt = """TEXT TO SUMMARIZE:
""" + original_text + """

Create the shortest possible summary that captures the essential information. 
Be extremely concise - use the minimum words necessary.
Do NOT ask any questions.
Output ONLY the summary text without any introduction or explanation.

SUMMARY:
"""
                    
                    system_prompt = "You are a professional summarizer. Create ultra-concise summaries using the minimum words necessary while preserving key information."
                    max_tokens = max(100, len(original_text) // 4)  # Summary should be much shorter
                    
                    api_type = str(self.get_config("api_type", "completions")).lower()
                    request = self.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)
                    
                    # Create cursor at the end of selection
                    cursor = text.createTextCursorByRange(text_range)
                    cursor.collapseToEnd()
                    
                    # Insert the summary markers
                    text.insertString(cursor, "\n\n---début-du-résumé---\n", False)
                    
                    # Track accumulated summary text
                    summary_text = ""
                    
                    # Stop phrases
                    stop_phrases = [
                        "end of document",
                        "end of the document",
                        "[END]",
                        "---END---"
                    ]

                    def append_summary(chunk_text):
                        nonlocal summary_text
                        summary_text += chunk_text
                        
                        # Check for stop phrases
                        for stop_phrase in stop_phrases:
                            if stop_phrase.lower() in summary_text.lower():
                                pos = summary_text.lower().find(stop_phrase.lower())
                                summary_text = summary_text[:pos].rstrip()
                                return
                        
                        # Insert summary text
                        text.insertString(cursor, chunk_text, False)

                    self.stream_request(request, api_type, append_summary)
                    
                    # Add closing marker
                    text.insertString(cursor, "\n---fin-du-résumé---\n", False)

                except Exception as e:
                    text_range = selection.getByIndex(0)
                    text_range.setString(text_range.getString() + ": " + str(e))
            
            elif args == "SimplifySelection":
                # Send telemetry trace
                send_telemetry_trace_async(self, "SimplifySelection", {
                    "action": "simplify_selection",
                    "text_length": str(len(text_range.getString()))
                })
                
                # Reformulate the selected text in clearer language
                try:
                    # Save the original text
                    original_text = text_range.getString()
                    
                    if len(original_text.strip()) == 0:
                        return
                    
                    # Prepare the prompt for simplification
                    prompt = """TEXT TO REFORMULATE:
""" + original_text + """

IMPORTANT: Rewrite this text in the SAME LANGUAGE as the original text.
Rewrite in clear, simple language that everyone can understand.
Use:
- Short sentences
- Common words (avoid jargon and technical terms)
- Active voice
- Concrete examples when possible

CRITICAL: 
- Keep the SAME LANGUAGE as the original text
- Do NOT translate to another language
- Do NOT ask questions
- Do NOT add explanations
- Output ONLY the reformulated text

REFORMULATED VERSION:
"""
                    
                    system_prompt = "You are a plain language expert. Rewrite complex text in clear, simple language accessible to all readers. ALWAYS use the same language as the input text. Use short sentences and common words."
                    max_tokens = len(original_text) + self.get_config("edit_selection_max_new_tokens", 15000)
                    
                    api_type = str(self.get_config("api_type", "completions")).lower()
                    request = self.make_api_request(prompt, system_prompt, max_tokens, api_type=api_type)
                    
                    # Create cursor at the end of selection
                    cursor = text.createTextCursorByRange(text_range)
                    cursor.collapseToEnd()
                    
                    # Insert the opening marker with proper formatting
                    text.insertString(cursor, "\n\n---reformulation-du-texte---\n", False)
                    
                    # Track accumulated simplified text
                    simplified_text = ""
                    
                    # Stop phrases
                    stop_phrases = [
                        "end of document",
                        "end of the document",
                        "[END]",
                        "---END---"
                    ]
                    
                    # Question patterns
                    question_patterns = [
                        "would you like", "do you want", "should i", "can i help",
                        "voulez-vous", "souhaitez-vous", "dois-je", "puis-je",
                        "here is", "here's", "voici", "voilà"
                    ]

                    def append_simplified(chunk_text):
                        nonlocal simplified_text
                        simplified_text += chunk_text
                        
                        # Check for questions
                        lower_text = simplified_text.lower()
                        for pattern in question_patterns:
                            if pattern in lower_text:
                                cursor.gotoStart(False)
                                cursor.gotoEnd(True)
                                text.insertString(cursor, "[Le modèle a posé une question. Veuillez réessayer.]", False)
                                simplified_text = ""
                                return
                        
                        # Check for stop phrases
                        for stop_phrase in stop_phrases:
                            if stop_phrase.lower() in simplified_text.lower():
                                pos = simplified_text.lower().find(stop_phrase.lower())
                                simplified_text = simplified_text[:pos].rstrip()
                                return
                        
                        # Insert simplified text (preserves formatting)
                        text.insertString(cursor, chunk_text, False)

                    self.stream_request(request, api_type, append_simplified)
                    
                    # Add closing marker
                    text.insertString(cursor, "\n---fin-de-reformulation---\n", False)

                except Exception as e:
                    text_range = selection.getByIndex(0)
                    text_range.setString(text_range.getString() + ": " + str(e))
            
            elif args == "OpenmiraiWebsite":
                # Send telemetry trace
                send_telemetry_trace_async(self, "OpenmiraiWebsite", {
                    "action": "open_website"
                })
                
                # Open mirai website in default browser
                try:
                    import webbrowser
                    webbrowser.open("https://mirai.interieur.gouv.fr")
                except Exception as e:
                    log_to_file(f"Error opening website: {str(e)}")
            elif args == "MenuSeparator":
                return
            
            elif args == "settings":
                # Send telemetry trace
                send_telemetry_trace_async(self, "OpenSettings", {
                    "action": "open_settings"
                })
                
                try:
                    result = self.settings_box("Settings")
                                    
                    if "endpoint" in result and result["endpoint"].startswith("http"):
                        self.set_config("llm_base_urls", result["endpoint"])

                    if "api_key" in result:
                        self.set_config("llm_api_tokens", result["api_key"])
                        log_to_file("Settings saved: llm_api_tokens updated")

                    if "model" in result:                
                        self.set_config("llm_default_models", result["model"])


                except Exception as e:
                    text_range = selection.getByIndex(0)
                    # Append the user input to the selected text
                    text_range.setString(text_range.getString() + ":error: " + str(e))
        elif hasattr(model, "Sheets"):
            log_to_file("Processing Calc document")
            try:
                sheet = model.CurrentController.ActiveSheet
                selection = model.CurrentController.Selection

                if args == "settings":
                    try:
                        result = self.settings_box("Settings")
                                        
                        if "endpoint" in result and result["endpoint"].startswith("http"):
                            self.set_config("llm_base_urls", result["endpoint"])

                        if "api_key" in result:
                            self.set_config("llm_api_tokens", result["api_key"])
                            log_to_file("Settings saved: llm_api_tokens updated")

                        if "model" in result:                
                            self.set_config("llm_default_models", result["model"])
                    except Exception:
                        pass
                    return

                user_input = ""
                if args == "EditSelection":
                    user_input = self.input_box("Saisissez vos instructions d'édition !", "Modifier la sélection", "", ok_label="Envoyer", cancel_label="Fermer", always_on_top=True)

                area = selection.getRangeAddress()
                start_row = area.StartRow
                end_row = area.EndRow
                start_col = area.StartColumn
                end_col = area.EndColumn

                col_range = range(start_col, end_col + 1)
                row_range = range(start_row, end_row + 1)

                api_type = str(self.get_config("api_type", "completions")).lower()
                extend_system_prompt = self.get_config("extend_selection_system_prompt", "")
                extend_max_tokens = self.get_config("extend_selection_max_tokens", 70)
                edit_system_prompt = self.get_config("edit_selection_system_prompt", "")
                edit_max_new_tokens = self.get_config("edit_selection_max_new_tokens", 0)
                try:
                    edit_max_new_tokens = int(edit_max_new_tokens)
                except (TypeError, ValueError):
                    edit_max_new_tokens = 0

                for row in row_range:
                    for col in col_range:
                        cell = sheet.getCellByPosition(col, row)

                        if args == "ExtendSelection":
                            cell_text = cell.getString()
                            if not cell_text:
                                continue
                            try:
                                request = self.make_api_request(cell_text, extend_system_prompt, extend_max_tokens, api_type=api_type)

                                def append_cell_text(chunk_text, target_cell=cell):
                                    target_cell.setString(target_cell.getString() + chunk_text)

                                self.stream_request(request, api_type, append_cell_text)
                            except Exception as e:
                                cell.setString(cell.getString() + ": " + str(e))
                        elif args == "EditSelection":
                            try:
                                prompt =  "ORIGINAL VERSION:\n" + cell.getString() + "\n Below is an edited version according to the following instructions. Don't waste time thinking, be as fast as you can. The edited text will be a shorter or longer version of the original text based on the instructions. There are no comments in the edited version. The edited version is followed by the end of the document. The original version will be edited as follows to create the edited version:\n" + user_input + "\nEDITED VERSION:\n"

                                max_tokens = len(cell.getString()) + edit_max_new_tokens
                                request = self.make_api_request(prompt, edit_system_prompt, max_tokens, api_type=api_type)

                                cell.setString("")

                                def append_edit_text(chunk_text, target_cell=cell):
                                    target_cell.setString(target_cell.getString() + chunk_text)

                                self.stream_request(request, api_type, append_edit_text)
                            except Exception as e:
                                cell.setString(cell.getString() + ": " + str(e))
            except Exception:
                pass
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
