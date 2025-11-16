import sys
import unohelper
import officehelper
import json
import urllib.request
import urllib.parse
import ssl
from com.sun.star.task import XJobExecutor
from com.sun.star.awt import MessageBoxButtons as MSG_BUTTONS
import uno
import os 
import logging
import re
import uuid
import time
import base64
import threading

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
        
        # Send telemetry trace on extension load
        try:
            self._ensure_extension_uuid()
            send_telemetry_trace_async(self, "ExtensionLoaded", {
                "event.type": "extension_loaded",
                "extension.context": "libreoffice_writer"
            })
        except Exception as e:
            log_to_file(f"Failed to send extension load telemetry: {str(e)}")
    
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

    def get_config(self,key,default):
        # Check for telemetry defaults first
        telemetry_defaults = self._get_telemetry_defaults()
        if key in telemetry_defaults and default is None:
            default = telemetry_defaults[key]
        
        name_file ="mirai.json"
        #path_settings = create_instance('com.sun.star.util.PathSettings')
        
        
        path_settings = self.sm.createInstanceWithContext('com.sun.star.util.PathSettings', self.ctx)

        user_config_path = getattr(path_settings, "UserConfig")

        if user_config_path.startswith('file://'):
            user_config_path = str(uno.fileUrlToSystemPath(user_config_path))
        
        # Ensure the path ends with the filename
        config_file_path = os.path.join(user_config_path, name_file)

        # Check if the file exists
        if not os.path.exists(config_file_path):
            return default

        # Try to load the JSON content from the file
        try:
            with open(config_file_path, 'r') as file:
                config_data = json.load(file)
        except (IOError, json.JSONDecodeError):
            return default

        # Get the value from config file
        value = config_data.get(key, default)
        
        # If telemetry key is empty string and we have a default from telemetry_defaults, use it
        if key == "telemetryKey" and (value == "" or value is None) and key in telemetry_defaults:
            return telemetry_defaults[key]
        
        return value

    def set_config(self, key, value):
        name_file = "mirai.json"
        
        path_settings = self.sm.createInstanceWithContext('com.sun.star.util.PathSettings', self.ctx)
        user_config_path = getattr(path_settings, "UserConfig")

        if user_config_path.startswith('file://'):
            user_config_path = str(uno.fileUrlToSystemPath(user_config_path))

        # Ensure the path ends with the filename
        config_file_path = os.path.join(user_config_path, name_file)

        # Load existing configuration if the file exists
        if os.path.exists(config_file_path):
            try:
                with open(config_file_path, 'r') as file:
                    config_data = json.load(file)
            except (IOError, json.JSONDecodeError):
                config_data = {}
        else:
            config_data = {}

        # Update the configuration with the new key-value pair
        config_data[key] = value

        # Write the updated configuration back to the file
        try:
            with open(config_file_path, 'w') as file:
                json.dump(config_data, file, indent=4)
        except IOError as e:
            # Handle potential IO errors (optional)
            print(f"Error writing to {config_file_path}: {e}")

    def _as_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        if isinstance(value, (int, float)):
            return value != 0
        return False

    def _is_openai_compatible(self):
        endpoint = str(self.get_config("endpoint", "http://127.0.0.1:5000"))
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

        endpoint = str(self.get_config("endpoint", "http://127.0.0.1:5000")).rstrip("/")
        api_key = str(self.get_config("api_key", ""))
        if api_type is None:
            api_type = str(self.get_config("api_type", "completions")).lower()
        api_type = "chat" if api_type == "chat" else "completions"
        model = str(self.get_config("model", ""))
        
        # Add default system prompt to ensure plain text output
        default_system_prompt = "You must return only plain text without any formatting, markdown, code blocks, or special characters. Do not use **, *, _, `, #, or any other formatting symbols. Return natural, simple text only."
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

        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'

        # Detect OpenWebUI endpoints (they use /api/ instead of /v1/)
        is_openwebui = self._as_bool(self.get_config("is_openwebui", False)) or "open-webui" in endpoint.lower() or "openwebui" in endpoint.lower()
        api_path = "/api" if is_openwebui else "/v1"
        
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

        json_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
        log_to_file(f"Request data: {json.dumps(data, ensure_ascii=False, indent=2)}")
        log_to_file(f"Headers: {headers}")
        
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
        except Exception as e:
            log_to_file(f"ERROR in stream_request: {str(e)}")
            append_callback(f"ERROR: {str(e)}")
            toolkit.processEventsToIdle()

    #retrieved from https://wiki.documentfoundation.org/Macros/General/IO_to_Screen
    #License: Creative Commons Attribution-ShareAlike 3.0 Unported License,
    #License: The Document Foundation  https://creativecommons.org/licenses/by-sa/3.0/
    #begin sharealike section 
    def input_box(self,message, title="", default="", x=None, y=None):
        """ Shows dialog with input box.
            @param message message to show on the dialog
            @param title window title
            @param default default value
            @param x optional dialog position in twips
            @param y optional dialog position in twips
            @return string if OK button pushed, otherwise zero length string
        """
        WIDTH = 600
        HORI_MARGIN = VERT_MARGIN = 8
        BUTTON_WIDTH = 100
        BUTTON_HEIGHT = 26
        HORI_SEP = VERT_SEP = 8
        LABEL_HEIGHT = BUTTON_HEIGHT * 2 + 5
        EDIT_HEIGHT = 24
        HEIGHT = VERT_MARGIN * 2 + LABEL_HEIGHT + VERT_SEP + EDIT_HEIGHT
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
        dialog.setPosSize(0, 0, WIDTH, HEIGHT, SIZE)
        def add(name, type, x_, y_, width_, height_, props):
            model = dialog_model.createInstance("com.sun.star.awt.UnoControl" + type + "Model")
            dialog_model.insertByName(name, model)
            control = dialog.getControl(name)
            control.setPosSize(x_, y_, width_, height_, POSSIZE)
            for key, value in props.items():
                setattr(model, key, value)
        label_width = WIDTH - BUTTON_WIDTH - HORI_SEP - HORI_MARGIN * 2
        add("label", "FixedText", HORI_MARGIN, VERT_MARGIN, label_width, LABEL_HEIGHT, 
            {"Label": str(message), "NoLabel": True})
        add("btn_ok", "Button", HORI_MARGIN + label_width + HORI_SEP, VERT_MARGIN, 
                BUTTON_WIDTH, BUTTON_HEIGHT, {"PushButtonType": OK, "DefaultButton": True})
        add("edit", "Edit", HORI_MARGIN, LABEL_HEIGHT + VERT_MARGIN + VERT_SEP, 
                WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT, {"Text": str(default)})
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

    def settings_box(self,title="", x=None, y=None):
        """ Settings dialog with configurable backend options """
        WIDTH = 600
        HORI_MARGIN = VERT_MARGIN = 8
        BUTTON_WIDTH = 100
        BUTTON_HEIGHT = 26
        HORI_SEP = 8
        VERT_SEP = 4
        LABEL_HEIGHT = BUTTON_HEIGHT  + 5
        EDIT_HEIGHT = 24
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

        openai_compatibility_value = "true" if self._as_bool(self.get_config("openai_compatibility", False)) else "false"
        is_openwebui_value = "true" if self._as_bool(self.get_config("is_openwebui", False)) else "false"
        field_specs = [
            {"name": "endpoint", "label": "Endpoint URL/Port:", "value": str(self.get_config("endpoint","http://127.0.0.1:5000"))},
            {"name": "model", "label": "Model (Required by Ollama/OpenAI):", "value": str(self.get_config("model",""))},
            {"name": "api_key", "label": "API Key (for OpenAI-compatible endpoints):", "value": str(self.get_config("api_key",""))},
            {"name": "api_type", "label": "API Type (completions/chat):", "value": str(self.get_config("api_type","completions"))},
            {"name": "is_openwebui", "label": "Is OpenWebUI endpoint? (true/false):", "value": is_openwebui_value, "type": "bool"},
            {"name": "openai_compatibility", "label": "OpenAI Compatible Endpoint? (true/false):", "value": openai_compatibility_value, "type": "bool"},
            {"name": "extend_selection_max_tokens", "label": "Extend Selection Max Tokens:", "value": str(self.get_config("extend_selection_max_tokens","15000")), "type": "int"},
            {"name": "extend_selection_system_prompt", "label": "Extend Selection System Prompt:", "value": str(self.get_config("extend_selection_system_prompt",""))},
            {"name": "edit_selection_max_new_tokens", "label": "Edit Selection Max New Tokens:", "value": str(self.get_config("edit_selection_max_new_tokens","15000")), "type": "int"},
            {"name": "edit_selection_system_prompt", "label": "Edit Selection System Prompt:", "value": str(self.get_config("edit_selection_system_prompt",""))},
        ]

        num_fields = len(field_specs)
        total_field_height = num_fields * (LABEL_HEIGHT + EDIT_HEIGHT + 2 * VERT_SEP)
        HEIGHT = VERT_MARGIN * 2 + total_field_height
        dialog.setPosSize(0, 0, WIDTH, HEIGHT, SIZE)

        def add(name, type, x_, y_, width_, height_, props):
            model = dialog_model.createInstance("com.sun.star.awt.UnoControl" + type + "Model")
            dialog_model.insertByName(name, model)
            control = dialog.getControl(name)
            control.setPosSize(x_, y_, width_, height_, POSSIZE)
            for key, value in props.items():
                setattr(model, key, value)

        label_width = WIDTH - BUTTON_WIDTH - HORI_SEP - HORI_MARGIN * 2
        field_controls = {}
        current_y = VERT_MARGIN
        for idx, field in enumerate(field_specs):
            label_name = f"label_{field['name']}"
            edit_name = f"edit_{field['name']}"
            add(label_name, "FixedText", HORI_MARGIN, current_y, label_width, LABEL_HEIGHT,
                {"Label": field["label"], "NoLabel": True})
            if idx == 0:
                add("btn_ok", "Button", HORI_MARGIN + label_width + HORI_SEP, current_y,
                    BUTTON_WIDTH, BUTTON_HEIGHT, {"PushButtonType": OK, "DefaultButton": True})
            current_y += LABEL_HEIGHT + VERT_SEP
            add(edit_name, "Edit", HORI_MARGIN, current_y,
                WIDTH - HORI_MARGIN * 2, EDIT_HEIGHT, {"Text": field["value"]})
            field_controls[field["name"]] = dialog.getControl(edit_name)
            current_y += EDIT_HEIGHT + VERT_SEP

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
            control = field_controls[field["name"]]
            text_value = str(field["value"])
            control.setSelection(uno.createUnoStruct("com.sun.star.awt.Selection", 0, len(text_value)))

        field_controls["endpoint"].setFocus()

        if dialog.execute():
            result = {}
            for field in field_specs:
                control_text = field_controls[field["name"]].getModel().Text
                field_type = field.get("type", "text")
                if field_type == "int":
                    if control_text.isdigit():
                        result[field["name"]] = int(control_text)
                elif field_type == "bool":
                    result[field["name"]] = self._as_bool(control_text)
                else:
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

                        def append_text(chunk_text):
                            # Insert text at cursor position (preserves formatting)
                            text.insertString(cursor, chunk_text, False)

                        self.stream_request(request, api_type, append_text)
                                      
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
                    user_input = self.input_box("Saisissez votre prompt d'édition !", "Input", "")
                    
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
            
            elif args == "OpenMiraiWebsite":
                # Send telemetry trace
                send_telemetry_trace_async(self, "OpenMiraiWebsite", {
                    "action": "open_website"
                })
                
                # Open MirAI website in default browser
                try:
                    import webbrowser
                    webbrowser.open("https://mirai.interieur.gouv.fr")
                except Exception as e:
                    log_to_file(f"Error opening website: {str(e)}")
            
            elif args == "settings":
                # Send telemetry trace
                send_telemetry_trace_async(self, "OpenSettings", {
                    "action": "open_settings"
                })
                
                try:
                    result = self.settings_box("Settings")
                                    
                    if "extend_selection_max_tokens" in result:
                        self.set_config("extend_selection_max_tokens", result["extend_selection_max_tokens"])

                    if "extend_selection_system_prompt" in result:
                        self.set_config("extend_selection_system_prompt", result["extend_selection_system_prompt"])

                    if "edit_selection_max_new_tokens" in result:
                        self.set_config("edit_selection_max_new_tokens", result["edit_selection_max_new_tokens"])

                    if "edit_selection_system_prompt" in result:
                        self.set_config("edit_selection_system_prompt", result["edit_selection_system_prompt"])

                    if "endpoint" in result and result["endpoint"].startswith("http"):
                        self.set_config("endpoint", result["endpoint"])

                    if "api_key" in result:
                        self.set_config("api_key", result["api_key"])

                    if "api_type" in result:
                        api_type_value = str(result["api_type"]).strip().lower()
                        if api_type_value not in ("chat", "completions"):
                            api_type_value = "completions"
                        self.set_config("api_type", api_type_value)

                    if "is_openwebui" in result:
                        self.set_config("is_openwebui", result["is_openwebui"])

                    if "openai_compatibility" in result:
                        self.set_config("openai_compatibility", result["openai_compatibility"])

                    if "model" in result:                
                        self.set_config("model", result["model"])


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
                                        
                        if "extend_selection_max_tokens" in result:
                            self.set_config("extend_selection_max_tokens", result["extend_selection_max_tokens"])

                        if "extend_selection_system_prompt" in result:
                            self.set_config("extend_selection_system_prompt", result["extend_selection_system_prompt"])

                        if "edit_selection_max_new_tokens" in result:
                            self.set_config("edit_selection_max_new_tokens", result["edit_selection_max_new_tokens"])

                        if "edit_selection_system_prompt" in result:
                            self.set_config("edit_selection_system_prompt", result["edit_selection_system_prompt"])

                        if "endpoint" in result and result["endpoint"].startswith("http"):
                            self.set_config("endpoint", result["endpoint"])

                        if "api_key" in result:
                            self.set_config("api_key", result["api_key"])

                        if "api_type" in result:
                            api_type_value = str(result["api_type"]).strip().lower()
                            if api_type_value not in ("chat", "completions"):
                                api_type_value = "completions"
                            self.set_config("api_type", api_type_value)

                        if "is_openwebui" in result:
                            self.set_config("is_openwebui", result["is_openwebui"])

                        if "openai_compatibility" in result:
                            self.set_config("openai_compatibility", result["openai_compatibility"])

                        if "model" in result:                
                            self.set_config("model", result["model"])
                    except Exception:
                        pass
                    return

                user_input = ""
                if args == "EditSelection":
                    user_input = self.input_box("Please enter edit instructions!", "Input", "")

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
log_to_file("=== Loading Mirai extension module ===")
g_ImplementationHelper = unohelper.ImplementationHelper()
g_ImplementationHelper.addImplementation(
    MainJob,  # UNO object class
    "fr.gouv.interieur.mirai.do",  # implementation name
    ("com.sun.star.task.JobExecutor",), )  # implemented services
log_to_file("=== Mirai extension registered successfully ===")
# vim: set shiftwidth=4 softtabstop=4 expandtab:
