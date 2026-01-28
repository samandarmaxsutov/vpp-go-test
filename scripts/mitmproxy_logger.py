#!/usr/bin/env python3
"""
mitmproxy addon script to log HTTP/HTTPS requests to JSONL format.
Used by TLS Interception feature to capture URLs for the web UI.
Compatible with mitmproxy 11.x
"""

import json
import os
from datetime import datetime
from mitmproxy import http, ctx

# Log file path - same location as other logs
LOG_FILE = os.environ.get("MITMPROXY_LOG_FILE", "/home/mitigator/vpp-go-test/url_logs.jsonl")

class URLLogger:
    def __init__(self):
        self.log_file = LOG_FILE
        # Ensure log file directory exists
        log_dir = os.path.dirname(self.log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
    def _get_client_ip(self, flow: http.HTTPFlow) -> str:
        """Get client IP address - compatible with mitmproxy 11.x"""
        try:
            # mitmproxy 11.x uses flow.client_conn.peername as tuple (ip, port)
            if hasattr(flow.client_conn, 'peername') and flow.client_conn.peername:
                return flow.client_conn.peername[0]
            # Fallback for older versions
            if hasattr(flow.client_conn, 'address') and flow.client_conn.address:
                return flow.client_conn.address[0]
        except Exception:
            pass
        return "unknown"
        
    def request(self, flow: http.HTTPFlow) -> None:
        """Log each HTTP request"""
        try:
            client_ip = self._get_client_ip(flow)
            
            # Get request details
            method = flow.request.method
            url = flow.request.pretty_url
            host = flow.request.host
            port = flow.request.port
            path = flow.request.path
            scheme = flow.request.scheme
            
            # Get headers (only interesting ones)
            headers = dict(flow.request.headers)
            user_agent = headers.get("user-agent", headers.get("User-Agent", ""))
            content_type = headers.get("content-type", headers.get("Content-Type", ""))
            
            # Build log entry
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "url",
                "client_ip": client_ip,
                "method": method,
                "scheme": scheme,
                "host": host,
                "port": port,
                "path": path,
                "url": url,
                "user_agent": user_agent[:200] if user_agent else "",  # Truncate long user agents
                "content_type": content_type,
                "status": "REQUEST"
            }
            
            # Write to log file
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
                
        except Exception as e:
            ctx.log.error(f"URLLogger error on request: {e}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Log response status"""
        try:
            client_ip = self._get_client_ip(flow)
            
            # Get response details
            status_code = flow.response.status_code
            content_length = len(flow.response.content) if flow.response.content else 0
            content_type = flow.response.headers.get("content-type", "")
            
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "url",
                "client_ip": client_ip,
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "host": flow.request.host,
                "status_code": status_code,
                "content_length": content_length,
                "content_type": content_type[:100] if content_type else "",
                "status": "RESPONSE"
            }
            
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
                
        except Exception as e:
            ctx.log.error(f"URLLogger error on response: {e}")

    def error(self, flow: http.HTTPFlow) -> None:
        """Log connection errors"""
        try:
            client_ip = self._get_client_ip(flow)
            
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "url",
                "client_ip": client_ip,
                "method": flow.request.method if flow.request else "UNKNOWN",
                "url": flow.request.pretty_url if flow.request else "unknown",
                "host": flow.request.host if flow.request else "unknown",
                "error": str(flow.error) if flow.error else "Unknown error",
                "status": "ERROR"
            }
            
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
                
        except Exception as e:
            ctx.log.error(f"URLLogger error on error: {e}")


addons = [URLLogger()]
