#!/usr/bin/env python3
"""
mitmproxy addon script to log HTTP/HTTPS requests to JSONL format.
Used by Traffic Inspection (TLS interception) to capture URLs for the web UI.

Features:
- Daily log rotation: /etc/sarhad-guard/url_logs/urls_DD_MM_YYYY.log
- Appends if file exists; otherwise creates new
- Archives (gzip) logs older than 7 days, checked only once/day when a new log file is created
- Excluded URL patterns loaded from backend config:
    /etc/sarhad-guard/tls-interception/tls_conf.conf  -> excluded_urls: [ ... ]
  (substring match on full URL + host)
"""

import gzip
import json
import os
import re
import shutil
from datetime import datetime, timedelta
from mitmproxy import http, ctx

TLS_CONF_FILE = os.environ.get("TLS_CONF_FILE", "/etc/sarhad-guard/tls-interception/tls_conf.conf")
LOG_DIR = "/etc/sarhad-guard/url_logs"
ARCHIVE_DIR = os.path.join(LOG_DIR, "archive")

# MITMPROXY_LOG_FILE is kept for compatibility; actual daily file is derived from date.
_ = os.environ.get("MITMPROXY_LOG_FILE", "")

DATE_FMT = "%d_%m_%Y"
FNAME_RE = re.compile(r"^urls_(\d{2})_(\d{2})_(\d{4})\.log$")


class URLLogger:
    def __init__(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        os.makedirs(ARCHIVE_DIR, exist_ok=True)

        self.current_date = None
        self.log_file = None

        self._excluded = []
        self._conf_mtime = 0.0
        self._last_conf_check = 0.0

        self._ensure_daily_logfile(force=True)

    def _today_str(self) -> str:
        return datetime.now().strftime(DATE_FMT)

    def _daily_log_path(self, day_str: str) -> str:
        return os.path.join(LOG_DIR, f"urls_{day_str}.log")

    def _ensure_daily_logfile(self, force: bool = False):
        day_str = self._today_str()
        if force or self.current_date != day_str:
            self.current_date = day_str
            path = self._daily_log_path(day_str)

            created = False
            if not os.path.exists(path):
                # create new file
                with open(path, "a", encoding="utf-8") as f:
                    f.write("")  # touch
                created = True

            self.log_file = path

            # archive only when a new daily file is created (once/day)
            if created:
                try:
                    self._archive_old_logs(days=7)
                except Exception as e:
                    ctx.log.warn(f"URLLogger archive error: {e}")

    def _archive_old_logs(self, days: int = 7):
        cutoff = datetime.now() - timedelta(days=days)

        for name in os.listdir(LOG_DIR):
            m = FNAME_RE.match(name)
            if not m:
                continue
            dd, mm, yyyy = m.group(1), m.group(2), m.group(3)
            try:
                d = datetime(int(yyyy), int(mm), int(dd))
            except Exception:
                continue

            # don't archive today's file
            if d.strftime(DATE_FMT) == self.current_date:
                continue

            if d < cutoff:
                src = os.path.join(LOG_DIR, name)
                gz_name = name + ".gz"
                dst = os.path.join(ARCHIVE_DIR, gz_name)

                # already archived?
                if os.path.exists(dst):
                    # if original still exists, remove it
                    try:
                        os.remove(src)
                    except Exception:
                        pass
                    continue

                # gzip compress
                with open(src, "rb") as f_in:
                    with gzip.open(dst, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)

                # remove original after successful compress
                try:
                    os.remove(src)
                except Exception:
                    pass

    def _load_excludes_if_changed(self):
        # throttle checks (every ~2 seconds max)
        now = datetime.now().timestamp()
        if now - self._last_conf_check < 2.0:
            return
        self._last_conf_check = now

        try:
            st = os.stat(TLS_CONF_FILE)
        except FileNotFoundError:
            self._excluded = []
            self._conf_mtime = 0.0
            return
        except Exception:
            return

        if st.st_mtime <= self._conf_mtime:
            return

        self._conf_mtime = st.st_mtime

        try:
            with open(TLS_CONF_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            ex = data.get("excluded_urls", [])
            if not isinstance(ex, list):
                ex = []
            self._excluded = [str(x).strip() for x in ex if str(x).strip()]
        except Exception as e:
            ctx.log.warn(f"URLLogger config read error: {e}")

    def _is_excluded(self, url: str, host: str) -> bool:
        if not self._excluded:
            return False
        u = url or ""
        h = host or ""
        for pat in self._excluded:
            # substring match
            if pat in u or pat in h:
                return True
        return False

    def _get_client_ip(self, flow: http.HTTPFlow) -> str:
        try:
            if hasattr(flow.client_conn, "peername") and flow.client_conn.peername:
                return flow.client_conn.peername[0]
            if hasattr(flow.client_conn, "address") and flow.client_conn.address:
                return flow.client_conn.address[0]
        except Exception:
            pass
        return "unknown"

    def _write(self, obj: dict):
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except Exception as e:
            ctx.log.warn(f"URLLogger write error: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            self._ensure_daily_logfile()
            self._load_excludes_if_changed()

            client_ip = self._get_client_ip(flow)

            method = flow.request.method
            url = flow.request.pretty_url
            host = flow.request.host
            port = flow.request.port
            path = flow.request.path
            scheme = flow.request.scheme

            if self._is_excluded(url, host):
                return

            headers = dict(flow.request.headers)
            user_agent = headers.get("user-agent", headers.get("User-Agent", ""))
            content_type = headers.get("content-type", headers.get("Content-Type", ""))

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
                "user_agent": user_agent[:200] if user_agent else "",
                "content_type": content_type[:150] if content_type else "",
                "status": "REQUEST",
            }

            self._write(log_entry)
        except Exception as e:
            ctx.log.error(f"URLLogger error on request: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            self._ensure_daily_logfile()
            self._load_excludes_if_changed()

            if not flow.request or not flow.response:
                return

            url = flow.request.pretty_url
            host = flow.request.host
            if self._is_excluded(url, host):
                return

            client_ip = self._get_client_ip(flow)
            status_code = flow.response.status_code
            content_length = len(flow.response.content) if flow.response.content else 0
            content_type = flow.response.headers.get("content-type", "")

            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "url",
                "client_ip": client_ip,
                "method": flow.request.method,
                "url": url,
                "host": host,
                "status_code": status_code,
                "content_length": content_length,
                "content_type": content_type[:150] if content_type else "",
                "status": "RESPONSE",
            }

            self._write(log_entry)
        except Exception as e:
            ctx.log.error(f"URLLogger error on response: {e}")

    def error(self, flow: http.HTTPFlow) -> None:
        try:
            self._ensure_daily_logfile()
            self._load_excludes_if_changed()

            client_ip = self._get_client_ip(flow)
            method = flow.request.method if flow.request else "UNKNOWN"
            url = flow.request.pretty_url if flow.request else "unknown"
            host = flow.request.host if flow.request else "unknown"

            if self._is_excluded(url, host):
                return

            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "url",
                "client_ip": client_ip,
                "method": method,
                "url": url,
                "host": host,
                "error": str(flow.error) if flow.error else "Unknown error",
                "status": "ERROR",
            }

            self._write(log_entry)
        except Exception as e:
            ctx.log.error(f"URLLogger error on error: {e}")


addons = [URLLogger()]
