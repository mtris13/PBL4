"""Small synchronous HTTP API, called off the Tk UI thread."""
import json
import socket
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

MESSAGES = {
    "invalid_credentials": "Email hoặc mật khẩu không đúng.",
    "unauthorized": "Phiên đã hết hạn. Hãy đăng nhập lại.",
    "email_unavailable": "Email đã được sử dụng. Hãy đăng nhập hoặc dùng email khác.",
    "login_throttled": "Đăng nhập sai quá nhiều lần. Hãy đợi rồi thử lại.",
    "stock_unavailable": "Không đủ tồn kho hoặc số lượng ngoài 1–10. Hãy tải lại giỏ hàng.",
    "empty_cart": "Giỏ hàng đang trống.",
    "invalid_fields": "Kiểm tra thông tin: tên 2–60 ký tự, mật khẩu 12–128 ký tự.",
    "invalid_request": "Thông tin gửi lên không hợp lệ.",
    "not_found": "Không tìm thấy sản phẩm hoặc đơn hàng.",
    "network": "Không kết nối được server. Kiểm tra IP, cùng mạng Wi-Fi, server và firewall.",
    "bad_response": "Server trả dữ liệu không đúng API. Kiểm tra địa chỉ và phiên bản server.",
}

class ApiError(Exception):
    def __init__(self, code, status=0, retry_after=None):
        self.code, self.status = code, status
        message = MESSAGES.get(code, f"Yêu cầu thất bại (HTTP {status}, {code}).")
        if retry_after:
            message += f" Thử lại sau {retry_after} giây."
        super().__init__(message)

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def normalize_url(value):
    value = value.strip().rstrip("/")
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
        port = parts.port
        if (parts.scheme not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.query or parts.fragment or parts.path not in ("", "/api/v1")
                or any(c.isspace() or ord(c) < 32 for c in value)
                or (port is not None and not 1 <= port <= 65535)):
            raise ValueError
    except ValueError:
        raise ValueError("Nhập địa chỉ dạng http://192.168.1.20:8080 (không có mật khẩu hoặc query).") from None
    return urlunsplit((parts.scheme, parts.netloc, "/api/v1", "", ""))

class ApiClient:
    def __init__(self, base_url, timeout=8):
        self.base_url = normalize_url(base_url)
        self.timeout = timeout
        self.token = None
        self.user_email = None
        self.pending_order_key = None
        # A LAN request must not accidentally go through a machine's corporate proxy.
        # HTTPS uses Python's default certificate validation.
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def request(self, method, path, payload=None, headers=None):
        request_headers = {"Accept": "application/json"}
        if self.token:
            request_headers["Authorization"] = "Bearer " + self.token
        if headers:
            request_headers.update(headers)
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        req = Request(self.base_url + path, data=data, headers=request_headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                if response.status == 204:
                    return None
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ApiError("bad_response")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise ApiError("bad_response")
                return result
        except HTTPError as exc:
            try:
                body = json.loads(exc.read(65536))
                code = body["error"]["code"]
                if not isinstance(code, str):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                code = "http_error"
            finally:
                exc.close()
            raise ApiError(code, exc.code, exc.headers.get("Retry-After")) from None
        except (URLError, TimeoutError, socket.timeout, ConnectionError, OSError, HTTPException):
            raise ApiError("network") from None
        except (ValueError, UnicodeError):
            raise ApiError("bad_response") from None

    def login(self, email, password):
        if self.pending_order_key and email.strip().lower() != self.user_email:
            raise ValueError("Hãy đăng nhập lại đúng tài khoản đã gửi đơn để kiểm tra kết quả.")
        result = self.request("POST", "/auth/login", {"email": email, "password": password})
        self.token = result["token"]
        self.user_email = result["user"]["email"].strip().lower()
        return result["user"]

    def logout(self):
        try:
            return self.request("POST", "/auth/logout")
        finally:
            self.token = None
            self.pending_order_key = None

    def products(self, query=""):
        return self.request("GET", "/products?" + urlencode({"q": query}))["items"]

    def checkout(self):
        # Explicit retry uses exactly the same key after an ambiguous network/5xx result.
        if self.pending_order_key is None:
            self.pending_order_key = uuid4().hex
        try:
            result = self.request("POST", "/orders",
                                  headers={"Idempotency-Key": self.pending_order_key})
        except ApiError as exc:
            if 400 <= exc.status < 500 and exc.status not in (401, 408, 429):
                self.pending_order_key = None
            raise
        order = result.get("order")
        if (not isinstance(order, dict) or not isinstance(order.get("id"), str)
                or type(order.get("total")) is not int or not isinstance(order.get("items"), list)
                or not isinstance(order.get("created_at"), str)):
            raise ApiError("bad_response")
        self.pending_order_key = None
        return order
