"""Tk desktop storefront; all network work runs outside the UI thread."""
import argparse
import json
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import messagebox, ttk

from client.api import ApiClient, ApiError

CONFIG = Path.home() / ".pbl4-client.json"

def money(value):
    return f"{value:,}".replace(",", ".") + " đ"

class ShopWindow:
    def __init__(self, root, initial_url=None):
        self.root = root
        self.root.title("Mộc Shop • PBL4 Desktop")
        self.root.geometry("1080x740")
        self.root.minsize(860, 620)
        self.pool = ThreadPoolExecutor(max_workers=1)
        self.future = None
        self.api = None
        self.user = None
        self.products_by_id = {}
        self.orders_by_id = {}
        self.connected = False
        self.protected = []
        self.general = []
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 11))
        style.configure("TFrame", background="#f4f6f2")
        style.configure("TLabel", background="#f4f6f2", foreground="#203e36")
        style.configure("TButton", padding=(12, 8))
        style.configure("Accent.TButton", background="#245c49", foreground="white")
        style.map("Accent.TButton", background=[("active", "#34735d")])
        style.configure("Treeview", rowheight=36, background="white", fieldbackground="white")
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("Title.TLabel", font=("Segoe UI", 26, "bold"))
        outer = ttk.Frame(root, padding=22)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="MỘC SHOP", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="Góc làm việc, theo cách của bạn.").pack(side="left", padx=24)
        self.identity = ttk.Label(header, text="Chưa đăng nhập")
        self.identity.pack(side="right")
        connection = ttk.LabelFrame(outer, text="1. Kết nối máy server", padding=12)
        connection.pack(fill="x", pady=(16, 10))
        saved = "http://127.0.0.1:8080"
        try:
            saved = json.loads(CONFIG.read_text(encoding="utf-8"))["server_url"]
        except (OSError, ValueError, KeyError, TypeError):
            pass
        self.url = tk.StringVar(value=initial_url or saved)
        self.url_entry = ttk.Entry(connection, textvariable=self.url)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.connect_button = ttk.Button(connection, text="Kết nối", command=self.connect, style="Accent.TButton")
        self.connect_button.pack(side="left")
        account = ttk.Frame(outer)
        account.pack(fill="x", pady=(0, 12))
        self.login_button = self.button(account, "Đăng nhập", lambda: self.auth_dialog(False))
        self.register_button = self.button(account, "Tạo tài khoản", lambda: self.auth_dialog(True))
        self.logout_button = self.button(account, "Đăng xuất", self.logout, protected=True)
        ttk.Label(account, text="Demo học tập • Không thanh toán thật").pack(side="right")
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        catalog = ttk.Frame(self.tabs, padding=12)
        cart = ttk.Frame(self.tabs, padding=12)
        orders = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(catalog, text="  Sản phẩm  ")
        self.tabs.add(cart, text="  Giỏ hàng  ")
        self.tabs.add(orders, text="  Đơn hàng của tôi  ")
        search = ttk.Frame(catalog)
        search.pack(fill="x", pady=(0, 10))
        self.query = tk.StringVar()
        ttk.Entry(search, textvariable=self.query).pack(side="left", fill="x", expand=True)
        self.button(search, "Tìm kiếm", self.load_products)
        self.catalog = self.table(catalog, ("name", "category", "price", "stock"),
                                  ("Sản phẩm", "Danh mục", "Giá", "Còn lại"), (350, 180, 140, 90))
        self.catalog.bind("<<TreeviewSelect>>", self.product_selected)
        self.description = ttk.Label(catalog, text="Kết nối server để xem sản phẩm.", wraplength=930)
        self.description.pack(anchor="w", pady=10)
        add = ttk.Frame(catalog)
        add.pack(fill="x")
        ttk.Label(add, text="Số lượng trong giỏ:").pack(side="left")
        self.quantity = tk.StringVar(value="1")
        ttk.Spinbox(add, from_=1, to=10, textvariable=self.quantity, width=5, state="readonly").pack(side="left", padx=10)
        self.button(add, "Thêm / cập nhật giỏ", self.add_cart, protected=True, accent=True)
        ttk.Label(add, text="Đặt số lượng cuối cùng, tối đa 10 mỗi sản phẩm.").pack(side="left", padx=10)
        cartbar = ttk.Frame(cart)
        cartbar.pack(fill="x", pady=(0, 10))
        self.button(cartbar, "Tải lại giỏ", self.load_cart, protected=True)
        self.button(cartbar, "Xóa sản phẩm đã chọn", self.remove_cart, protected=True)
        self.cart = self.table(cart, ("name", "price", "qty", "total"),
                               ("Sản phẩm", "Đơn giá", "Số lượng", "Thành tiền"), (350, 160, 90, 160))
        cartbottom = ttk.Frame(cart)
        cartbottom.pack(fill="x", pady=14)
        self.total = ttk.Label(cartbottom, text="Tổng cộng: 0 đ", font=("Segoe UI", 16, "bold"))
        self.total.pack(side="left")
        self.checkout_button = self.button(cartbottom, "Đặt đơn mô phỏng", self.checkout, protected=True, accent=True)
        orderbar = ttk.Frame(orders)
        orderbar.pack(fill="x", pady=(0, 10))
        self.button(orderbar, "Tải lại đơn hàng", self.load_orders, protected=True)
        self.button(orderbar, "Xem chi tiết", self.order_detail, protected=True)
        self.orders = self.table(orders, ("id", "created", "total"),
                                 ("Mã đơn", "Thời gian (UTC)", "Tổng tiền"), (330, 300, 150))
        self.orders.bind("<Double-1>", lambda event: self.order_detail())
        self.status = tk.StringVar(value="Nhập địa chỉ server do thành viên chạy Linux cung cấp, rồi bấm Kết nối.")
        ttk.Label(outer, textvariable=self.status, wraplength=980).pack(fill="x", pady=(12, 0))
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.update_controls()

    def button(self, parent, label, command, protected=False, accent=False):
        widget = ttk.Button(parent, text=label, command=command,
                            style="Accent.TButton" if accent else "TButton")
        widget.pack(side="left", padx=(0, 8))
        (self.protected if protected else self.general).append(widget)
        return widget

    def table(self, parent, columns, headings, widths):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for key, heading, width in zip(columns, headings, widths):
            tree.heading(key, text=heading)
            tree.column(key, width=width, minwidth=70)
        bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return tree

    def update_controls(self):
        busy = self.future is not None
        for widget in self.general:
            widget.configure(state="normal" if self.connected and not busy else "disabled")
        for widget in self.protected:
            widget.configure(state="normal" if self.user and not busy else "disabled")
        pending = self.api is not None and self.api.pending_order_key is not None
        self.connect_button.configure(state="disabled" if busy or self.user or pending else "normal")
        self.url_entry.configure(state="disabled" if busy or self.user or pending else "normal")
        if pending:
            self.register_button.configure(state="disabled")
        if self.user:
            self.login_button.configure(state="disabled")
            self.register_button.configure(state="disabled")
        if self.api and self.api.pending_order_key:
            self.checkout_button.configure(text="Thử lại đơn vừa gửi")
        else:
            self.checkout_button.configure(text="Đặt đơn mô phỏng")

    def run(self, work, success, text="Đang liên hệ server…", failure=None):
        if self.future:
            return
        self.status.set(text)
        self.future = self.pool.submit(work)
        self.update_controls()
        def poll():
            if not self.future.done():
                self.root.after(80, poll)
                return
            future, self.future = self.future, None
            try:
                result = future.result()
            except Exception as exc:
                if failure:
                    failure()
                if isinstance(exc, ApiError) and exc.code == "unauthorized":
                    self.clear_user()
                message = str(exc) if isinstance(exc, (ApiError, ValueError)) else "Dữ liệu hoặc kết nối không hợp lệ. Hãy thử tải lại."
                if self.api and self.api.pending_order_key:
                    message += " Đơn có thể đã được tạo: bấm 'Thử lại đơn vừa gửi' để nhận kết quả, không đổi giỏ."
                self.status.set(message)
                messagebox.showerror("Chưa hoàn tất", message, parent=self.root)
            else:
                self.status.set("Sẵn sàng.")
                success(result)
            self.update_controls()
        self.root.after(80, poll)

    def connect(self):
        try:
            api = ApiClient(self.url.get())
        except ValueError as exc:
            messagebox.showerror("Địa chỉ server", str(exc), parent=self.root)
            return
        def work():
            if api.request("GET", "/health").get("status") != "ok":
                raise ApiError("bad_response")
            return api.products()
        def done(products):
            self.api, self.connected = api, True
            self.url.set(api.base_url)
            self.show_products(products)
            self.status.set("Đã kết nối server. Bạn có thể tạo tài khoản hoặc đăng nhập.")
            try:
                CONFIG.write_text(json.dumps({"server_url": api.base_url}), encoding="utf-8")
            except OSError:
                pass
        self.connected = False
        self.run(work, done, "Đang kiểm tra server…")

    def auth_dialog(self, register):
        if not self.connected or self.future:
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Tạo tài khoản" if register else "Đăng nhập")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        body = ttk.Frame(dialog, padding=24)
        body.pack(fill="both", expand=True)
        values = {}
        fields = ([("name", "Tên hiển thị")] if register else []) + [("email", "Email"), ("password", "Mật khẩu")]
        for row, (key, label) in enumerate(fields):
            ttk.Label(body, text=label).grid(row=row * 2, column=0, sticky="w", pady=(6, 2))
            value = tk.StringVar()
            values[key] = value
            entry = ttk.Entry(body, textvariable=value, width=40, show="*" if key == "password" else "")
            entry.grid(row=row * 2 + 1, column=0, sticky="ew")
            if row == 0:
                entry.focus_set()
        ttk.Label(body, text="Mật khẩu: 12–128 ký tự. Chỉ dùng tài khoản demo.").grid(row=7, column=0, pady=12)
        def submit():
            payload = {key: value.get() for key, value in values.items()}
            dialog.destroy()
            if register:
                def registered(result):
                    self.status.set("Tạo tài khoản thành công. Bấm Đăng nhập để tiếp tục.")
                    messagebox.showinfo("Đã tạo tài khoản", "Bây giờ hãy đăng nhập với email và mật khẩu vừa tạo.", parent=self.root)
                self.run(lambda: self.api.request("POST", "/auth/register", payload), registered)
            else:
                def logged_in(user):
                    self.user = user
                    self.identity.configure(text="Xin chào, " + user["name"])
                    self.status.set("Đã đăng nhập. Chọn sản phẩm, số lượng rồi thêm vào giỏ.")
                self.run(lambda: self.api.login(payload["email"], payload["password"]), logged_in)
        ttk.Button(body, text="Tạo tài khoản" if register else "Đăng nhập",
                   command=submit, style="Accent.TButton").grid(row=8, column=0, sticky="ew")
        dialog.bind("<Return>", lambda event: submit())

    def clear_user(self):
        self.user = None
        if self.api:
            self.api.token = None
        self.identity.configure(text="Chưa đăng nhập")
        for tree in (self.cart, self.orders):
            tree.delete(*tree.get_children())
        self.orders_by_id.clear()
        self.total.configure(text="Tổng cộng: 0 đ")

    def logout(self):
        if self.api.pending_order_key:
            messagebox.showwarning("Đơn chưa xác nhận", "Hãy thử lại đơn vừa gửi trước khi đăng xuất.", parent=self.root)
            return
        def done(result):
            self.clear_user()
            self.status.set("Đã đăng xuất; token đã xóa khỏi client.")
        self.run(self.api.logout, done, failure=self.clear_user)

    def show_products(self, products):
        self.products_by_id = {str(p["id"]): p for p in products}
        self.catalog.delete(*self.catalog.get_children())
        for product in products:
            self.catalog.insert("", "end", iid=str(product["id"]), values=(
                product["name"], product["category"], money(product["price"]), product["stock"]))
        self.description.configure(text=f"{len(products)} sản phẩm. Chọn một dòng để xem mô tả.")

    def load_products(self):
        query = self.query.get()
        self.run(lambda: self.api.products(query), self.show_products)

    def product_selected(self, event=None):
        selected = self.catalog.selection()
        if selected:
            product = self.products_by_id[selected[0]]
            self.description.configure(text=product["description"])

    def can_change_cart(self):
        if not self.user or self.future:
            return False
        if self.api.pending_order_key:
            messagebox.showwarning("Đơn chưa xác nhận", "Hãy bấm Thử lại đơn vừa gửi trước khi đổi giỏ.", parent=self.root)
            return False
        return True

    def show_cart(self, cart):
        self.cart.delete(*self.cart.get_children())
        for item in cart["items"]:
            product = item["product"]
            self.cart.insert("", "end", iid=str(product["id"]), values=(
                product["name"], money(product["price"]), item["quantity"], money(item["line_total"])))
        self.total.configure(text="Tổng cộng: " + money(cart["total"]))

    def add_cart(self):
        if not self.can_change_cart():
            return
        selected = self.catalog.selection()
        if not selected:
            messagebox.showinfo("Chọn sản phẩm", "Bấm một sản phẩm trong bảng trước.", parent=self.root)
            return
        product_id = selected[0]
        try:
            quantity = int(self.quantity.get())
        except ValueError:
            return
        def done(cart):
            self.show_cart(cart)
            self.tabs.select(1)
            self.status.set("Đã cập nhật giỏ. Giá và tổng tiền được tính trên server.")
        self.run(lambda: self.api.request("PUT", f"/cart/items/{product_id}", {"quantity": quantity}), done)

    def load_cart(self):
        self.run(lambda: self.api.request("GET", "/cart"), self.show_cart)

    def remove_cart(self):
        if not self.can_change_cart():
            return
        selected = self.cart.selection()
        if not selected:
            return
        product_id = selected[0]
        def work():
            self.api.request("DELETE", f"/cart/items/{product_id}")
            return self.api.request("GET", "/cart")
        self.run(work, self.show_cart)

    def checkout(self):
        if not self.user or self.future:
            return
        if not self.api.pending_order_key and not messagebox.askyesno(
                "Xác nhận đặt đơn", "Tạo đơn từ giỏ hàng hiện tại? Đây là đơn mô phỏng, không thu tiền.", parent=self.root):
            return
        def done(order):
            self.show_cart({"items": [], "total": 0})
            self.status.set("Đặt đơn thành công: " + order["id"])
            self.show_order_dialog(order)
            def refresh():
                return self.api.products(), self.api.request("GET", "/orders")
            def refreshed(data):
                self.show_products(data[0])
                self.show_orders(data[1])
                self.status.set("Đặt đơn thành công. Tồn kho và lịch sử đã cập nhật.")
            self.run(refresh, refreshed)
            self.tabs.select(2)
        self.run(self.api.checkout, done, "Đang xác nhận đơn với server…")

    def show_orders(self, orders):
        self.orders_by_id = {order["id"]: order for order in orders["items"]}
        self.orders.delete(*self.orders.get_children())
        for order in orders["items"]:
            self.orders.insert("", "end", iid=order["id"], values=(
                order["id"], order["created_at"][:19].replace("T", " "), money(order["total"])))

    def load_orders(self):
        self.run(lambda: self.api.request("GET", "/orders"), self.show_orders)

    def order_detail(self):
        selected = self.orders.selection()
        if selected and not self.future:
            order_id = selected[0]
            self.run(lambda: self.api.request("GET", "/orders/" + order_id),
                     lambda data: self.show_order_dialog(data["order"]))

    def show_order_dialog(self, order):
        lines = [f"Mã đơn: {order['id']}", f"Thời gian UTC: {order['created_at']}", ""]
        lines.extend(f"{item['name']} × {item['quantity']} — {money(item['price'] * item['quantity'])}"
                     for item in order["items"])
        lines.extend(["", "Tổng cộng: " + money(order["total"]), "Đơn mô phỏng • Không thu tiền"])
        messagebox.showinfo("Đơn hàng", "\n".join(lines), parent=self.root)

    def close(self):
        if self.future:
            messagebox.showinfo("Đang xử lý", "Đợi yêu cầu hiện tại hoàn tất rồi đóng ứng dụng.", parent=self.root)
            return
        if self.api and self.api.pending_order_key:
            if not messagebox.askyesno("Đơn chưa xác nhận",
                    "Đơn có thể đã được tạo. Đóng ứng dụng sẽ mất mã thử lại. Lần sau hãy kiểm tra lịch sử đơn trước khi đặt tiếp. Vẫn đóng?", parent=self.root):
                return
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()

def main():
    parser = argparse.ArgumentParser(description="Mộc Shop desktop client")
    parser.add_argument("--server", help="Server URL, e.g. http://192.168.1.20:8080")
    args = parser.parse_args()
    root = tk.Tk()
    ShopWindow(root, args.server)
    root.mainloop()
