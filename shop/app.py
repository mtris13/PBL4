import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from uuid import uuid4

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import SecurityError

from shop.database import close_db, get_db, initialize


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SHOP_SECRET_KEY"),
        DATABASE=os.environ.get("SHOP_DATABASE", str(Path("runtime") / "shop.sqlite3")),
        SESSION_COOKIE_NAME="pbl4_session", SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=True,
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        MAX_CONTENT_LENGTH=16384, MAX_FORM_MEMORY_SIZE=16384, MAX_FORM_PARTS=20,
        TRUSTED_HOSTS=["localhost", "127.0.0.1"],
    )
    if config:
        app.config.update(config)
    if not app.config["SECRET_KEY"] or len(app.config["SECRET_KEY"]) < 32:
        raise ValueError("Set SHOP_SECRET_KEY to a random secret of at least 32 characters")
    initialize(app.config["DATABASE"])
    app.teardown_appcontext(close_db)
    # Same password-hashing work when email does not exist; value is not an account.
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32))

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Bạn hãy đăng nhập để tiếp tục nhé.", "info")
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    @app.before_request
    def load_user_and_csrf():
        # No ProxyFix: forwarded headers never change identity/host/scheme in the app.
        # Health checks must not create or refresh browser sessions at the ALB boundary.
        if request.endpoint == "health":
            return
        g.user = get_db().execute("SELECT id, name, email FROM users WHERE id = ?",
                                 (session.get("user_id"),)).fetchone()
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            supplied = request.form.get("csrf_token", "")
            if not secrets.compare_digest(supplied.encode("utf-8"), session["csrf"].encode("utf-8")):
                abort(400, description="Phiên biểu mẫu đã hết hạn. Hãy tải lại trang rồi thử lại.")

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'none'; style-src 'self'; img-src 'self'; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def common():
        count = 0
        if g.get("user"):
            count = get_db().execute("SELECT COALESCE(SUM(quantity), 0) FROM cart WHERE user_id = ?",
                                     (g.user["id"],)).fetchone()[0]
        return {"cart_count": count}

    @app.template_filter("vnd")
    def vnd(value):
        return f"{value:,}".replace(",", ".") + " ₫"

    @app.get("/healthz")
    def health():
        get_db().execute("SELECT 1").fetchone()
        return {"status": "ok"}

    @app.get("/")
    def catalog():
        query = request.args.get("q", "")
        category = request.args.get("category", "")
        if len(query) > 200 or len(category) > 40:
            abort(400)
        # LIKE wildcard escaping + bound parameters: user input is never SQL syntax.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        products = get_db().execute(
            "SELECT * FROM products WHERE name LIKE ? ESCAPE '\\' AND (? = '' OR category = ?) ORDER BY id",
            (f"%{escaped}%", category, category),
        ).fetchall()
        return render_template("catalog.html", products=products, query=query, category=category)

    @app.get("/products/<int:product_id>")
    def product(product_id):
        item = get_db().execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if item is None:
            abort(404)
        return render_template("product.html", product=item)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if (not 2 <= len(name) <= 60 or len(email) > 254
                    or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
                    or not 12 <= len(password) <= 128):
                return render_template("auth.html", mode="register", error="Kiểm tra tên, email và mật khẩu từ 12–128 ký tự."), 400
            try:
                db = get_db()
                db.execute("INSERT INTO users(name, email, password_hash) VALUES (?, ?, ?)",
                           (name, email, generate_password_hash(password)))
                db.commit()
            except sqlite3.IntegrityError:
                db.rollback()
                return render_template("auth.html", mode="register", error="Không thể tạo tài khoản với thông tin này."), 409
            flash("Tài khoản đã được tạo. Bạn có thể đăng nhập.", "success")
            return redirect(url_for("login"), code=303)
        return render_template("auth.html", mode="register")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if len(email) > 254 or len(password) > 128:
                abort(400)
            user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            valid = check_password_hash(user["password_hash"] if user else dummy_hash, password)
            if not user or not valid:
                return render_template("auth.html", mode="login", error="Email hoặc mật khẩu không đúng."), 401
            session.clear()
            session["user_id"] = user["id"]
            session["csrf"] = secrets.token_urlsafe(32)
            session.permanent = True
            return redirect(url_for("catalog"), code=303)
        return render_template("auth.html", mode="login")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("catalog"), code=303)

    @app.post("/cart/add/<int:product_id>")
    @login_required
    def add_cart(product_id):
        try:
            quantity = int(request.form.get("quantity", "1"))
        except ValueError:
            abort(400)
        if not 1 <= quantity <= 10:
            abort(400)
        db = get_db()
        db.execute("BEGIN IMMEDIATE")
        item = db.execute("SELECT stock FROM products WHERE id = ?", (product_id,)).fetchone()
        if item is None:
            abort(404)
        old = db.execute("SELECT quantity FROM cart WHERE user_id = ? AND product_id = ?",
                         (g.user["id"], product_id)).fetchone()
        total = quantity + (old["quantity"] if old else 0)
        if total > min(10, item["stock"]):
            db.rollback()
            flash("Số lượng vượt quá tồn kho hoặc giới hạn 10 sản phẩm.", "error")
            return redirect(url_for("cart"), code=303)
        db.execute("INSERT INTO cart VALUES (?, ?, ?) ON CONFLICT(user_id, product_id) DO UPDATE SET quantity=excluded.quantity",
                   (g.user["id"], product_id, total))
        db.commit()
        flash("Đã thêm vào giỏ hàng.", "success")
        return redirect(url_for("cart"), code=303)

    @app.get("/cart")
    @login_required
    def cart():
        items = get_db().execute("SELECT p.*, c.quantity FROM cart c JOIN products p ON p.id=c.product_id WHERE c.user_id=?",
                                 (g.user["id"],)).fetchall()
        session.setdefault("checkout_key", secrets.token_urlsafe(32))
        return render_template("cart.html", items=items, total=sum(i["price"] * i["quantity"] for i in items))

    @app.post("/cart/remove/<int:product_id>")
    @login_required
    def remove_cart(product_id):
        db = get_db()
        db.execute("DELETE FROM cart WHERE user_id=? AND product_id=?", (g.user["id"], product_id))
        db.commit()
        return redirect(url_for("cart"), code=303)

    @app.post("/checkout")
    @login_required
    def checkout():
        key = request.form.get("checkout_key", "")
        if not key or len(key) > 100:
            abort(400)
        db = get_db()
        db.execute("BEGIN IMMEDIATE")
        existing = db.execute("SELECT id FROM orders WHERE checkout_key=? AND user_id=?", (key, g.user["id"])).fetchone()
        if existing:
            db.rollback()
            return redirect(url_for("order", order_id=existing["id"]), code=303)
        if not secrets.compare_digest(key.encode("utf-8"), session.get("checkout_key", "").encode("utf-8")):
            abort(400)
        items = db.execute("SELECT p.*, c.quantity FROM cart c JOIN products p ON p.id=c.product_id WHERE c.user_id=?",
                           (g.user["id"],)).fetchall()
        if not items or any(i["quantity"] > i["stock"] for i in items):
            db.rollback()
            flash("Giỏ hàng trống hoặc sản phẩm không đủ tồn kho.", "error")
            return redirect(url_for("cart"), code=303)
        order_id = uuid4().hex
        total = sum(i["price"] * i["quantity"] for i in items)
        db.execute("INSERT INTO orders VALUES (?, ?, ?, ?, ?)",
                   (order_id, g.user["id"], key, total, datetime.now(timezone.utc).isoformat()))
        for item in items:
            db.execute("INSERT INTO order_items VALUES (?, ?, ?, ?, ?)",
                       (order_id, item["id"], item["name"], item["price"], item["quantity"]))
            db.execute("UPDATE products SET stock=stock-? WHERE id=?", (item["quantity"], item["id"]))
        db.execute("DELETE FROM cart WHERE user_id=?", (g.user["id"],))
        db.commit()
        session.pop("checkout_key", None)
        return redirect(url_for("order", order_id=order_id), code=303)

    @app.get("/orders/<order_id>")
    @login_required
    def order(order_id):
        record = get_db().execute("SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, g.user["id"])).fetchone()
        if record is None:
            abort(404)
        items = get_db().execute("SELECT * FROM order_items WHERE order_id=?", (order_id,)).fetchall()
        return render_template("order.html", order=record, items=items)

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(413)
    def expected_error(error):
        # Fixed copy, no reflection of exception text, URI, credentials or payload.
        if isinstance(error, SecurityError):
            # Invalid Host prevents Flask constructing a URL adapter; don't render
            # templates using url_for() in this branch.
            return app.response_class("Invalid request host.", status=400, mimetype="text/plain")
        return render_template("error.html", code=error.code), error.code

    return app
