import sqlite3
from contextlib import closing
from pathlib import Path

from flask import current_app, g


PRODUCTS = [
    (1, "Bàn phím Pebble", "Thiết bị", "keyboard", 890000, 24,
     "Gõ êm, kết nối không dây và một sắc xanh dịu cho góc làm việc của bạn."),
    (2, "Đèn bàn Arc", "Góc bàn", "lamp", 650000, 18,
     "Ánh sáng ấm, thiết kế gọn gàng. Một khoảng sáng vừa đủ cho những ý tưởng mới."),
    (3, "Sổ tay Everyday", "Văn phòng phẩm", "notebook", 125000, 40,
     "160 trang giấy màu kem để ghi lại ý tưởng, kế hoạch và những điều nhỏ mỗi ngày."),
    (4, "Tai nghe Studio", "Thiết bị", "headphones", 1250000, 16,
     "Đệm tai mềm, âm thanh cân bằng cho những giờ tập trung và phút nghỉ ngơi."),
    (5, "Bình giữ nhiệt Terra", "Góc bàn", "bottle", 320000, 32,
     "Dung tích 500 ml, thân thép không gỉ và màu đất nung gần gũi."),
    (6, "Khay để bàn Form", "Văn phòng phẩm", "tray", 210000, 25,
     "Giữ bút, chìa khóa và những món đồ nhỏ ngăn nắp trong tầm tay."),
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
  illustration TEXT NOT NULL, price INTEGER NOT NULL CHECK(price > 0),
  stock INTEGER NOT NULL CHECK(stock >= 0), description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cart (
  user_id INTEGER NOT NULL REFERENCES users(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 10),
  PRIMARY KEY(user_id, product_id)
);
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
  checkout_key TEXT NOT NULL UNIQUE, total INTEGER NOT NULL CHECK(total > 0),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS order_items (
  order_id TEXT NOT NULL REFERENCES orders(id), product_id INTEGER NOT NULL,
  name TEXT NOT NULL, price INTEGER NOT NULL, quantity INTEGER NOT NULL,
  PRIMARY KEY(order_id, product_id)
);
"""


def connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(path)) as db, db:
        db.executescript(SCHEMA)
        db.executemany("INSERT OR IGNORE INTO products VALUES (?, ?, ?, ?, ?, ?, ?)", PRODUCTS)


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()
