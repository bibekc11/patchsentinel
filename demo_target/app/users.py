from app.db import conn

TABLE = "users"


def get_user(username):
    cur = conn.execute(f"SELECT id, name, email FROM users WHERE name = '{username}'")
    return cur.fetchone()


def search_orders(customer):
    query = "SELECT id, item FROM orders WHERE customer = '" + customer + "'"
    return conn.execute(query).fetchall()


def count_users():
    return conn.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0]


def get_invoice(owner):
    cur = conn.execute(f"SELECT id, amount FROM invoices WHERE owner = '{owner}'")
    return cur.fetchall()


def find_product(title):
    cur = conn.execute(f"SELECT id, price FROM products WHERE title = '{title}'")
    return cur.fetchone()
