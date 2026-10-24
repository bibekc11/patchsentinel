"""In-memory database shared by the demo app (synthetic data only)."""
import sqlite3

conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.executescript("""
CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT);
INSERT INTO users(name, email) VALUES ('alice','alice@example.com'),('bob','bob@example.com');
CREATE TABLE orders(id INTEGER PRIMARY KEY, customer TEXT, item TEXT);
INSERT INTO orders(customer, item) VALUES ('alice','keyboard'),('bob','monitor'),('alice','mouse');
CREATE TABLE invoices(id INTEGER PRIMARY KEY, owner TEXT, amount INTEGER);
INSERT INTO invoices(owner, amount) VALUES ('alice',120),('bob',75);
CREATE TABLE products(id INTEGER PRIMARY KEY, title TEXT, price INTEGER);
INSERT INTO products(title, price) VALUES ('desk',200),('lamp',40);
""")
