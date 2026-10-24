from app import files, network, users


def test_get_user():
    assert users.get_user("alice")[1] == "alice"


def test_search_orders():
    assert len(users.search_orders("alice")) == 2


def test_count_users():
    assert users.count_users() == 2


def test_get_invoice():
    assert users.get_invoice("bob") == [(2, 75)]


def test_find_product():
    assert users.find_product("lamp")[1] == 40


def test_read_report():
    assert "revenue" in files.read_report("q1.txt")


def test_load_template():
    assert files.load_template("welcome.tpl").startswith("WELCOME")


def test_lookup_host():
    assert network.lookup_host("example.com").strip() == "resolving example.com"


def test_trace_host():
    assert network.trace_host("example.org").strip() == "tracing example.org"


def test_tool_version():
    assert network.tool_version() == 0
