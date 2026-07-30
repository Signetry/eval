"""PUBLIC family (cases 1-7): OWASP Top 10 / real-CVE-shaped vulnerability patterns.

Each case is a minimal reimplementation of a publicly documented vulnerability
class, labelled with its canonical CWE. Provenance cites the public source of the
pattern (OWASP category or a representative CVE) — the code is original, the
*pattern* is public and auditable.
"""
from __future__ import annotations

from .schema import Case, ExpectedFinding, Family

CASES: list[Case] = [
    Case(
        id="PUB-01-sqli-python",
        family=Family.PUBLIC,
        language="python",
        title="SQL injection via f-string in a Flask handler",
        provenance="OWASP A03:2021 Injection; CWE-89. Pattern per OWASP SQL Injection cheat sheet.",
        files={"app.py": '''\
import sqlite3, flask
app = flask.Flask(__name__)

@app.route("/search")
def search():
    term = flask.request.args.get("q")
    con = sqlite3.connect("db.sqlite")
    cur = con.cursor()
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return str(cur.fetchall())
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "app.py")],
    ),
    Case(
        id="PUB-02-cmdi-node",
        family=Family.PUBLIC,
        language="javascript",
        title="OS command injection via child_process in Express",
        provenance="OWASP A03:2021 Injection; CWE-78. Node child_process.exec misuse (CVE-2019 class).",
        files={"routes.js": '''\
const express = require("express");
const { exec } = require("child_process");
const router = express.Router();

router.get("/nslookup", (req, res) => {
  exec("nslookup " + req.query.host, (err, out) => res.send(out));
});
module.exports = router;
'''},
        expected=[ExpectedFinding("CWE-78", "command_injection", "routes.js")],
    ),
    Case(
        id="PUB-03-pickle-python",
        family=Family.PUBLIC,
        language="python",
        title="Insecure deserialization of an untrusted pickle",
        provenance="OWASP A08:2021 Software and Data Integrity Failures; CWE-502. Python pickle RCE pattern.",
        files={"session.py": '''\
import pickle, base64, flask
app = flask.Flask(__name__)

@app.route("/restore")
def restore():
    blob = flask.request.cookies.get("session")
    state = pickle.loads(base64.b64decode(blob))
    return str(state)
'''},
        expected=[ExpectedFinding("CWE-502", "insecure_deserialization", "session.py")],
    ),
    Case(
        id="PUB-04-xss-node",
        family=Family.PUBLIC,
        language="javascript",
        title="Reflected XSS: user input echoed into HTML",
        provenance="OWASP A03:2021 (XSS); CWE-79. Reflected XSS reference pattern.",
        files={"profile.js": '''\
const express = require("express");
const app = express();

app.get("/hello", (req, res) => {
  res.send("<html><body>Welcome " + req.query.name + "</body></html>");
});
module.exports = app;
'''},
        expected=[ExpectedFinding("CWE-79", "xss", "profile.js")],
    ),
    Case(
        id="PUB-05-path-traversal-python",
        family=Family.PUBLIC,
        language="python",
        title="Path traversal in a file-download endpoint",
        provenance="OWASP A01:2021 Broken Access Control; CWE-22. Directory traversal reference.",
        files={"download.py": '''\
import flask
app = flask.Flask(__name__)

@app.route("/file")
def get_file():
    name = flask.request.args.get("name")
    path = "/srv/uploads/" + name
    with open(path, "rb") as fh:
        return fh.read()
'''},
        expected=[ExpectedFinding("CWE-22", "path_traversal", "download.py")],
    ),
    Case(
        id="PUB-06-hardcoded-secret",
        family=Family.PUBLIC,
        language="python",
        title="Hardcoded cloud credential in source",
        provenance="OWASP A07:2021 Identification and Auth Failures; CWE-798. Hardcoded credentials.",
        files={"settings.py": '''\
# Production configuration
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE1"
DATABASE_PASSWORD = "pr0d-db-P@ssw0rd-2024"

def connect():
    return (AWS_ACCESS_KEY_ID, DATABASE_PASSWORD)
'''},
        expected=[ExpectedFinding("CWE-798", "hardcoded_secret", "settings.py")],
    ),
    Case(
        id="PUB-07-weak-hash-python",
        family=Family.PUBLIC,
        language="python",
        title="Weak password hashing with MD5",
        provenance="OWASP A02:2021 Cryptographic Failures; CWE-327. Broken/weak hash for passwords.",
        files={"auth.py": '''\
import hashlib

def store_password(username, password):
    digest = hashlib.md5(password.encode()).hexdigest()
    save(username, digest)

def save(u, d):
    pass
'''},
        expected=[ExpectedFinding("CWE-327", "weak_crypto", "auth.py")],
    ),
]
