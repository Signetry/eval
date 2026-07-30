"""Ground-truth fixture for the head-to-head detection benchmark.

A deliberately vulnerable multi-language app with a KNOWN, enumerated set of
planted vulnerabilities. This is the scoring key: any scanner's output is compared
against ``GROUND_TRUTH`` to compute recall (did it find the planted vuln?) and
false-positive rate (did it flag safe code?).

The fixture is embedded as source strings (not files on disk) so the benchmark is
reproducible in CI with no external checkout. A companion SAFE module is included
so false positives can be measured: any finding in a SAFE file is a false positive.

Each ground-truth entry: (id, file, line, category, cwe, description). ``line`` is
approximate (the vulnerable statement); scanners are credited on file+category
match within the file, so small line drift does not penalise a correct detection.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GroundTruthVuln:
    id: str
    file: str
    category: str
    cwe: str
    description: str
    excluded_by_competitors: bool = False  # e.g. open-redirect: Claude filters these out


# --- vulnerable sources -----------------------------------------------------

VULN_APP_PY = '''\
import os, sqlite3, subprocess, pickle, hashlib, flask

app = flask.Flask(__name__)
SECRET_KEY = "sk-live-1234567890abcdefghijABCDEF"
DB_PASSWORD = "SuperSecretP@ssw0rd!"

@app.route("/user")
def get_user():
    user_id = flask.request.args.get("id")
    cur = sqlite3.connect("app.db").cursor()
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cur.execute(query)
    return str(cur.fetchall())

@app.route("/ping")
def ping():
    host = flask.request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)

@app.route("/load")
def load():
    data = flask.request.args.get("data")
    return str(pickle.loads(bytes.fromhex(data)))

@app.route("/render")
def render():
    name = flask.request.args.get("name")
    return "<h1>Hello " + name + "</h1>"

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def run_code(expr):
    return eval(expr)

@app.route("/read")
def read_file():
    fname = flask.request.args.get("file")
    with open("/var/data/" + fname) as f:
        return f.read()

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
'''

VULN_SERVER_JS = '''\
const express = require("express");
const app = express();
const JWT_SECRET = "hardcoded-jwt-secret-do-not-use";

app.get("/redirect", (req, res) => { res.redirect(req.query.url); });

app.get("/exec", (req, res) => {
  const { exec } = require("child_process");
  exec("ls " + req.query.dir, (err, stdout) => res.send(stdout));
});

app.get("/token", (req, res) => { res.send(Math.random().toString(36).slice(2)); });
app.get("/html", (req, res) => { res.send("<div>" + req.query.msg + "</div>"); });
module.exports = app;
'''

PACKAGE_JSON = '''\
{
  "name": "vuln-benchmark",
  "version": "1.0.0",
  "dependencies": { "lodash": "4.17.11", "express": "4.16.0", "minimist": "1.2.0" }
}
'''

# --- safe sources (any finding here is a false positive) --------------------

SAFE_PY = '''\
import sqlite3, subprocess, hashlib, secrets
from markupsafe import escape

def get_user(user_id):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()

def ping(host):
    return subprocess.check_output(["ping", "-c", "1", host])

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def render(name):
    return "<h1>Hello " + escape(name) + "</h1>"

def token():
    return secrets.token_hex(16)

API_URL = "https://api.example.com"
'''

SAFE_JS = '''\
const crypto = require("crypto");
function token() { return crypto.randomBytes(16).toString("hex"); }
const API_URL = "https://api.example.com";
'''

VULN_FILES: dict[str, str] = {
    "src/app.py": VULN_APP_PY,
    "src/server.js": VULN_SERVER_JS,
    "package.json": PACKAGE_JSON,
}

SAFE_FILES: dict[str, str] = {
    "safe/util.py": SAFE_PY,
    "safe/util.js": SAFE_JS,
}

# --- the scoring key --------------------------------------------------------

GROUND_TRUTH: list[GroundTruthVuln] = [
    GroundTruthVuln("GT-1", "src/app.py", "hardcoded_secret", "CWE-798", "Hardcoded API key"),
    GroundTruthVuln("GT-2", "src/app.py", "sql_injection", "CWE-89", "SQL injection via string formatting"),
    GroundTruthVuln("GT-3", "src/app.py", "command_injection", "CWE-78", "Command injection shell=True"),
    GroundTruthVuln("GT-4", "src/app.py", "insecure_deserialization", "CWE-502", "Unpickling untrusted data"),
    GroundTruthVuln("GT-5", "src/app.py", "xss", "CWE-79", "Reflected XSS"),
    GroundTruthVuln("GT-6", "src/app.py", "weak_crypto", "CWE-327", "MD5 for passwords"),
    GroundTruthVuln("GT-7", "src/app.py", "code_injection", "CWE-95", "eval() code injection"),
    GroundTruthVuln("GT-8", "src/app.py", "path_traversal", "CWE-22", "Path traversal"),
    GroundTruthVuln("GT-9", "src/app.py", "debug_enabled", "CWE-489", "Flask debug=True"),
    GroundTruthVuln("GT-10", "src/server.js", "hardcoded_secret", "CWE-798", "Hardcoded JWT secret"),
    GroundTruthVuln("GT-11", "src/server.js", "open_redirect", "CWE-601", "Open redirect",
                    excluded_by_competitors=True),
    GroundTruthVuln("GT-12", "src/server.js", "command_injection", "CWE-78", "Command injection exec"),
    GroundTruthVuln("GT-13", "src/server.js", "insecure_randomness", "CWE-330", "Math.random for token"),
    GroundTruthVuln("GT-14", "src/server.js", "xss", "CWE-79", "Reflected XSS Express"),
]


def in_scope_ground_truth() -> list[GroundTruthVuln]:
    """Ground-truth vulns excluding classes the competitors deliberately filter out
    (e.g. open redirect), so recall is compared on the same in-scope set."""
    return [g for g in GROUND_TRUTH if not g.excluded_by_competitors]
