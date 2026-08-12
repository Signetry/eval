"""ACADEMIC family (cases 8-14): NIST SARD / Juliet / CWE-catalogue-shaped snippets.

These mirror the structure of labelled academic vulnerability datasets (a "bad"
sink reached by a tainted source), each tagged with its CWE. The code is original;
the labelled pattern follows the public CWE catalogue and Juliet-style test-case
shape so the ground truth is standard and auditable.
"""
from __future__ import annotations

from .schema import Case, ExpectedFinding, Family

CASES: list[Case] = [
    Case(
        id="ACAD-08-eval-python",
        family=Family.ACADEMIC,
        language="python",
        title="CWE-95: eval() on tainted input",
        provenance="NIST CWE-95 (Eval Injection); Juliet-style tainted-source-to-eval-sink.",
        files={"calc.py": '''\
import flask
app = flask.Flask(__name__)

@app.route("/calc")
def calc():
    expr = flask.request.args.get("expr")
    result = eval(expr)
    return str(result)
'''},
        expected=[ExpectedFinding("CWE-95", "code_injection", "calc.py")],
    ),
    Case(
        id="ACAD-09-yaml-load-python",
        family=Family.ACADEMIC,
        language="python",
        title="CWE-502: yaml.load without SafeLoader",
        provenance="NIST CWE-502; PyYAML full-loader deserialization (CVE-2017-18342 class).",
        files={"config_loader.py": '''\
import yaml, flask
app = flask.Flask(__name__)

@app.route("/load", methods=["POST"])
def load():
    body = flask.request.data
    cfg = yaml.load(body)
    return str(cfg)
'''},
        expected=[ExpectedFinding("CWE-502", "insecure_deserialization", "config_loader.py")],
    ),
    Case(
        id="ACAD-10-tls-disabled-python",
        family=Family.ACADEMIC,
        language="python",
        title="CWE-295: TLS certificate verification disabled",
        provenance="NIST CWE-295 (Improper Certificate Validation); requests verify=False.",
        files={"client.py": '''\
import requests

def fetch(url):
    return requests.get(url, verify=False).text
'''},
        expected=[ExpectedFinding("CWE-295", "tls_disabled", "client.py")],
    ),
    Case(
        id="ACAD-11-insecure-random-node",
        family=Family.ACADEMIC,
        language="javascript",
        title="CWE-330: predictable token from Math.random",
        provenance="NIST CWE-330 (Insufficiently Random Values); Math.random for security tokens.",
        files={"reset.js": '''\
function makeResetToken() {
  let t = "";
  for (let i = 0; i < 12; i++) t += Math.random().toString(36)[2];
  return t;
}
module.exports = { makeResetToken };
'''},
        expected=[ExpectedFinding("CWE-330", "insecure_randomness", "reset.js")],
    ),
    Case(
        id="ACAD-12-os-system-python",
        family=Family.ACADEMIC,
        language="python",
        title="CWE-78: os.system with concatenated input",
        provenance="NIST CWE-78 (OS Command Injection); os.system tainted concat sink.",
        files={"ops.py": '''\
import os, flask
app = flask.Flask(__name__)

@app.route("/backup")
def backup():
    target = flask.request.args.get("dir")
    os.system("tar czf backup.tgz " + target)
    return "ok"
'''},
        expected=[ExpectedFinding("CWE-78", "command_injection", "ops.py")],
    ),
    Case(
        id="ACAD-13-debug-python",
        family=Family.ACADEMIC,
        language="python",
        title="CWE-489: debug feature enabled in production",
        provenance="NIST CWE-489 (Active Debug Code); Flask debug=True on 0.0.0.0.",
        files={"wsgi.py": '''\
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "home"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
'''},
        expected=[ExpectedFinding("CWE-489", "debug_enabled", "wsgi.py")],
    ),
    Case(
        id="ACAD-14-sqli-via-format-python",
        family=Family.ACADEMIC,
        language="python",
        title="CWE-89: SQL built with .format() then executed",
        provenance="NIST CWE-89; str.format tainted-to-execute sink (Juliet-style).",
        files={"users.py": '''\
import sqlite3, flask
app = flask.Flask(__name__)

@app.route("/user")
def user():
    uid = flask.request.args.get("id")
    q = "SELECT * FROM users WHERE id = {}".format(uid)
    cur = sqlite3.connect("db").cursor()
    cur.execute(q)
    return str(cur.fetchall())
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "users.py")],
    ),
]
