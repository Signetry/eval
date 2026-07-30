"""CRAFTED family (cases 15-20): edge cases that discriminate precision & robustness.

These are the cases that separate a precise detector from a trigger-happy one:
- Taint that flows through a helper/local (true positives a naive matcher misses).
- SAFE code that *looks* dangerous (parameterised query, arg-list subprocess,
  escaped output, secure randomness, placeholder secret) — any finding here is a
  FALSE POSITIVE. LLM scanners lower recall to keep these quiet; a deterministic
  taint engine should get them right structurally.

Cases marked SAFE have an empty ``expected`` list.
"""
from __future__ import annotations

from .schema import Case, ExpectedFinding, Family

CASES: list[Case] = [
    Case(
        id="CRAFT-15-taint-through-helper-python",
        family=Family.CRAFTED,
        language="python",
        title="SQLi where taint passes through a helper variable chain",
        provenance="Crafted: taint-through-intermediate-variable (probes flow tracking).",
        files={"repo.py": '''\
import sqlite3, flask
app = flask.Flask(__name__)

@app.route("/lookup")
def lookup():
    raw = flask.request.args.get("id")
    key = raw
    clause = "id = '" + key + "'"
    q = "SELECT * FROM t WHERE " + clause
    sqlite3.connect("d").cursor().execute(q)
    return "ok"
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "repo.py")],
    ),
    Case(
        id="CRAFT-16-SAFE-parameterized-python",
        family=Family.CRAFTED,
        language="python",
        title="SAFE: parameterised query (must NOT be flagged as SQLi)",
        provenance="Crafted SAFE decoy: correct parameterisation (false-positive probe).",
        files={"safe_repo.py": '''\
import sqlite3, flask
app = flask.Flask(__name__)

@app.route("/lookup")
def lookup():
    uid = flask.request.args.get("id")
    cur = sqlite3.connect("d").cursor()
    cur.execute("SELECT * FROM t WHERE id = ?", (uid,))
    return str(cur.fetchall())
'''},
        expected=[],  # SAFE
    ),
    Case(
        id="CRAFT-17-SAFE-arglist-subprocess-python",
        family=Family.CRAFTED,
        language="python",
        title="SAFE: subprocess with an argument list, no shell",
        provenance="Crafted SAFE decoy: arg-list subprocess (false-positive probe).",
        files={"safe_ops.py": '''\
import subprocess, flask
app = flask.Flask(__name__)

@app.route("/ping")
def ping():
    host = flask.request.args.get("host")
    return subprocess.check_output(["ping", "-c", "1", host])
'''},
        expected=[],  # SAFE
    ),
    Case(
        id="CRAFT-18-SAFE-escaped-xss-node",
        family=Family.CRAFTED,
        language="javascript",
        title="SAFE: user input HTML-escaped before render",
        provenance="Crafted SAFE decoy: escaped output (false-positive probe).",
        files={"safe_view.js": '''\
const express = require("express");
const escapeHtml = require("escape-html");
const app = express();

app.get("/hello", (req, res) => {
  res.send("<p>Hi " + escapeHtml(req.query.name) + "</p>");
});
module.exports = app;
'''},
        expected=[],  # SAFE
    ),
    Case(
        id="CRAFT-19-SAFE-secure-random-node",
        family=Family.CRAFTED,
        language="javascript",
        title="SAFE: crypto.randomBytes for token (not Math.random)",
        provenance="Crafted SAFE decoy: secure randomness (false-positive probe).",
        files={"safe_token.js": '''\
const crypto = require("crypto");
function makeToken() {
  return crypto.randomBytes(24).toString("hex");
}
module.exports = { makeToken };
'''},
        expected=[],  # SAFE
    ),
    Case(
        id="CRAFT-20-multi-vuln-python",
        family=Family.CRAFTED,
        language="python",
        title="Two distinct vulns in one file (command injection + hardcoded secret)",
        provenance="Crafted: multiple independent findings in one file (co-detection probe).",
        files={"admin.py": '''\
import os, flask
app = flask.Flask(__name__)

API_TOKEN = "sk-live-9f8e7d6c5b4a39281706abcdef012345"

@app.route("/run")
def run():
    cmd = flask.request.args.get("cmd")
    os.system("/usr/local/bin/tool " + cmd)
    return "done"
'''},
        expected=[
            ExpectedFinding("CWE-78", "command_injection", "admin.py"),
            ExpectedFinding("CWE-798", "hardcoded_secret", "admin.py"),
        ],
    ),
]
