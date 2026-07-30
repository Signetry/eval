"""HARD family: discriminating cases that separate pattern-matching from semantics.

Unlike the base corpus (canonical patterns both a deterministic engine and an LLM
catch), these probe the boundary:

- **Cross-file taint** — source in one file, sink in another (needs whole-repo flow).
- **String indirection / obfuscation** — the dangerous call assembled from pieces.
- **Framework-specific sinks** — Django ``.extra()``, template ``| safe``, etc.
- **Sanitizer-that-does-not-sanitize** — looks safe, is not (semantic trap).
- **True-negative traps** — dangerous-looking but provably safe (constant input).

We label each with its ground truth AND a ``discriminating`` note describing *why*
it is hard, so the head-to-head report can explain wins/losses honestly rather than
just showing a number. A deterministic engine is expected to MISS some of these —
that is the point: the report tells the truth about where each approach wins.
"""
from __future__ import annotations

from .schema import Case, ExpectedFinding, Family

CASES: list[Case] = [
    Case(
        id="HARD-21-crossfile-taint-python",
        family=Family.HARD,
        language="python",
        title="Cross-file taint: request source in views.py, SQL sink in db.py",
        provenance="Crafted HARD: interprocedural/cross-file taint (CWE-89). Probes whole-repo flow.",
        files={
            "views.py": '''\
import flask
from db import run_query
app = flask.Flask(__name__)

@app.route("/find")
def find():
    term = flask.request.args.get("q")
    return str(run_query(term))
''',
            "db.py": '''\
import sqlite3

def run_query(term):
    con = sqlite3.connect("app.db")
    return con.cursor().execute("SELECT * FROM t WHERE name = '" + term + "'").fetchall()
''',
        },
        expected=[ExpectedFinding("CWE-89", "sql_injection", "db.py")],
    ),
    Case(
        id="HARD-22-string-indirection-python",
        family=Family.HARD,
        language="python",
        title="Command built via getattr/format indirection",
        provenance="Crafted HARD: obfuscated command injection (CWE-78). Sink assembled dynamically.",
        files={"runner.py": '''\
import os, flask
app = flask.Flask(__name__)

TEMPLATE = "{bin} {arg}"

@app.route("/run")
def run():
    arg = flask.request.args.get("x")
    cmd = TEMPLATE.format(bin="/usr/bin/convert", arg=arg)
    os.system(cmd)
    return "ok"
'''},
        expected=[ExpectedFinding("CWE-78", "command_injection", "runner.py")],
    ),
    Case(
        id="HARD-23-django-extra-sqli",
        family=Family.HARD,
        language="python",
        title="Django ORM .extra() SQL injection",
        provenance="CWE-89; Django .extra()/RawSQL injection pattern (framework-specific sink).",
        files={"views.py": '''\
from django.http import JsonResponse
from myapp.models import Product

def search(request):
    q = request.GET.get("q")
    rows = Product.objects.extra(where=["name = '%s'" % q])
    return JsonResponse(list(rows.values()), safe=False)
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "views.py")],
    ),
    Case(
        id="HARD-24-ssrf-python",
        family=Family.HARD,
        language="python",
        title="SSRF: user-controlled URL fetched server-side",
        provenance="OWASP A10:2021 SSRF; CWE-918. User input drives an outbound request.",
        files={"proxy.py": '''\
import requests, flask
app = flask.Flask(__name__)

@app.route("/fetch")
def fetch():
    url = flask.request.args.get("url")
    return requests.get(url).text
'''},
        expected=[ExpectedFinding("CWE-918", "ssrf", "proxy.py")],
    ),
    Case(
        id="HARD-25-jwt-none-python",
        family=Family.HARD,
        language="python",
        title="JWT verified with algorithm 'none' / verification disabled",
        provenance="CWE-347 Improper Verification of Cryptographic Signature; JWT alg=none.",
        files={"token.py": '''\
import jwt

def decode(token):
    return jwt.decode(token, options={"verify_signature": False})
'''},
        expected=[ExpectedFinding("CWE-347", "auth_bypass", "token.py")],
    ),
    Case(
        id="HARD-26-ssti-python",
        family=Family.HARD,
        language="python",
        title="Server-side template injection via render_template_string",
        provenance="CWE-1336 SSTI; Jinja2 render_template_string on user input.",
        files={"page.py": '''\
import flask
from flask import render_template_string
app = flask.Flask(__name__)

@app.route("/greet")
def greet():
    name = flask.request.args.get("name")
    return render_template_string("<h1>Hi " + name + "</h1>")
'''},
        expected=[ExpectedFinding("CWE-1336", "template_injection", "page.py")],
    ),
    Case(
        id="HARD-27-nosql-injection-node",
        family=Family.HARD,
        language="javascript",
        title="NoSQL injection: unsanitized query object into Mongo",
        provenance="CWE-943 NoSQL injection; user object spread into a Mongo query.",
        files={"login.js": '''\
const express = require("express");
const app = express();

app.post("/login", async (req, res) => {
  const user = await db.collection("users").findOne({
    username: req.body.username,
    password: req.body.password,
  });
  res.send(user ? "ok" : "no");
});
module.exports = app;
'''},
        expected=[ExpectedFinding("CWE-943", "nosql_injection", "login.js")],
    ),
    Case(
        id="HARD-28-SAFE-fake-sanitizer-python",
        family=Family.HARD,
        language="python",
        title="SAFE: input validated by an allowlist before the sink",
        provenance="Crafted HARD true-negative: allowlist-validated input (must NOT be flagged).",
        files={"safe_run.py": '''\
import subprocess, flask
app = flask.Flask(__name__)
ALLOWED = {"status", "uptime", "version"}

@app.route("/cmd")
def cmd():
    name = flask.request.args.get("name")
    if name not in ALLOWED:
        flask.abort(400)
    return subprocess.check_output(["/usr/local/bin/tool", name])
'''},
        expected=[],  # SAFE
    ),
    Case(
        id="HARD-29-SAFE-constant-not-secret-python",
        family=Family.HARD,
        language="python",
        title="SAFE: config value that looks secret-ish but is a public constant",
        provenance="Crafted HARD true-negative: public constant, not a credential.",
        files={"config.py": '''\
# The public key ID is not a secret; it is published in our API docs.
PUBLIC_KEY_ID = "pk_publishable_example_00000000"
TOKEN_ENDPOINT = "https://auth.example.com/oauth/token"
'''},
        expected=[],  # SAFE (placeholder/public — should not flag)
    ),
    Case(
        id="HARD-30-multi-file-mixed",
        family=Family.HARD,
        language="python",
        title="Mixed: real command injection + a SAFE parameterized query in same repo",
        provenance="Crafted HARD: co-located true positive + true negative (discrimination).",
        files={
            "handlers.py": '''\
import os, sqlite3, flask
app = flask.Flask(__name__)

@app.route("/safe")
def safe():
    uid = flask.request.args.get("id")
    cur = sqlite3.connect("d").cursor()
    cur.execute("SELECT * FROM u WHERE id = ?", (uid,))
    return str(cur.fetchall())

@app.route("/danger")
def danger():
    path = flask.request.args.get("path")
    os.system("cat " + path)
    return "ok"
''',
        },
        expected=[ExpectedFinding("CWE-78", "command_injection", "handlers.py")],
    ),
]
