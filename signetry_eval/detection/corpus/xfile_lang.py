"""XFILE_LANG family: cross-file taint in non-Python languages.

Proves Signetry's interprocedural analysis now spans files for Go, Java and PHP (not
just Python): a user source in one file flows through a function call into a sink in
another file. Includes a SAFE cross-file decoy (constant argument) so the
false-positive measurement covers the cross-file path too.
"""
from __future__ import annotations

from .schema import Case, ExpectedFinding, Family

CASES: list[Case] = [
    Case(
        id="XLANG-46-go-crossfile-sqli",
        family=Family.HARD,
        language="go",
        title="Go: cross-file SQLi (source in handler.go, sink in store.go)",
        provenance="CWE-89; interprocedural taint across Go files.",
        files={
            "handler.go": '''\
package main

import "net/http"

func handler(db *DB, r *http.Request) {
    id := r.URL.Query().Get("id")
    lookup(db, id)
}
''',
            "store.go": '''\
package main

func lookup(db *DB, name string) {
    q := "SELECT * FROM users WHERE name = " + name
    db.Query(q)
}
''',
        },
        expected=[ExpectedFinding("CWE-89", "sql_injection", "store.go")],
    ),
    Case(
        id="XLANG-47-java-crossfile-sqli",
        family=Family.HARD,
        language="java",
        title="Java: cross-file SQLi (source in Controller, sink in Dao)",
        provenance="CWE-89; interprocedural taint across Java files.",
        files={
            "Controller.java": '''\
public class Controller {
    void handle(Dao dao, javax.servlet.http.HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        dao.find(id);
    }
}
''',
            "Dao.java": '''\
public class Dao {
    public void find(String id) throws Exception {
        String q = "SELECT * FROM users WHERE id = " + id;
        stmt.executeQuery(q);
    }
}
''',
        },
        expected=[ExpectedFinding("CWE-89", "sql_injection", "Dao.java")],
    ),
    Case(
        id="XLANG-48-php-crossfile-sqli",
        family=Family.HARD,
        language="php",
        title="PHP: cross-file SQLi (source in index.php, sink in db.php)",
        provenance="CWE-89; interprocedural taint across PHP files.",
        files={
            "index.php": '''\
<?php
require "db.php";
$id = $_GET["id"];
run_query($id);
''',
            "db.php": '''\
<?php
function run_query($id) {
    $q = "SELECT * FROM users WHERE id = " . $id;
    mysqli_query($conn, $q);
}
''',
        },
        expected=[ExpectedFinding("CWE-89", "sql_injection", "db.php")],
    ),
    Case(
        id="XLANG-49-SAFE-go-crossfile-constant",
        family=Family.HARD,
        language="go",
        title="SAFE: cross-file call passes a constant (no user taint)",
        provenance="Crafted SAFE decoy: constant argument into a query helper.",
        files={
            "main.go": '''\
package main

func boot(db *DB) {
    lookup(db, "healthcheck")
}
''',
            "repo.go": '''\
package main

func lookup(db *DB, name string) {
    db.Query("SELECT * FROM services WHERE name = $1", name)
}
''',
        },
        expected=[],  # SAFE (constant arg + parameterised callee)
    ),
    Case(
        id="XLANG-50-ruby-crossfile-sqli",
        family=Family.HARD,
        language="ruby",
        title="Ruby: cross-file SQLi (source in controller, sink in dao)",
        provenance="CWE-89; interprocedural taint across Ruby files.",
        files={
            "controller.rb": '''\
class Controller
  def handle(dao, params)
    id = params[:id]
    dao.find(id)
  end
end
''',
            "dao.rb": '''\
class Dao
  def find(id)
    q = "SELECT * FROM users WHERE id = #{id}"
    ActiveRecord::Base.connection.execute(q)
  end
end
''',
        },
        expected=[ExpectedFinding("CWE-89", "sql_injection", "dao.rb")],
    ),
    Case(
        id="XLANG-51-csharp-crossfile-sqli",
        family=Family.HARD,
        language="csharp",
        title="C#: cross-file SQLi (source in Controller, sink in Dao)",
        provenance="CWE-89; interprocedural taint across C# files.",
        files={
            "Controller.cs": '''\
public class Controller {
    public void Handle(Dao dao, Microsoft.AspNetCore.Http.HttpRequest request) {
        var id = request.Query["id"];
        dao.Find(id);
    }
}
''',
            "Dao.cs": '''\
public class Dao {
    public void Find(string id) {
        var q = "SELECT * FROM Users WHERE Id = " + id;
        var cmd = new SqlCommand(q);
    }
}
''',
        },
        expected=[ExpectedFinding("CWE-89", "sql_injection", "Dao.cs")],
    ),
    Case(
        id="XLANG-52-SAFE-php-crossfile-prepared",
        family=Family.HARD,
        language="php",
        title="SAFE: cross-file call into a callee that uses a prepared statement",
        provenance="Crafted SAFE decoy: user input crosses files but the callee binds it.",
        files={
            "app.php": '''\
<?php
require "repo.php";
$id = $_GET["id"];
find_user($pdo, $id);
''',
            "repo.php": '''\
<?php
function find_user($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
}
''',
        },
        expected=[],  # SAFE (callee parameterises the crossed-in value)
    ),
]
