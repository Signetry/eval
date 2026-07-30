"""MULTILANG family: coverage across Go, Java, Ruby, PHP, C#.

Language breadth was the axis where LLM scanners (which read any language) had an
edge over an AST engine limited to Python/JS. These cases prove Umbra's native
regex tier now covers the common server languages for the top injection/crypto
classes. Each case cites the CWE; SAFE polyglot decoys are included to keep the
false-positive measurement honest across languages too.
"""
from __future__ import annotations

from .schema import Case, ExpectedFinding, Family

CASES: list[Case] = [
    Case(
        id="LANG-31-go-sqli",
        family=Family.MULTILANG,
        language="go",
        title="Go: SQL built with fmt.Sprintf",
        provenance="CWE-89; Go database/sql string-built query.",
        files={"main.go": '''\
package main

import ("database/sql"; "fmt"; "net/http")

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
    _ = rows
}
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "main.go")],
    ),
    Case(
        id="LANG-32-go-tls",
        family=Family.MULTILANG,
        language="go",
        title="Go: TLS verification disabled",
        provenance="CWE-295; InsecureSkipVerify: true.",
        files={"client.go": '''\
package main

import "crypto/tls"

func cfg() *tls.Config {
    return &tls.Config{InsecureSkipVerify: true}
}
'''},
        expected=[ExpectedFinding("CWE-295", "tls_disabled", "client.go")],
    ),
    Case(
        id="LANG-33-java-sqli",
        family=Family.MULTILANG,
        language="java",
        title="Java: JDBC query with string concatenation",
        provenance="CWE-89; Statement.executeQuery concatenation.",
        files={"Dao.java": '''\
public class Dao {
    public void find(java.sql.Statement stmt, String id) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }
}
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "Dao.java")],
    ),
    Case(
        id="LANG-34-java-deser",
        family=Family.MULTILANG,
        language="java",
        title="Java: native deserialization of untrusted input",
        provenance="CWE-502; ObjectInputStream.readObject.",
        files={"Loader.java": '''\
import java.io.*;
public class Loader {
    Object load(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }
}
'''},
        expected=[ExpectedFinding("CWE-502", "insecure_deserialization", "Loader.java")],
    ),
    Case(
        id="LANG-35-ruby-cmdi",
        family=Family.MULTILANG,
        language="ruby",
        title="Ruby: command injection via interpolation",
        provenance="CWE-78; system with #{...} interpolation.",
        files={"ops.rb": '''\
class Ops
  def backup(params)
    system("tar czf backup.tgz #{params[:dir]}")
  end
end
'''},
        expected=[ExpectedFinding("CWE-78", "command_injection", "ops.rb")],
    ),
    Case(
        id="LANG-36-php-sqli",
        family=Family.MULTILANG,
        language="php",
        title="PHP: SQL injection from a superglobal",
        provenance="CWE-89; mysqli_query with $_GET.",
        files={"user.php": '''\
<?php
$conn = mysqli_connect("localhost", "u", "p", "db");
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "user.php")],
    ),
    Case(
        id="LANG-37-php-object-injection",
        family=Family.MULTILANG,
        language="php",
        title="PHP: object injection via unserialize on a cookie",
        provenance="CWE-502; unserialize($_COOKIE).",
        files={"session.php": '''\
<?php
$state = unserialize($_COOKIE["session"]);
'''},
        expected=[ExpectedFinding("CWE-502", "insecure_deserialization", "session.php")],
    ),
    Case(
        id="LANG-38-csharp-sqli",
        family=Family.MULTILANG,
        language="csharp",
        title="C#: SqlCommand built with concatenation",
        provenance="CWE-89; SqlCommand string concatenation.",
        files={"Repo.cs": '''\
using System.Data.SqlClient;
public class Repo {
    public void Find(string id) {
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id);
    }
}
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "Repo.cs")],
    ),
    Case(
        id="LANG-39-SAFE-go-parameterized",
        family=Family.MULTILANG,
        language="go",
        title="SAFE: Go parameterised query",
        provenance="Crafted SAFE decoy: Go placeholder query (false-positive probe).",
        files={"safe.go": '''\
package main

import ("database/sql"; "net/http")

func handler(db *sql.DB, r *http.Request) {
    id := r.URL.Query().Get("id")
    rows, _ := db.Query("SELECT * FROM users WHERE id = $1", id)
    _ = rows
}
'''},
        expected=[],  # SAFE
    ),
    Case(
        id="LANG-40-SAFE-php-prepared",
        family=Family.MULTILANG,
        language="php",
        title="SAFE: PHP prepared statement",
        provenance="Crafted SAFE decoy: PDO prepared statement (false-positive probe).",
        files={"safe.php": '''\
<?php
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET["id"]]);
'''},
        expected=[],  # SAFE
    ),
    # --- multi-variable taint flow (source -> local -> sink), non-Python ------
    Case(
        id="LANG-41-go-multivar-sqli",
        family=Family.MULTILANG,
        language="go",
        title="Go: SQLi where taint flows through an intermediate variable",
        provenance="CWE-89; Go source->local->db.Query (probes cross-language taint tracking).",
        files={"store.go": '''\
package main

import ("database/sql"; "net/http")

func handler(db *sql.DB, r *http.Request) {
    id := r.URL.Query().Get("id")
    q := "SELECT * FROM users WHERE id = " + id
    rows, _ := db.Query(q)
    _ = rows
}
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "store.go")],
    ),
    Case(
        id="LANG-42-java-multivar-sqli",
        family=Family.MULTILANG,
        language="java",
        title="Java: SQLi where taint flows through a local String",
        provenance="CWE-89; Java getParameter->local->executeQuery.",
        files={"UserDao.java": '''\
public class UserDao {
    public void find(java.sql.Statement stmt, javax.servlet.http.HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        String q = "SELECT * FROM users WHERE id = " + id;
        stmt.executeQuery(q);
    }
}
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "UserDao.java")],
    ),
    Case(
        id="LANG-43-php-multivar-cmdi",
        family=Family.MULTILANG,
        language="php",
        title="PHP: command injection through an intermediate variable",
        provenance="CWE-78; PHP $_GET->local->system.",
        files={"run.php": '''\
<?php
$dir = $_GET["dir"];
$cmd = "ls -la " . $dir;
system($cmd);
'''},
        expected=[ExpectedFinding("CWE-78", "command_injection", "run.php")],
    ),
    Case(
        id="LANG-44-csharp-multivar-sqli",
        family=Family.MULTILANG,
        language="csharp",
        title="C#: SQLi where taint flows through a local var",
        provenance="CWE-89; C# Request.Query->local->SqlCommand.",
        files={"Repo2.cs": '''\
using System.Data.SqlClient;
public class Repo2 {
    public void Find(Microsoft.AspNetCore.Http.HttpRequest request) {
        var id = request.Query["id"];
        var q = "SELECT * FROM Users WHERE Id = " + id;
        var cmd = new SqlCommand(q);
    }
}
'''},
        expected=[ExpectedFinding("CWE-89", "sql_injection", "Repo2.cs")],
    ),
    Case(
        id="LANG-45-SAFE-java-parameterized",
        family=Family.MULTILANG,
        language="java",
        title="SAFE: Java PreparedStatement with bound parameter",
        provenance="Crafted SAFE decoy: JDBC prepared statement (false-positive probe).",
        files={"SafeDao.java": '''\
import java.sql.*;
public class SafeDao {
    public void find(Connection c, String id) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();
    }
}
'''},
        expected=[],  # SAFE
    ),
]
