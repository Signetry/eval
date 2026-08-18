"""MULTILANG family: coverage across Go, Java, Ruby, PHP, C#.

Language breadth was the axis where LLM scanners (which read any language) had an
edge over an AST engine limited to Python/JS. These cases prove Signetry's native
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

    # --- OWASP breadth: XXE, path traversal, SSRF (Signetry/eval#11, #12, #29) ---
    Case(
        id="LANG-53-java-xxe",
        family=Family.MULTILANG,
        language="java",
        title="Java: XML parsed with a default DocumentBuilderFactory (XXE)",
        provenance="OWASP A05:2021 Security Misconfiguration; CWE-611. Pattern per the "
                   "OWASP XXE Prevention cheat sheet: the JAXP default factory resolves "
                   "external entities unless DOCTYPE processing is explicitly disabled.",
        files={"XmlLoader.java": '''\
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class XmlLoader {
    public void load(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }
}
'''},
        expected=[ExpectedFinding("CWE-611", "xxe", "XmlLoader.java")],
    ),
    Case(
        id="LANG-54-php-xxe",
        family=Family.MULTILANG,
        language="php",
        title="PHP: loadXML with LIBXML_NOENT|LIBXML_DTDLOAD (XXE)",
        provenance="OWASP A05:2021; CWE-611. Since PHP 8 / libxml 2.9 external entities "
                   "are off by default, so the vulnerable pattern is code that explicitly "
                   "re-enables them via LIBXML_NOENT / LIBXML_DTDLOAD.",
        files={"import.php": '''\
<?php
$xml = $_POST["payload"];
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
echo $doc->saveXML();
'''},
        expected=[ExpectedFinding("CWE-611", "xxe", "import.php")],
    ),
    Case(
        id="LANG-55-SAFE-php-xml-default",
        family=Family.MULTILANG,
        language="php",
        title="SAFE: PHP loadXML without entity flags (default-safe on modern PHP)",
        provenance="Crafted SAFE decoy: parsing untrusted XML is not itself XXE on PHP 8+ "
                   "(entities off by default) — probes whether the rule keys on the flag "
                   "rather than on 'parses XML'.",
        files={"safe_import.php": '''\
<?php
$xml = $_POST["payload"];
$doc = new DOMDocument();
$doc->loadXML($xml);
echo $doc->saveXML();
'''},
        expected=[],  # SAFE
    ),
    Case(
        id="LANG-56-go-path-traversal",
        family=Family.MULTILANG,
        language="go",
        title="Go: file path built from a query parameter (traversal)",
        provenance="OWASP A01:2021 Broken Access Control; CWE-22. Unconfined path join "
                   "from a request parameter, per the OWASP Path Traversal description.",
        files={"files.go": '''\
package main

import (
    "net/http"
    "os"
)

func download(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("file")
    data, err := os.ReadFile("/var/data/" + name)
    if err != nil {
        http.Error(w, "not found", 404)
        return
    }
    w.Write(data)
}
'''},
        expected=[ExpectedFinding("CWE-22", "path_traversal", "files.go")],
    ),
    Case(
        id="LANG-57-java-path-traversal",
        family=Family.MULTILANG,
        language="java",
        title="Java: FileInputStream opened on a request parameter (traversal)",
        provenance="OWASP A01:2021; CWE-22. Servlet parameter concatenated into a "
                   "filesystem path with no canonicalisation or base-dir confinement.",
        files={"Download.java": '''\
import javax.servlet.http.HttpServletRequest;

public class Download {
    public void send(HttpServletRequest req) throws Exception {
        String name = req.getParameter("file");
        java.io.FileInputStream in = new java.io.FileInputStream("/var/data/" + name);
        in.close();
    }
}
'''},
        expected=[ExpectedFinding("CWE-22", "path_traversal", "Download.java")],
    ),
    Case(
        id="LANG-58-SAFE-go-constant-path",
        family=Family.MULTILANG,
        language="go",
        title="SAFE: Go reads a compiled-in constant path",
        provenance="Crafted SAFE decoy: a constant filesystem path is not traversal "
                   "(false-positive probe for the traversal sink).",
        files={"config.go": '''\
package main

import "os"

func loadConfig() ([]byte, error) {
    return os.ReadFile("/etc/app/config.yaml")
}
'''},
        expected=[],  # SAFE
    ),
    Case(
        id="LANG-59-go-ssrf",
        family=Family.MULTILANG,
        language="go",
        title="Go: outbound HTTP request to a user-controlled URL (SSRF)",
        provenance="OWASP A10:2021 Server-Side Request Forgery; CWE-918. A fetch-by-URL "
                   "handler forwards a request parameter straight to http.Get, reaching "
                   "internal services and cloud metadata endpoints.",
        files={"proxy.go": '''\
package main

import (
    "io"
    "net/http"
)

func fetch(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    resp, err := http.Get(target)
    if err != nil {
        http.Error(w, "fetch failed", 502)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
'''},
        expected=[ExpectedFinding("CWE-918", "ssrf", "proxy.go")],
    ),
    Case(
        id="LANG-60-SAFE-go-constant-url",
        family=Family.MULTILANG,
        language="go",
        title="SAFE: Go fetches a constant URL with a user-supplied query string",
        provenance="Crafted SAFE decoy: the destination host is compiled in and only the "
                   "query string is user-controlled — not SSRF. Probes the same "
                   "constant-URL-with-tainted-parameters distinction that the Python SSRF "
                   "rule is measured on.",
        files={"client.go": '''\
package main

import (
    "net/http"
    "net/url"
)

func search(r *http.Request) (*http.Response, error) {
    q := r.URL.Query().Get("q")
    return http.Get("https://api.example.com/search?q=" + url.QueryEscape(q))
}
'''},
        expected=[],  # SAFE
    ),
]
