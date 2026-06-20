{ config, pkgs, ... }:

let
  hrApp = pkgs.writeText "hr_app.py" ''
    import csv, os
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from urllib.parse import parse_qs, urlparse

    CSV_PATH = "/var/lib/hr/employees.csv"
    FIELDS   = ["employeeNumber", "firstName", "lastName",
                 "email", "department", "title", "active"]

    def read_employees():
        if not os.path.exists(CSV_PATH):
            return []
        with open(CSV_PATH, newline="") as f:
            return list(csv.DictReader(f))

    def write_employees(employees):
        with open(CSV_PATH, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=FIELDS)
            w.writeheader()
            w.writerows(employees)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/employees.csv":
                self._serve_csv()
            elif parsed.path == "/healthz":
                self._ok("ok")
            else:
                self._serve_ui()

        def _serve_csv(self):
            with open(CSV_PATH, "rb") as f:
                data = f.read()
            self._respond(200, "text/csv", data)

        def _serve_ui(self):
            employees = read_employees()
            rows = ""
            for e in employees:
                status_color = "#2d8a2d" if e.get("active","true").lower() == "true" else "#a00"
                status_label = "Active"  if e.get("active","true").lower() == "true" else "Inactive"
                deactivate_btn = ""
                if e.get("active","true").lower() == "true":
                    deactivate_btn = (
                        f'<form method="POST" action="/deactivate" style="display:inline">'
                        f'<input type="hidden" name="employeeNumber" value="{e["employeeNumber"]}">'
                        f'<button type="submit">Deactivate</button></form>'
                    )
                rows += (
                    f"<tr><td>{e['employeeNumber']}</td><td>{e['firstName']}</td>"
                    f"<td>{e['lastName']}</td><td>{e['email']}</td>"
                    f"<td>{e['department']}</td><td>{e['title']}</td>"
                    f"<td style='color:{status_color}'>{status_label}</td>"
                    f"<td>{deactivate_btn}</td></tr>\n"
                )
            html = (
                "<!DOCTYPE html>\n"
                "<html lang='en'>\n"
                "<head>\n"
                "  <meta charset='UTF-8'>\n"
                "  <title>HR Simulator</title>\n"
                "  <style>\n"
                "    body { font-family: sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; }\n"
                "    h1   { color: #333; }\n"
                "    table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }\n"
                "    th, td { border: 1px solid #ccc; padding: .5rem .75rem; text-align: left; }\n"
                "    th { background: #f0f0f0; }\n"
                "    tr:nth-child(even) { background: #fafafa; }\n"
                "    fieldset { max-width: 480px; padding: 1rem; border-radius: 4px; }\n"
                "    label { display: block; margin: .5rem 0; }\n"
                "    input, select { width: 100%; padding: .3rem; box-sizing: border-box; }\n"
                "    button { margin-top: .75rem; padding: .4rem 1rem; cursor: pointer; }\n"
                "    .note { color: #666; font-size: .85rem; }\n"
                "  </style>\n"
                "</head>\n"
                "<body>\n"
                "<h1>HR Simulator</h1>\n"
                "<p class='note'>MidPoint reads <code>GET /employees.csv</code> &mdash; "
                "every save here is picked up on the next MidPoint reconciliation run.</p>\n"
                "<h2>Current Employees</h2>\n"
                "<table>\n"
                "  <tr><th>ID</th><th>First</th><th>Last</th><th>Email</th>"
                "<th>Department</th><th>Title</th><th>Status</th><th></th></tr>\n"
                f"  {rows if rows else '<tr><td colspan=8>No employees yet.</td></tr>'}\n"
                "</table>\n"
                "<h2>Add Employee</h2>\n"
                "<form method='POST' action='/add'>\n"
                "<fieldset>\n"
                "  <legend>New hire</legend>\n"
                "  <label>First Name <input name='firstName' required></label>\n"
                "  <label>Last Name  <input name='lastName'  required></label>\n"
                "  <label>Department\n"
                "    <select name='department'>\n"
                "      <option>Engineering</option>\n"
                "      <option>IT</option>\n"
                "      <option>HR</option>\n"
                "      <option>Finance</option>\n"
                "      <option>Operations</option>\n"
                "    </select>\n"
                "  </label>\n"
                "  <label>Title <input name='title' value='Employee'></label>\n"
                "  <button type='submit'>Hire &amp; Add to CSV</button>\n"
                "</fieldset>\n"
                "</form>\n"
                "</body>\n"
                "</html>\n"
            )
            self._respond(200, "text/html; charset=utf-8", html.encode())

        def do_POST(self):
            length  = int(self.headers.get("Content-Length", 0))
            body    = self.rfile.read(length).decode()
            params  = parse_qs(body)
            path    = urlparse(self.path).path

            employees = read_employees()

            if path == "/add":
                first = params.get("firstName", [""])[0].strip()
                last  = params.get("lastName",  [""])[0].strip()
                dept  = params.get("department", ["IT"])[0].strip()
                title = params.get("title",      ["Employee"])[0].strip()

                nums     = [int(e["employeeNumber"].replace("EMP",""))
                             for e in employees if e["employeeNumber"].startswith("EMP")]
                next_num = max(nums, default=0) + 1
                emp_num  = f"EMP{next_num:04d}"
                username = (first[0] + last).lower().replace(" ", "")

                employees.append({
                    "employeeNumber": emp_num,
                    "firstName":  first,
                    "lastName":   last,
                    "email":      f"{username}@lab.internal",
                    "department": dept,
                    "title":      title,
                    "active":     "true",
                })

            elif path == "/deactivate":
                emp_num = params.get("employeeNumber", [""])[0]
                for e in employees:
                    if e["employeeNumber"] == emp_num:
                        e["active"] = "false"

            write_employees(employees)
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()

        def _ok(self, text):
            self._respond(200, "text/plain", text.encode())

        def _respond(self, code, ctype, data):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            pass  # suppress access log noise

    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    if not os.path.exists(CSV_PATH):
        write_employees([])

    print("HR Simulator listening on :8888", flush=True)
    HTTPServer(("0.0.0.0", 8888), Handler).serve_forever()
    '';
in

{
  networking.hostName      = "hr01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers   = [ "192.168.100.10" ];

  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.10
    search lab.internal
  '';
  networking.firewall.allowedTCPPorts = [ 8888 ];
  system.stateVersion = "25.11";

  services.chrony.servers = [ "192.168.100.1" ];

  users.users.hr = { isSystemUser = true; group = "hr"; };
  users.groups.hr = {};

  systemd.services.hr-simulator = {
    description = "HR Simulator — CSV source of truth for MidPoint";
    wantedBy    = [ "multi-user.target" ];
    after       = [ "network.target" ];
    serviceConfig = {
      ExecStart  = "${pkgs.python3}/bin/python3 ${hrApp}";
      Restart    = "on-failure";
      RestartSec = "5s";
      User       = "hr";
      Group      = "hr";
      UMask      = "0022"; # ensure employees.csv is world-readable (0644) for MidPoint
    };
  };
}
