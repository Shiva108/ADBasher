#!/usr/bin/env python3
"""
HTML Report Generator for ADBasher
Generates a professional HTML report from session database
"""
import sys
import os
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager, Target, Credential, Vulnerability

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADBasher Penetration Test Report - {session_id}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f4f4f4;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #667eea;
            color: white;
            font-weight: bold;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity-critical {{ color: #d32f2f; font-weight: bold; }}
        .severity-high {{ color: #f57c00; font-weight: bold; }}
        .severity-medium {{ color: #fbc02d; font-weight: bold; }}
        .severity-low {{ color: #388e3c; font-weight: bold; }}
        .admin-badge {{
            background: #4caf50;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .metric {{
            display: inline-block;
            background: #f0f0f0;
            padding: 15px 25px;
            margin: 10px 10px 10px 0;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        .metric .number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .metric .label {{
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 ADBasher Penetration Test Report</h1>
        <p><strong>Session ID:</strong> {session_id}</p>
        <p><strong>Date:</strong> {date}</p>
    </div>

    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="metric">
            <div class="number">{target_count}</div>
            <div class="label">Targets Discovered</div>
        </div>
        <div class="metric">
            <div class="number">{cred_count}</div>
            <div class="label">Credentials Compromised</div>
        </div>
        <div class="metric">
            <div class="number">{admin_count}</div>
            <div class="label">Admin Accounts</div>
        </div>
        <div class="metric">
            <div class="number">{vuln_count}</div>
            <div class="label">Vulnerabilities</div>
        </div>
    </div>

    <div class="section">
        <h2>🎯 Discovered Targets</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Domain</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
                {targets_table}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>🔑 Compromised Credentials</h2>
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Domain</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Privilege</th>
                </tr>
            </thead>
            <tbody>
                {creds_table}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>⚠️ Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {vulns_table}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>💡 Recommendations</h2>
        <ol>
            <li><strong>Password Policy:</strong> Enforce complex passwords (min 14 chars) and implement MFA</li>
            <li><strong>Kerberoasting:</strong> Disable or rotate service account passwords regularly</li>
            <li><strong>SMB Signing:</strong> Enable SMB signing on all hosts and DCs</li>
            <li><strong>LDAP Anonymous:</strong> Disable anonymous LDAP binds</li>
            <li><strong>Privileged Access:</strong> Implement least privilege and tiered admin model</li>
            <li><strong>Monitoring:</strong> Enable advanced threat protection and SIEM alerts</li>
        </ol>
    </div>

    <div class="section">
        <h2>📁 Artifacts</h2>
        <ul>
            <li>Session logs: <code>{session_dir}/session_*.log</code></li>
            <li>BloodHound data: <code>{session_dir}/bloodhound_data/</code></li>
            <li>Database: <code>{session_dir}/session.db</code></li>
        </ul>
    </div>
</body>
</html>
"""

def generate_html_report(session_dir, session_id):
    """Generate HTML report from session database."""
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    session = db.get_session()
    targets = session.query(Target).all()
    credentials = session.query(Credential).all()
    vulnerabilities = session.query(Vulnerability).all()
    session.close()
    
    # Build tables
    targets_table = ""
    for t in targets:
        dc_flag = "🖥️ Domain Controller" if t.is_dc else "💻 Workstation"
        targets_table += f"<tr><td>{t.ip_address}</td><td>{t.hostname or 'N/A'}</td><td>{t.domain or 'N/A'}</td><td>{dc_flag}</td></tr>\n"
    
    creds_table = ""
    for c in credentials:
        cred_type = "🔑 Password" if c.password else "🔒 NTLM Hash"
        priv = '<span class="admin-badge">ADMIN</span>' if c.is_admin else "User"
        creds_table += f"<tr><td>{c.username}</td><td>{c.domain or 'N/A'}</td><td>{cred_type}</td><td>{c.source}</td><td>{priv}</td></tr>\n"
    
    vulns_table = ""
    for v in vulnerabilities:
        severity_class = f"severity-{v.severity.lower()}"
        session = db.get_session()
        target = session.query(Target).filter_by(id=v.target_id).first()
        target_display = target.ip_address if target else "Unknown"
        session.close()
        vulns_table += f"<tr><td>{target_display}</td><td>{v.name}</td><td class='{severity_class}'>{v.severity}</td><td>{v.description or 'N/A'}</td></tr>\n"
    
    admin_count = sum(1 for c in credentials if c.is_admin)
    
    # Generate HTML
    html = HTML_TEMPLATE.format(
        session_id=session_id,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        target_count=len(targets),
        cred_count=len(credentials),
        admin_count=admin_count,
        vuln_count=len(vulnerabilities),
        targets_table=targets_table,
        creds_table=creds_table,
        vulns_table=vulns_table,
        session_dir=session_dir
    )
    
    output_path = os.path.join(session_dir, "report.html")
    with open(output_path, 'w') as f:
        f.write(html)
    
    return output_path

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--session-id", required=True)
    args = parser.parse_args()
    
    output = generate_html_report(args.session_dir, args.session_id)
    print(f"HTML report generated: {output}")
