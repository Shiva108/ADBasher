import os
import uuid
import yaml
import time
from datetime import datetime
from rich.console import Console
from rich.progress import Progress

from core.logger import setup_logger, get_logger
from core.database import DatabaseManager, Target

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
        # TODO: Implement Phase 2: Vuln scanning
        time.sleep(1)
        pass

    def run_cred_attacks(self):
        # TODO: Implement Phase 3: Credential modules
        time.sleep(1)
        pass

    def run_lateral_movement(self):
        # TODO: Implement Phase 5: Lateral movement
        time.sleep(1)
        pass

    def run_reporting(self):
        # TODO: Generate final report
        report_path = os.path.join(self.session_dir, "report.md")
        with open(report_path, "w") as f:
            f.write(f"# ADBasher Report - Session {self.session_id}\n")
            f.write("## Execution Log\n")
            f.write("Orchestration complete.\n")
        self.logger.info(f"Report generated at {report_path}")
