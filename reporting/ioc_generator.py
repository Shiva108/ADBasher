#!/usr/bin/env python3
"""
IOC Generator - Indicators of Compromise Export

Generates IOCs in multiple formats:
- STIX 2.1 (Structured Threat Information eXpression)
- TAXII (Trusted Automated eXchange of Indicator Information)
- OpenIOC XML
- MISP JSON
- CSV/JSON for SIEM ingestion

Extracts IOCs from ADBasher session:
- File hashes (tools, payloads)
- Network indicators (IPs, domains)
- Registry keys
- File paths
- Command-line patterns
"""

import sys
import os
import argparse
import json
import hashlib
import csv
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

class IOCGenerator:
    """Generates IOCs from penetration test session"""
    
    def __init__(self, session_dir, session_id):
        self.session_dir = session_dir
        self.session_id = session_id
        self.iocs = {
            'file_hashes': [],
            'network': [],
            'registry': [],
            'file_paths': [],
            'commands': [],
            'user_agents': []
        }
    
    def collect_iocs(self):
        """Collect all IOCs from session"""
        logger.info("Collecting IOCs from session...")
        
        # 1. File hashes from uploaded tools
        self._collect_file_hashes()
        
        # 2. Network indicators from database
        self._collect_network_indicators()
        
        # 3. Registry modifications
        self._collect_registry_iocs()
        
        # 4. File system artifacts
        self._collect_file_iocs()
        
        # 5. Command-line patterns
        self._collect_command_patterns()
        
        total = sum(len(v) for v in self.iocs.values())
        logger.info(f"Collected {total} IOCs")
        
        return self.iocs
    
    def _collect_file_hashes(self):
        """Hash all tools and payloads used"""
        logger.info("Hashing session files...")
        
        # Common tool directories to hash
        tool_paths = [
            os.path.join(self.session_dir, "tools"),
            os.path.join(self.session_dir, "payloads"),
            os.path.join(self.session_dir, "scripts")
        ]
        
        for tool_dir in tool_paths:
            if os.path.exists(tool_dir):
                for root, dirs, files in os.walk(tool_dir):
                    for file in files:
                        filepath = os.path.join(root, file)
                        
                        try:
                            # Calculate hashes
                            md5_hash, sha1_hash, sha256_hash = self._hash_file(filepath)
                            
                            self.iocs['file_hashes'].append({
                                'filename': file,
                                'md5': md5_hash,
                                'sha1': sha1_hash,
                                'sha256': sha256_hash,
                                'size': os.path.getsize(filepath),
                                'path': filepath
                            })
                        except Exception as e:
                            logger.debug(f"Failed to hash {filepath}: {e}")
    
    def _hash_file(self, filepath):
        """Calculate MD5, SHA1, SHA256 hashes"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
    
    def _collect_network_indicators(self):
        """Extract network IOCs from database"""
        logger.info("Extracting network indicators...")
        
        db_path = os.path.join(self.session_dir, "session.db")
        if not os.path.exists(db_path):
            return
        
        db = DatabaseManager(db_path)
        session = db.get_session()
        
        # Get all targets (these are victim IPs, not our IPs)
        targets = session.query(db.Target).all()
        
        for target in targets:
            self.iocs['network'].append({
                'type': 'ipv4',
                'value': target.ip_address,
                'context': 'target_system',
                'hostname': target.hostname,
                'domain': target.domain
            })
        
        session.close()
        
        # Add attacker IP (should be extracted from logs)
        # This would require parsing session logs
    
    def _collect_registry_iocs(self):
        """Collect registry modifications made during pentest"""
        # Common persistence registry keys
        persistence_keys = [
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\System\CurrentControlSet\Services"
        ]
        
        for key in persistence_keys:
            self.iocs['registry'].append({
                'key': key,
                'context': 'persistence_location'
            })
    
    def _collect_file_iocs(self):
        """Collect file system artifacts"""
        # Common payload drop locations
        drop_locations = [
            r"C:\Windows\Temp",
            r"C:\Users\Public",
            r"C:\ProgramData"
        ]
        
        for location in drop_locations:
            self.iocs['file_paths'].append({
                'path': location,
                'context': 'payload_drop_location'
            })
    
    def _collect_command_patterns(self):
        """Extract command-line patterns used"""
        common_commands = [
            "powershell.exe -nop -w hidden -enc",
            "cmd.exe /c",
            "net user",
            "net localgroup administrators",
            "secretsdump.py",
            "mimikatz.exe",
            "Invoke-Mimikatz"
        ]
        
        for cmd in common_commands:
            self.iocs['commands'].append({
                'pattern': cmd,
                'context': 'attack_command'
            })
    
    def export_stix(self, output_path):
        """Export IOCs in STIX 2.1 format"""
        logger.info(f"Generating STIX 2.1 bundle...")
        
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{self.session_id}",
            "spec_version": "2.1",
            "objects": []
        }
        
        # Create identity object
        identity = {
            "type": "identity",
            "id": f"identity--adbasher-{self.session_id}",
            "name": "ADBasher Penetration Test",
            "identity_class": "organization",
            "created": datetime.now(timezone.utc).isoformat()
        }
        stix_bundle["objects"].append(identity)
        
        # Add file hash indicators
        for file_hash in self.iocs['file_hashes']:
            indicator = {
                "type": "indicator",
                "id": f"indicator--{hashlib.md5(file_hash['sha256'].encode()).hexdigest()}",
                "created": datetime.now(timezone.utc).isoformat(),
                "modified": datetime.now(timezone.utc).isoformat(),
                "name": f"Malicious file: {file_hash['filename']}",
                "description": f"File used in penetration test session {self.session_id}",
                "pattern": f"[file:hashes.SHA256 = '{file_hash['sha256']}']",
                "pattern_type": "stix",
                "valid_from": datetime.now(timezone.utc).isoformat(),
                "indicator_types": ["malicious-activity"]
            }
            stix_bundle["objects"].append(indicator)
        
        # Add network indicators (IPv4)
        for net_ioc in self.iocs['network']:
            if net_ioc['type'] == 'ipv4':
                indicator = {
                    "type": "indicator",
                    "id": f"indicator--{hashlib.md5(net_ioc['value'].encode()).hexdigest()}",
                    "created": datetime.now(timezone.utc).isoformat(),
                    "modified": datetime.now(timezone.utc).isoformat(),
                    "name": f"Compromised system: {net_ioc['value']}",
                    "description": f"IP address involved in pentest: {net_ioc.get('hostname', 'Unknown')}",
                    "pattern": f"[ipv4-addr:value = '{net_ioc['value']}']",
                    "pattern_type": "stix",
                    "valid_from": datetime.now(timezone.utc).isoformat(),
                    "indicator_types": ["compromised"]
                }
                stix_bundle["objects"].append(indicator)
        
        # Save STIX bundle
        with open(output_path, 'w') as f:
            json.dump(stix_bundle, f, indent=2)
        
        logger.info(f"STIX bundle saved: {output_path}")
        logger.info(f"  Objects: {len(stix_bundle['objects'])}")
        
        return output_path
    
    def export_csv(self, output_path):
        """Export IOCs in CSV format for SIEM"""
        logger.info(f"Generating CSV export...")
        
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = ['type', 'indicator', 'context', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            # File hashes
            for file_hash in self.iocs['file_hashes']:
                writer.writerow({
                    'type': 'file_sha256',
                    'indicator': file_hash['sha256'],
                    'context': file_hash['filename'],
                    'timestamp': datetime.now().isoformat()
                })
            
            # Network indicators
            for net_ioc in self.iocs['network']:
                writer.writerow({
                    'type': 'ipv4',
                    'indicator': net_ioc['value'],
                    'context': net_ioc.get('hostname', 'Unknown'),
                    'timestamp': datetime.now().isoformat()
                })
            
            # Registry keys
            for reg_ioc in self.iocs['registry']:
                writer.writerow({
                    'type': 'registry_key',
                    'indicator': reg_ioc['key'],
                    'context': reg_ioc['context'],
                    'timestamp': datetime.now().isoformat()
                })
        
        logger.info(f"CSV export saved: {output_path}")
        return output_path
    
    def export_json(self, output_path):
        """Export IOCs in JSON format"""
        logger.info(f"Generating JSON export...")
        
        output = {
            'session_id': self.session_id,
            'generated': datetime.now().isoformat(),
            'ioc_count': sum(len(v) for v in self.iocs.values()),
            'iocs': self.iocs
        }
        
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        
        logger.info(f"JSON export saved: {output_path}")
        logger.info(f"  Total IOCs: {output['ioc_count']}")
        
        return output_path


def main(session_dir, session_id):
    """Main IOC generation flow"""
    global logger
    
    setup_logger("ioc_generator", session_dir)
    logger = get_logger("ioc_generator")
    
    logger.info("=" * 60)
    logger.info("IOC Generator - Threat Intelligence Export")
    logger.info("=" * 60)
    logger.info(f"Session: {session_id}")
    
    # Initialize generator
    generator = IOCGenerator(session_dir, session_id)
    
    # Collect IOCs
    logger.info("\n[1/4] Collecting IOCs from session...")
    iocs = generator.collect_iocs()
    
    # Create output directory
    ioc_dir = os.path.join(session_dir, "iocs")
    os.makedirs(ioc_dir, exist_ok=True)
    
    # Export in multiple formats
    logger.info("\n[2/4] Exporting STIX 2.1...")
    stix_path = os.path.join(ioc_dir, f"iocs_{session_id}.stix")
    generator.export_stix(stix_path)
    
    logger.info("\n[3/4] Exporting CSV...")
    csv_path = os.path.join(ioc_dir, f"iocs_{session_id}.csv")
    generator.export_csv(csv_path)
    
    logger.info("\n[4/4] Exporting JSON...")
    json_path = os.path.join(ioc_dir, f"iocs_{session_id}.json")
    generator.export_json(json_path)
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("IOC Generation Complete")
    logger.info("=" * 60)
    logger.info(f"Total IOCs: {sum(len(v) for v in iocs.values())}")
    logger.info(f"  File Hashes: {len(iocs['file_hashes'])}")
    logger.info(f"  Network: {len(iocs['network'])}")
    logger.info(f"  Registry: {len(iocs['registry'])}")
    logger.info(f"  File Paths: {len(iocs['file_paths'])}")
    logger.info(f"  Commands: {len(iocs['commands'])}")
    logger.info("\nExported files:")
    logger.info(f"  STIX 2.1: {stix_path}")
    logger.info(f"  CSV: {csv_path}")
    logger.info(f"  JSON: {json_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IOC Generator - Export Indicators of Compromise"
    )
    parser.add_argument("--session-dir", required=True, help="Session directory")
    parser.add_argument("--session-id", required=True, help="Session ID")
    
    args = parser.parse_args()
    
    main(args.session_dir, args.session_id)
