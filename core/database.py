from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

Base = declarative_base()

class Target(Base):
    __tablename__ = 'targets'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, unique=True, nullable=False)
    hostname = Column(String)
    domain = Column(String)
    os_version = Column(String)
    is_dc = Column(Boolean, default=False)
    is_alive = Column(Boolean, default=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="target")

    def __repr__(self):
        return f"<Target(ip='{self.ip_address}', hostname='{self.hostname}')>"

class Credential(Base):
    __tablename__ = 'credentials'

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    password = Column(String) # Plaintext if found
    ntlm_hash = Column(String)
    domain = Column(String)
    source = Column(String) # e.g., "responder", "memory", "spray"
    type = Column(String) # e.g., "plaintext", "hash", "ticket"
    is_valid = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    captured_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Credential(user='{self.username}', domain='{self.domain}')>"

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'))
    name = Column(String, nullable=False) # e.g., "Zerologon", "SMB Signing Disabled"
    cve_id = Column(String)
    severity = Column(String) # Critical, High, Medium, Low
    description = Column(Text)
    is_exploited = Column(Boolean, default=False)
    found_at = Column(DateTime, default=datetime.utcnow)

    target = relationship("Target", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerability(name='{self.name}', target_id='{self.target_id}')>"

class LateralMovement(Base):
    __tablename__ = 'lateral_movement_paths'

    id = Column(Integer, primary_key=True)
    source_ip = Column(String)
    target_ip = Column(String)
    method = Column(String) # e.g., "PsExec", "WMI", "WinRM"
    credential_used_id = Column(Integer, ForeignKey('credentials.id'))
    success = Column(Boolean)
    timestamp = Column(DateTime, default=datetime.utcnow)

class DatabaseManager:
    def __init__(self, db_path: str):
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def get_session(self):
        return self.Session()

    def add_target(self, ip, hostname=None, domain=None, os_version=None, is_dc=False):
        session = self.get_session()
        try:
            target = session.query(Target).filter_by(ip_address=ip).first()
            if not target:
                target = Target(
                    ip_address=ip, 
                    hostname=hostname, 
                    domain=domain, 
                    os_version=os_version, 
                    is_dc=is_dc
                )
                session.add(target)
            else:
                # Update existing fields if new info is available
                if hostname: target.hostname = hostname
                if domain: target.domain = domain
                if os_version: target.os_version = os_version
                if is_dc: target.is_dc = is_dc
            
            session.commit()
            return target
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def add_credential(self, username, domain, password=None, ntlm_hash=None, source="unknown", is_admin=False):
        session = self.get_session()
        try:
            # Check for duplicates
            cred = session.query(Credential).filter_by(
                username=username, domain=domain, password=password, ntlm_hash=ntlm_hash
            ).first()
            
            if not cred:
                cred = Credential(
                    username=username,
                    domain=domain,
                    password=password,
                    ntlm_hash=ntlm_hash,
                    source=source,
                    is_admin=is_admin
                )
                session.add(cred)
                session.commit()
            return cred
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
