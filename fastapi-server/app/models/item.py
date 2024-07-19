from typing import Optional
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from database import Base

class ModsecHost(Base):
    __tablename__ = "modsechost"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    Port = Column(Integer, index=True)
    ServerName = Column(String)
    ProxyPreserveHost = Column(String)
    ProxyPass = Column(String)
    ProxyPassReverse = Column(String)
    ErrorLog = Column(String)
    ErrorDocument = Column(String)
    Protocol = Column(String) # This will store either 'http' or 'https'
    SecRuleEngine = Column(String) 
    SSLCertificateFile = Column(String, nullable=True)  # Only for HTTPS
    SSLCertificateKeyFile = Column(String, nullable=True)  # Only for HTTPS
    SSLEngine = Column(String, nullable=True)  # Only for HTTPS
    SSLProxyEngine = Column(String, nullable=True)  # Only for HTTPS
    
class HostAdd(BaseModel):
    Port: int
    ServerName: str
    ProxyPreserveHost: str
    ProxyPass: str
    ProxyPassReverse: str
    ErrorDocument: str
    Protocol: str
class HostUpdate(BaseModel):
    ProxyPreserveHost: Optional[str] = Field(default="")
    ProxyPass: Optional[str] = Field(default="")
    ProxyPassReverse: Optional[str] = Field(default="")
    ErrorDocument: Optional[str] = Field(default="")
    Protocol: Optional[str] = Field(default="")

class ModsecLog1(Base):
    __tablename__ = "modseclog1"
    id = Column(Integer, primary_key=True, index=True)
    transaction_id = Column(String)
    event_time = Column(String)
    remote_address = Column(String) 
    remote_port = Column(String) 
    request_host = Column(String)
    local_port = Column(String)
    request_useragent = Column(String)
    request_line = Column(String)
    request_line_method = Column(String)
    request_line_url = Column(String)
    request_line_protocol = Column(String)
    response_protocol = Column(String)
    response_status = Column(String)
    action = Column(String)
    action_phase = Column(String)
    action_message = Column(String)
    message_type = Column(String)
    message_description = Column(String)
    message_rule_id = Column(String)
    message_rule_file = Column(String)
    message_msg = Column(String)
    message_severity = Column(String)
    message_accuracy = Column(String)
    message_maturity = Column(String)
    full_message_line = Column(String)

class Request(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True, index=True)
    server_name = Column(String)
    port = Column(String)
    target_url = Column(String)
    source_ip = Column(String)
    datetime_request = Column(String)
    
class RuleContent(BaseModel):
    rule_content: str

class RuleModel(BaseModel):
    ServerName: str
    Port: str
    rules: str
class RuleAllModel(BaseModel):
    name: str
    rules: str

class ModSecurityConfig(BaseModel):
    SecRuleEngine: Optional[str] = Field(default="")
    SecDebugLogLevel: Optional[str] = Field(default="")
    SecAuditEngine:Optional[str] = Field(default="")
    SecAuditLogRelevantStatus: Optional[str] = Field(default="")
    SecAuditLogParts: Optional[str] = Field(default="")
    SecAuditLogType: Optional[str] = Field(default="")
    SecStatusEngine: Optional[str] = Field(default="")

class Rule_Remove(Base):
    __tablename__ = "rule_remove"
    id_rule= Column(String, primary_key=True)
    rule_file= Column(String)
    servername= Column(String)
    port = Column(String)