from typing import Optional
from fastapi import FastAPI,Request,HTTPException, Depends
from fastapi import HTTPException
from pydantic import BaseModel, Field
import time
import json
from datetime import datetime
import asyncio
import subprocess
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta  # Thêm timedelta vào import
from sqlalchemy import func
from sqlalchemy import or_
from ruleEngine import update_modsecurity_config
from ruleEngine import restart_apache
from ruleEngine import add_new_vhost_entry
from convertTime import convert_to_datetime
app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SQLITE_DATABASE_URL  = "sqlite:////home/kali/Desktop/WAF/db/modsec.db"
engine = create_engine(SQLITE_DATABASE_URL,connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ModsecLog(Base):
    __tablename__ = "modseclog"
    id = Column(Integer, primary_key=True, index=True)
    remote_address = Column(String)
    remote_port = Column(String)
    local_address = Column(String)
    local_port = Column(String)
    request = Column(String)
    time = Column(String)
    msg = Column(String)
    message = Column(String)

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
    Protocol = Column(String)  # This will store either 'http' or 'https'
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
    ErrorLog: str
    ErrorDocument: str
    Protocol: str
class HostUpdate(BaseModel):
    ProxyPreserveHost: Optional[str] = Field(default="")
    ProxyPass: Optional[str] = Field(default="")
    ProxyPassReverse: Optional[str] = Field(default="")
    ErrorLog: Optional[str] = Field(default="")
    ErrorDocument: Optional[str] = Field(default="")
    Protocol: Optional[str] = Field(default="")



@app.get("/")
def read_root():
    print("Hello world")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# LOG
@app.get("/getlog", tags=["logs"])
def get_log(number: int = 10,page: int = 1,distinct:int=0 ,filters: str = None):
    # oreder by id desc , filter with message colume with no case sensitive, distinct by msg
    db = SessionLocal()
    print(f"number: {number}, page: {page}, distinct: {distinct}, filters: {filters}")

    list_result = []
    list_msg = []
    try:
        query = db.query(ModsecLog)

        if filters:
            query = query.filter(ModsecLog.message.ilike(f"%{filters}%"))

        # if distinct == 1:
        #     query = query.distinct(ModsecLog.msg)

        log = query.order_by(ModsecLog.id.desc()).limit(number).offset((page - 1) * number).all()

        for entry in log:
            if distinct == 1 and entry.msg in list_msg:
                continue
            list_result.append({
                "id": entry.id,
                "remote_address": entry.remote_address,
                "remote_port": entry.remote_port,
                "local_address": entry.local_address,
                "local_port": entry.local_port,
                "request": entry.request,
                "time": entry.time,
                "msg": entry.msg,
                "message": entry.message
            })
            list_msg.append(entry.msg)
        del list_msg
        return list_result
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()
@app.get("/getLogWithinTime", tags=["logs"])
def get_log_within_time(
    time: int, number: int = 10, page: int = 1,
    src_ip: str = None, dest_ip: str = None, filters: str = None
):
    try:
        db = SessionLocal()
        print(f"time: {time}, number: {number}, page: {page}, src_ip: {src_ip}, dest_ip: {dest_ip}, filters: {filters}")

        query = db.query(ModsecLog)

        # Apply time filter
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time)
        query = query.filter(ModsecLog.time >= start_time, ModsecLog.time <= end_time)

        # Apply IP filters if provided
        if src_ip:
            query = query.filter(ModsecLog.remote_address == src_ip)
        if dest_ip:
            query = query.filter(ModsecLog.local_address == dest_ip)
        if filters:
            query = query.filter(ModsecLog.message.ilike(f"%{filters}%"))

        total_records = query.count()  # Get the total records matching the filter before applying limit and offset

        log = query.order_by(ModsecLog.id.desc()).limit(number).offset((page - 1) * number).all()

        list_result = []

        for entry in log:
            list_result.append({
                "id": entry.id,
                "remote_address": entry.remote_address,
                "remote_port": entry.remote_port,
                "local_address": entry.local_address,
                "local_port": entry.local_port,
                "request": entry.request,
                "time": entry.time,
                "msg": entry.msg,
                "message": entry.message
            })
        log_response = {
            "total": total_records,
            "data": list_result,
            "limit": number,
            "page": page,
            "total_pages": (total_records + number - 1) // number  # Calculate total pages
        }

        return log_response

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()
#get IP of attacker within time
@app.get("/getIPattackerWithinTime", tags=["logs"])
def get_IP_attacker_within_time(time: int, number: int = 10, page: int = 1, distinct: int = 0, filters: str = None):
    try:
        db = SessionLocal()
        print(f"time: {time}, number: {number}, page: {page}, distinct: {distinct}, filters: {filters}")

        query = db.query(ModsecLog.remote_address, func.count(ModsecLog.id)).\
            filter(ModsecLog.time >= datetime.now() - timedelta(hours=time)).\
            group_by(ModsecLog.remote_address).\
            order_by(func.count(ModsecLog.id).desc()).\
            limit(number).offset((page - 1) * number)

        if filters:
            query = query.filter(ModsecLog.message.ilike(f"%{filters}%"))

        results = query.all()

        # Tạo danh sách kết quả dưới dạng JSON
        list_result = {remote_address: count for remote_address, count in results}

        return list_result

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

# get the number of times d in a period
@app.get("/getDetectedTimes", tags=["logs"])
def get_detected_times(time:int):
    try:
        db = SessionLocal()
        print(f"time: {time}")

        query = db.query(func.count(ModsecLog.id)).\
            filter(ModsecLog.time >= datetime.now() - timedelta(hours=time))
        result = query.scalar()

        return {"detected_times": result}

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

#RULE        
@app.post("/update_RuleEngine_modsecconfig", tags=["rules"])
def update_modsecurity(port: int, mode: str):
    config_file_path = '/etc/apache2/sites-available/www.dvwa.com.conf'

    try:
        update_modsecurity_config(config_file_path, port, mode)
        return {"message": "ModSecurity configuration updated successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ModSecurity configuration: {str(e)}")           


#AGENT
@app.get("/getagent", tags=["agents"])
def get_agent(number: int = 10, page: int = 1, distinct: int = 0, filters: Optional[str] = None):
    db = SessionLocal()
    try:
        query = db.query(ModsecHost)
        if filters:
            # Construct a list of ilike filter conditions for all columns
            filter_conditions = []
            for column in ModsecHost.__table__.columns:
                filter_conditions.append(column.ilike(f"%{filters}%"))
            
            # Combine all filter conditions with OR
            query = query.filter(or_(*filter_conditions))
        skip = (page - 1) * number
        query = query.order_by(ModsecHost.id.asc())
        total = query.count()
        agents = query.offset(skip).limit(number).all()
        result_list = []
        for agent in agents:
            result_list.append({
                "id": agent.id,
                "Port": agent.Port,
                "ServerName": agent.ServerName,
                "ProxyPreserveHost": agent.ProxyPreserveHost,
                "ProxyPass": agent.ProxyPass,
                "ProxyPassReverse": agent.ProxyPassReverse,
                "ErrorLog": agent.ErrorLog,
                "ErrorDocument": agent.ErrorDocument,
                "Protocol": agent.Protocol,
                "SSLCertificateFile": agent.SSLCertificateFile,
                "SSLCertificateKeyFile": agent.SSLCertificateKeyFile,
                "SSLEngine": agent.SSLEngine,
                "SSLProxyEngine": agent.SSLProxyEngine
            })

        response = {
            "total": total,
            "limit": number,
            "page": page,
            "data": result_list
        }
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/addagent", tags=["agents"])
def add_agent(agent: HostAdd):
    config_file_path = f'/etc/apache2/sites-available/{agent.ServerName}.conf'
    config_file_apache = '/etc/apache2/apache2.conf'
    def check_port_in_apache_conf(port, file_content):
        listen_line = f"Listen {port}"
        return any(line.strip() == listen_line for line in file_content)
    db = SessionLocal()
    def check_vhost_exists(port, servername):
    # Kiểm tra xem có bản ghi nào có port hoặc servername như đã cho hay không
        existing_host = db.query(ModsecHost).filter(or_(ModsecHost.Port == port, ModsecHost.ServerName == servername)).first()
        if existing_host:
            print("Host đã tồn tại")
            return True  # Bản ghi đã tồn tại
        else:
            print("Host chưa tồn tại")
            return False  # Bản ghi không tồn tại 

    try:
        with open(config_file_apache, 'r') as file:
            apache_content = file.readlines()
        
        if not check_port_in_apache_conf(agent.Port, apache_content):
            with open(config_file_apache, 'a') as file:
                file.write(f"Listen {agent.Port}\n")
            subprocess.run(['sudo', 'service', 'apache2', 'reload'], check=True)
        with open(config_file_path, 'a') as file:
            pass
        with open(config_file_path, 'r') as file:
            vhost_content = file.readlines()
        
        if check_vhost_exists(agent.Port, agent.ServerName):
            raise HTTPException(status_code=400, detail="VirtualHost with this port and ServerName already exists.")
        
        new_vhost = add_new_vhost_entry(agent.Port, agent.ServerName, agent.ProxyPreserveHost, f'/ {agent.ProxyPass}', f'/ {agent.ProxyPassReverse}', agent.ErrorLog, f'403 {agent.ErrorDocument}', agent.Protocol)
        with open(config_file_path, 'a') as file:
            file.write(new_vhost)
        symlink_command = [
        'sudo', 'ln', '-s', 
        f'/etc/apache2/sites-available/{agent.ServerName}.conf', 
        f'/etc/apache2/sites-enabled/{agent.ServerName}.conf'
        ]
        try:
            subprocess.run(symlink_command, check=True)
        except subprocess.CalledProcessError as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Failed to create symbolic link: {e}")
        restart_apache()
                
        new_host = ModsecHost(
            Port=agent.Port,
            ServerName=agent.ServerName,
            ProxyPreserveHost=agent.ProxyPreserveHost,
            ProxyPass=agent.ProxyPass, 
            ProxyPassReverse=agent.ProxyPassReverse,
            ErrorLog=agent.ErrorLog,
            ErrorDocument= agent.ErrorDocument,
            Protocol=agent.Protocol,
            SSLCertificateFile = "/home/kali/Desktop/localhost.crt" if agent.Protocol == 'https' else None,  # Only for HTTPS
            SSLCertificateKeyFile = "/home/kali/Desktop/localhost.key" if agent.Protocol == 'https' else None,  # Only for HTTPS
            SSLEngine = "On" if agent.Protocol == 'https' else None,  # Only for HTTPS
            SSLProxyEngine = "On" if agent.Protocol == 'https' else None # Only for HTTPS
        )
        db.add(new_host)
        db.commit()
        
        return {"message": "Host added successfully to Apache and database."}
    except subprocess.CalledProcessError as e:
        print("rollback")
        print(e)
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to restart Apache: {e}")
    except Exception as e:
        db.rollback()
        error_message = f"Failed to add host: {repr(e)}"
        print(error_message)
        raise HTTPException(status_code=500, detail=f"Failed to add host: {str(e)}")
    finally:
        db.close()
        
#update host's config
@app.put("/updateagent/{host_id}", tags=["agents"])
def update_agent(host_id: int, host_update: HostUpdate):
    db = SessionLocal()
    ssl_lines = [
    "    SSLEngine on\n",
    "    SSLCertificateFile /home/kali/Desktop/localhost.crt\n",
    "    SSLCertificateKeyFile /home/kali/Desktop/localhost.key\n",
    "    ProxyRequests Off\n",
    "    SSLEngine On\n",
    "    SSLProxyEngine On\n",
    "    SSLProxyVerify none\n",
    "    SSLProxyCheckPeerCN off\n",
    "    SSLProxyCheckPeerName off\n"
]
    # Fetch the host from the database
    db_host = db.query(ModsecHost).filter(ModsecHost.id == host_id).first()
    config_file_path = f'/etc/apache2/sites-available/{db_host.ServerName}.conf'
    if db_host is None:
        raise HTTPException(status_code=404, detail="Host not found")

    # Read the Apache configuration file
    with open(config_file_path, 'r') as file:
        vhost_content = file.readlines()

    # Initialize a flag to determine if the protocol has changed
    protocol_changed = False
    config_changed = False

    # Check and update fields if they are provided in the request
    for var, value in vars(host_update).items():
        if value:
            # Update the field in the database
            setattr(db_host, var, value)
            print(var)
            # Check if protocol is being updated
            if var == "Protocol":
                protocol_changed = True
                # If changing to HTTPS, add the SSL configuration
                if value.lower() == 'https':
                    db_host.SSLCertificateFile = "/home/kali/Desktop/localhost.crt"
                    db_host.SSLCertificateKeyFile = "/home/kali/Desktop/localhost.key"
                    db_host.SSLEngine = "On"
                    db_host.SSLProxyEngine = "On"
                # If changing to HTTP, remove the SSL configuration
                elif value.lower() == 'http':
                    db_host.SSLCertificateFile = None
                    db_host.SSLCertificateKeyFile = None
                    db_host.SSLEngine = None
                    db_host.SSLProxyEngine = None
            config_changed = True

    db.commit()

    # If the protocol has changed, update the Apache configuration
    if config_changed:
        vhost_started = False
        closing_tag_index = None
        index_ssl=None
        for i, line in enumerate(vhost_content):
            if line.strip().startswith("<IfModule mod_security2.c>"):
                index_ssl=i
                if protocol_changed:
                    if db_host.Protocol.lower() == 'https':
                # Add SSL configuration lines before the closing tag
                        vhost_content.insert(index_ssl, ''.join(ssl_lines))
                    elif db_host.Protocol.lower() == 'http':
                # Remove SSL configuration lines
                        vhost_content = [
                            line for line in vhost_content
                            if not any(ssl_config_line.strip() in line for ssl_config_line in ssl_lines)
                        ]
                break
            else:
                index_ssl=None
            
        for i, line in enumerate(vhost_content):
            print(i)
            if line.strip().startswith(f"<VirtualHost *:{db_host.Port}>"):
                vhost_started = True
            
            # Update the directives inside the VirtualHost block
            if vhost_started:
                if line.strip().startswith("ProxyPreserveHost") and host_update.ProxyPreserveHost:
                    vhost_content[i] = f"    ProxyPreserveHost {host_update.ProxyPreserveHost}\n"
                elif line.strip().startswith("ProxyPass ") and host_update.ProxyPass:
                    vhost_content[i] = f"    ProxyPass / {host_update.ProxyPass}\n"
                elif line.strip().startswith("ProxyPassReverse ") and host_update.ProxyPassReverse:
                    vhost_content[i] = f"    ProxyPassReverse / {host_update.ProxyPassReverse}\n"
                elif line.strip().startswith("ErrorLog ") and host_update.ErrorLog:
                    vhost_content[i] = f"    ErrorLog {host_update.ErrorLog}\n"
                elif line.strip().startswith("ErrorDocument") and host_update.ErrorDocument:
                    vhost_content[i] = f"    ErrorDocument 403 {host_update.ErrorDocument}\n"
            elif vhost_started and "</VirtualHost>" in line.strip():
                vhost_started = False
                    
                


    # Write the updated content back to the Apache configuration file
        with open(config_file_path, 'w') as file:
            file.writelines(vhost_content)

    # Restart Apache to apply changes
    restart_apache()

    return {"message": "Host configuration updated successfully."}

@app.delete("/deleteagent/{host_id}", tags=["agents"])
def delete_agent(host_id: int):
    db = SessionLocal()
    def check_port_in_apache_conf(port, file_content):
        listen_line = f"Listen {port}"
        return any(line.strip() == listen_line for line in file_content)
    try:
        # Fetch the host from the database
        db_host = db.query(ModsecHost).filter(ModsecHost.id == host_id).first()
        if db_host is None:
            raise HTTPException(status_code=404, detail="Host not found")

        # Delete the host from the database
        db.delete(db_host)
        db.commit()
        # Close port
        config_file_apache = '/etc/apache2/apache2.conf'
        with open(config_file_apache, 'r') as file:
            apache_content = file.readlines()
        if not check_port_in_apache_conf(db_host.Port, apache_content):
            with open(config_file_apache, 'w') as file:
                for line in apache_content:
                    if line.strip() != f"Listen {db_host.Port}":
                        file.write(line)
            subprocess.run(['sudo', 'service', 'apache2', 'reload'], check=True)

        # Delete the Apache configuration file
        config_file_path = f'/etc/apache2/sites-available/{db_host.ServerName}.conf'
        try:
            subprocess.run(['sudo', 'rm', config_file_path], check=True)
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Failed to delete Apache configuration file: {e}")

        # Remove the symbolic link
        try:
            subprocess.run(['sudo', 'rm', f'/etc/apache2/sites-enabled/{db_host.ServerName}.conf'], check=True)
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Failed to remove symbolic link: {e}")

        # Restart Apache to apply changes
        restart_apache()

        return {"message": "Host deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5555, reload=True)
