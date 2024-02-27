from typing import Optional
from fastapi import FastAPI,Request,HTTPException, Depends
from fastapi import HTTPException
from pydantic import BaseModel
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
    port = Column(Integer, index=True)
    servername = Column(String)
    proxypreservehost = Column(String)
    proxypass = Column(String)
    proxypassreverse = Column(String)
    errorlog = Column(String)
    errordocument = Column(String)
    protocol = Column(String)  # This will store either 'http' or 'https'
    sslcertificatefile = Column(String, nullable=True)  # Only for HTTPS
    sslcertificatekeyfile = Column(String, nullable=True)  # Only for HTTPS
    sslengine = Column(String, nullable=True)  # Only for HTTPS
    sslproxyengine = Column(String, nullable=True)  # Only for HTTPS
class AgentUpdate(BaseModel):
    servername: str
    ProxyPreserveHost: str
    ProxyPass: str
    ProxyPassReverse: str
    ErrorLog: str
    ErrorDocument: str
    protocol: str

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
def get_log_within_time(time: int, number: int = 10, page: int = 1, distinct: int = 0, filters: str = None):
    try:
        db = SessionLocal()
        print(f"time: {time}, number: {number}, page: {page}, distinct: {distinct}, filters: {filters}")

        query = db.query(ModsecLog)

        # Áp dụng bộ lọc thời gian
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time)
        print(start_time)
        print(end_time)
        query = query.filter(ModsecLog.time >= start_time, ModsecLog.time <= end_time)

        if filters:
            query = query.filter(ModsecLog.message.ilike(f"%{filters}%"))

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

        return list_result

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
        # Begin building the query
        query = db.query(ModsecHost)
        
        # Apply filters if provided
        if filters:
            # Assuming filters is a JSON string with key-value pairs
            # Convert the filters from JSON to a dictionary
            filter_dict = json.loads(filters)
            
            # Apply the filters
            for key, value in filter_dict.items():
                query = query.filter(getattr(ModsecHost, key) == value)

        # Apply distinct if needed
        if distinct:
            query = query.distinct()

        # Calculate the offset for pagination
        skip = (page - 1) * number

        # Fetch the results with pagination
        agents = query.order_by(ModsecHost.id.asc()).offset(skip).limit(number).all()

        # Prepare the result list
        result_list = []
        for agent in agents:
            result_list.append({
                "id": agent.id,
                "port": agent.port,
                "servername": agent.servername,
                "proxypreservehost": agent.proxypreservehost,
                "proxypass": agent.proxypass,
                "proxypassreverse": agent.proxypassreverse,
                "errorlog": agent.errorlog,
                "errordocument": agent.errordocument,
                "protocol": agent.protocol,
                "sslcertificatefile": agent.sslcertificatefile,
                "sslcertificatekeyfile": agent.sslcertificatekeyfile,
                "sslengine": agent.sslengine,
                "sslproxyengine": agent.sslproxyengine
            })

        return result_list
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/addagent", tags=["agents"])
def add_agent(port: int, servername: str, ProxyPreserveHost: str, ProxyPass: str, ProxyPassReverse: str, ErrorLog: str, ErrorDocument: str, protocol: str):
    config_file_path = '/etc/apache2/sites-available/www.dvwa.com.conf'
    config_file_apache = '/etc/apache2/apache2.conf'
    
    def check_port_in_apache_conf(port, file_content):
        listen_line = f"Listen {port}"
        return any(line.strip() == listen_line for line in file_content)

    def check_vhost_exists(port, servername, vhost_content):
        vhost_line = f"<VirtualHost *:{port}>"
        servername_line = f"ServerName {servername}"
        inside_vhost = False
        for line in vhost_content:
            if vhost_line in line:
                inside_vhost = True
            elif inside_vhost and servername_line in line:
                return True
            elif inside_vhost and line.startswith('</VirtualHost>'):
                inside_vhost = False
        return False

    try:
        with open(config_file_apache, 'r') as file:
            apache_content = file.readlines()
        
        if not check_port_in_apache_conf(port, apache_content):
            with open(config_file_apache, 'a') as file:
                file.write(f"Listen {port}\n")
            subprocess.run(['sudo', 'service', 'apache2', 'reload'], check=True)
        
        with open(config_file_path, 'r') as file:
            vhost_content = file.readlines()
        
        if check_vhost_exists(port, servername, vhost_content):
            raise HTTPException(status_code=400, detail="VirtualHost with this port and ServerName already exists.")
        
        new_vhost = add_new_vhost_entry(port, servername, ProxyPreserveHost, ProxyPass, ProxyPassReverse, ErrorLog, ErrorDocument, protocol)
        with open(config_file_path, 'a') as file:
            file.write(new_vhost)
        
        restart_apache()
        
        db = SessionLocal()

        new_host = ModsecHost(
            port=port,
            servername=servername,
            proxypreservehost=ProxyPreserveHost,
            proxypass=ProxyPass,
            proxypassreverse=ProxyPassReverse,
            errorlog=ErrorLog,
            errordocument=ErrorDocument,
            protocol=protocol,
            sslcertificatefile = "/home/kali/Desktop/localhost.crt" if protocol == 'https' else None,  # Only for HTTPS
            sslcertificatekeyfile = "/home/kali/Desktop/localhost.key" if protocol == 'https' else None,  # Only for HTTPS
            sslengine = "On" if protocol == 'https' else None,  # Only for HTTPS
            sslproxyengine = "On" if protocol == 'https' else None # Only for HTTPS
        )
        
        db.add(new_host)
        db.commit()
        
        return {"message": "Host added successfully to Apache and database."}
    except subprocess.CalledProcessError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to restart Apache: {e}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to add host: {str(e)}")
    finally:
        db.close()
        
#update host's config
@app.put("/updateagent", tags=["agents"])
def update_agent(port: int, servername: str, ProxyPreserveHost: str, ProxyPass: str, ProxyPassReverse: str, ErrorLog: str, ErrorDocument: str, protocol: str):
    config_file_path = '/etc/apache2/sites-available/www.dvwa.com.conf'
    config_file_apache = '/etc/apache2/apache2.conf'

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5555, reload=True)
