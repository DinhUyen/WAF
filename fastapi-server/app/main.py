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
import psutil
import pandas as pd
import re
import os
import glob
from sqlalchemy import case
from io import BytesIO
from fastapi.responses import StreamingResponse
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta  # Thêm timedelta vào import
from sqlalchemy import func, distinct
from sqlalchemy import and_
from sqlalchemy import or_
from sqlalchemy.sql import text, func
from ruleEngine import restart_apache
from ruleEngine import add_new_vhost_entry
from pathlib import Path
from tempfile import NamedTemporaryFile
import matplotlib.pyplot as plt
from collections import Counter
from fastapi.responses import FileResponse
from fastapi import Query
from sqlalchemy.exc import SQLAlchemyError
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
from starlette.responses import Response
app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SQLITE_DATABASE_URL  = "sqlite:////learning/modsec.db"
engine = create_engine(SQLITE_DATABASE_URL,connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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
def get_log(number: int = 10, page: int = 1, distinct: int = 0, filters: str = None):
    db = SessionLocal()
    try:
        join_condition = or_(
            (ModsecHost.Port.in_([80, 443]) & (ModsecHost.ServerName == ModsecLog1.request_host)),
            ((ModsecHost.Port.notin_([80, 443])) & ((ModsecHost.ServerName + ":" + ModsecHost.Port.cast(String)) == ModsecLog1.request_host))
        )

        query = db.query(ModsecLog1, ModsecHost.ServerName).join(
            ModsecHost, join_condition
        )
        if filters:
            query = query.filter(ModsecLog1.message_msg.ilike(f"%{filters}%"))
        if distinct == 1:
            query = query.group_by(ModsecLog1.message_msg)
        log_entries = query.order_by(ModsecLog1.id.desc()).limit(number).offset((page - 1) * number).all()
        list_result = []
        for entry in log_entries:
            log, server_name = entry
            action_value = "passed" if log.action == "-" else log.action
            response_status_value = "403" if log.response_status == "-" else log.response_status
            list_result.append({
                "id": log.id,
                "transaction_id": log.transaction_id,
                "event_time": log.event_time,
                "remote_address": log.remote_address,
                "local_port": log.local_port,
                "server_name": server_name,
                "request": log.request_line,
                "response_status": response_status_value,
                "action": action_value,
                "message_msg": log.message_msg,
                "message_rule_id": log.message_rule_id                
            })
        return list_result
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

@app.get("/count_request", tags=["logs"],
         description="This API fetches the number of requests within a specified time frame.")
def count_request(time:int):
    db = SessionLocal()
    try:
        current_time = datetime.now()
        time_threshold = current_time - timedelta(hours=time)
        count = db.query(Request).filter(Request.datetime_request >= time_threshold, Request.datetime_request<= current_time).count()
        return count
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()
@app.get("/count_request_by_servername", tags=["logs"],
         description="This API fetches the number of requests within a specified time frame for a specific agent.")
def count_request(time:int, local_port: str = None, ServerName: str = None):
    db = SessionLocal()
    try:
        current_time = datetime.now()
        time_threshold = current_time - timedelta(hours=time)
        count = db.query(Request).filter(Request.datetime_request >= time_threshold, Request.datetime_request<= current_time, Request.server_name==ServerName, Request.port==local_port).count()
        return count
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/get_log_xlsx", tags=["logs"],
         description="This API fetches logs and returns them as an Excel file.")
def get_log_xlsx():
    db = SessionLocal()
    try:
        query = db.query(ModsecLog1)
        log = query.all()
        list_result = []
        for entry in log:
            list_result.append(entry.__dict__)
        
        # Convert to a Pandas DataFrame
        df = pd.DataFrame(list_result)
        
        # Remove metadata from the SQLAlchemy results
        df = df.drop('_sa_instance_state', axis=1)
        
        # Convert the DataFrame into an Excel file in memory
        excel_file = BytesIO()
        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='ModsecLog1 Data')
        
        # Reset file pointer
        excel_file.seek(0)
        
        # Create a filename with the current timestamp
        file_name = f"modseclog_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.xlsx"
        
        # Create a StreamingResponse to send the data back to the client
        response = StreamingResponse(excel_file, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response.headers["Content-Disposition"] = f"attachment; filename={file_name}"
        return response

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/getLogWithinTime", tags=["logs"],
         description="This API fetches logs within a specified time frame.")
def get_log_within_time(time: int, number: int = 10, page: int = 1,
    src_ip: str = None, local_port: str = None, ServerName: str = None, filters: str = None):
    try:
        db = SessionLocal()
        print(f"time: {time}, number: {number}, page: {page}, src_ip: {src_ip}, local_port: {local_port}, ServerName: {ServerName}, filters: {filters}")
        join_condition = or_(
            (ModsecHost.Port.in_([80, 443]) & (ModsecHost.ServerName == ModsecLog1.request_host)),
            ((ModsecHost.Port.notin_([80, 443])) & ((ModsecHost.ServerName + ":" + ModsecHost.Port.cast(String)) == ModsecLog1.request_host))
        )

        query = db.query(ModsecLog1, ModsecHost.ServerName).join(
            ModsecHost, join_condition
        )
        # Apply time filter
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time)
        query = query.filter(ModsecLog1.event_time >= start_time, ModsecLog1.event_time <= end_time)

        # Apply IP filters if provided
        if src_ip:
            query = query.filter(ModsecLog1.remote_address == src_ip)
        if local_port:
            query = query.filter(ModsecLog1.local_port == local_port)
        if ServerName:
            query = query.filter(ModsecHost.ServerName == ServerName)
        if filters:
            query = query.filter(ModsecLog1.message.ilike(f"%{filters}%"))

        total_records = query.count()  # Get the total records matching the filter before applying limit and offset

        log_entries = query.order_by(ModsecLog1.id.desc()).limit(number).offset((page - 1) * number).all()

        list_result = []
        for entry in log_entries:
            log, server_name = entry
            action_value = "passed" if log.action == "-" else log.action
            response_status_value = "403" if log.response_status == "-" else log.response_status
            list_result.append({
                "id": log.id,
                "transaction_id": log.transaction_id,
                "event_time": log.event_time,
                "remote_address": log.remote_address,
                "local_port": log.local_port,
                "server_name": server_name,
                "request": log.request_line,
                "response_status": response_status_value,
                "action": action_value,
                "message_msg": log.message_msg,
                "message_rule_id": log.message_rule_id                
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


@app.get("/get_log_within_time_xlsx", tags=["logs"],
         description="This API fetches logs within a specified time frame and returns them as an Excel file.")
def get_log_within_time_xlsx(
    time: int, src_ip: str = None, local_port: str = None, ServerName: str = None, filters: str = None):
    db = SessionLocal()
    try:
        query = db.query(ModsecLog1)
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time)
        query = query.filter(ModsecLog1.event_time >= start_time, ModsecLog1.event_time <= end_time)
        if src_ip:
            query = query.filter(ModsecLog1.remote_address == src_ip)
        if local_port:
            query = query.filter(ModsecLog1.local_port == local_port)
        if ServerName:
            query = query.join(ModsecHost, ModsecLog1.local_port == ModsecHost.Port).filter(ModsecHost.ServerName == ServerName)
        if filters:
            query = query.filter(ModsecLog1.message.ilike(f"%{filters}%"))
        logs = query.order_by(ModsecLog1.id.desc()).all()
        
        # Create a list of dictionaries, excluding the '_sa_instance_state'
        list_result = [{column.name: getattr(entry, column.name) for column in ModsecLog1.__table__.columns} for entry in logs]
        
        # Convert to a Pandas DataFrame
        df = pd.DataFrame(list_result)
        
        # Convert the DataFrame into an Excel file in memory
        excel_file = BytesIO()
        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='ModsecLog Data')
        
        # Reset file pointer
        excel_file.seek(0)
        
        # Create a filename with the current timestamp
        file_name = f"modseclog_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}-{time}hours.xlsx"
        
        # Create a StreamingResponse to send the data back to the client
        response = StreamingResponse(excel_file, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        response.headers["Content-Disposition"] = f"attachment; filename={file_name}"
        return response

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

#get IP of attacker within time
@app.get("/getIPattackerWithinTime", tags=["logs"],
         description="This API fetches IP addresses of attackers within a specified time frame.")
def get_IP_attacker_within_time(time: int, number: int = 10, page: int = 1, distinct: int = 0, filters: str = None):
    try:
        db = SessionLocal()
        print(f"time: {time}, number: {number}, page: {page}, distinct: {distinct}, filters: {filters}")

        query = db.query(ModsecLog1.remote_address, func.count(ModsecLog1.id)).\
            filter(ModsecLog1.event_time >= datetime.now() - timedelta(hours=time)).\
            group_by(ModsecLog1.remote_address).\
            order_by(func.count(ModsecLog1.id).desc()).\
            limit(number).offset((page - 1) * number)

        if filters:
            query = query.filter(ModsecLog1.message.ilike(f"%{filters}%"))

        results = query.all()

        # Tạo danh sách kết quả dưới dạng JSON
        list_result = {remote_address: count for remote_address, count in results}

        return list_result

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/count_IP_attacker_within_time_by_ID", tags=["logs"],
         description="This API fetches the number of distinct IP addresses that have attacked within a specified time frame for a specific agent.")
def count_IP_attacker_within_time_by_ID(id: int, time: int):
    try:
        db = SessionLocal()

        join_condition = or_(
            (ModsecHost.Port.in_([80, 443]) & (ModsecHost.ServerName == ModsecLog1.request_host)),
            ((ModsecHost.Port.notin_([80, 443])) & ((ModsecHost.ServerName + ":" + ModsecHost.Port.cast(String)) == ModsecLog1.request_host))
        )

        # Count distinct IP addresses that have attacked within the given time frame for the specified ID
        total_attacks = db.query(func.count(ModsecLog1.remote_address.distinct())).\
            join(ModsecHost, join_condition).\
            filter(
                ModsecLog1.event_time >= datetime.now() - timedelta(hours=time),
                ModsecHost.id == id
            ).scalar()

        return {"total_ip_attacks": total_attacks}

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/get_Attacks_Map", tags=["logs"],
         description="This API fetches the locations of the most recent attacks.")
def get_Attacks_Map():
    db = SessionLocal()
    geoip_reader = Reader('/home/kali/Desktop/WAF/db/GeoLite2-City.mmdb')    
    try:
        recent_attacks = db.query(ModsecLog1.remote_address).distinct().limit(10).all()
        #recent_attacks = [('103.172.79.50',), ('149.28.159.120',)]
        attacks_info = []
        for attack in recent_attacks:
            ip = attack.remote_address
            print(ip)
            #ip = ip = attack[0]
            try:
                response = geoip_reader.city(ip)
                print(response.location)
                attacks_info.append({
                    "ip": ip,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "city": response.city.name,
                    "country": response.country.name
                })
            except AddressNotFoundError:
                # Xử lý trường hợp IP không tìm thấy vị trí
                print(f"Location not found for IP: {ip}")
        return attacks_info            
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

#get attack map theo IP
@app.get("/getAttackMapIP", tags=["logs"],
         description="This API fetches the location of a specific IP address.")
def get_attack_map_ip(ip: str):
    geoip_reader = Reader('/home/kali/Desktop/WAF/db/GeoLite2-City.mmdb')

    try:
        # Ensure the IP is a valid format, if needed add validation here.
        print(ip)
        try:
            response = geoip_reader.city(ip)
            print(response.location)
            attack_info = {
                "ip": ip,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "city": response.city.name,
                "country": response.country.name
            }
            return attack_info
        except AddressNotFoundError:
            # Handle case where IP location is not found
            print(f"Location not found for IP: {ip}")
            return {"error": "Location not found for the provided IP address."}
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        geoip_reader.close()

# get the number of times d in a period
@app.get("/getDetectedTimes", tags=["logs"],
         description="This API fetches the number of times an attack has been detected within a specified time frame.")
def get_detected_times(time:int):
    try:
        db = SessionLocal()
        print(f"time: {time}")

        query = db.query(func.count(ModsecLog1.id)).\
            filter(ModsecLog1.event_time >= datetime.now() - timedelta(hours=time))
        result = query.scalar()

        return {"detected_times": result}

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/getDetectedTimesByID", tags=["logs"],
         description="This API fetches the number of times an attack has been detected within a specified time frame for a specific agent.")
def get_detected_times_byID(time: int, id: int):
    try:
        db = SessionLocal()
        print(f"time: {time}, id: {id}")
        join_condition = or_(
            (ModsecHost.Port.in_([80, 443]) & (ModsecHost.ServerName == ModsecLog1.request_host)),
            ((ModsecHost.Port.notin_([80, 443])) & ((ModsecHost.ServerName + ":" + ModsecHost.Port.cast(String)) == ModsecLog1.request_host))
        )

        # Adjusting the query to join ModsecLog1 with ModsecHost
        query = db.query(func.count(ModsecLog1.id)).\
            join(ModsecHost, join_condition).\
            filter(
                ModsecLog1.event_time >= datetime.now() - timedelta(hours=time),
                ModsecHost.id == id
            )
        result = query.scalar()
        return {"detected_times": result}

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

#Graph
@app.get("/get_severity", tags=["logs"],
         description="This API fetches the severity of attacks for each agent.")
def get_severity():
    db = SessionLocal()
    try:
        join_condition = or_(
            (ModsecHost.Port.in_([80, 443]) & (ModsecHost.ServerName == ModsecLog1.request_host)),
            ((ModsecHost.Port.notin_([80, 443])) & ((ModsecHost.ServerName + ":" + ModsecHost.Port.cast(String)) == ModsecLog1.request_host))
        )
        query = db.query(
            ModsecHost.ServerName,
            ModsecHost.Port,
            ModsecLog1.message_severity,
            func.count(ModsecLog1.id)
        ).join(
            ModsecHost, join_condition
        ).group_by(
            ModsecHost.ServerName,
            ModsecHost.Port,
            ModsecLog1.message_severity
        )
        
        results = query.all()
        list_result = [
            {"host": host, "port": port, "severity": severity, "count": count}
            for host, port, severity, count in results
        ]
        return list_result
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/graph_count_log_within_24h", tags=["logs"],
         description="This API is used to count the number of blocked requests per time interval.")
def graph_count_log_within_24h():
    # Tạo kết nối database
    db = SessionLocal()
    list_result = []

    try:
        current_time = datetime.now()
        if current_time.minute > 0 or current_time.second > 0 or current_time.microsecond > 0:
            current_time = current_time.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        start_time = current_time - timedelta(days=1)
        for i in range(8):
            period_start = start_time + timedelta(hours=i*3)
            period_end = start_time + timedelta(hours=(i+1)*3)

            total_count = db.query(func.count(Request.id)).filter(
                Request.datetime_request >= period_start,
                Request.datetime_request < period_end
            ).scalar()
            malicious_count = db.query(func.count(distinct(ModsecLog1.request_line))).filter(
                ModsecLog1.event_time >= period_start,
                ModsecLog1.event_time < period_end
            ).scalar()
            # Add results to the list
            list_result.append({
                "time": f"{period_start.strftime('%H.%M')}-{period_end.strftime('%H.%M')}",
                "number_of_prevented": malicious_count,
                "total_requests": total_count,
            })

        return list_result

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/graph_count_log_within_24h_byID", tags=["logs"],
         description="This API is used to count the number of blocked requests per time interval for a specific agent.")
def graph_count_log_within_24h_byID(id:int):
    # Tạo kết nối database
    db = SessionLocal()
    list_result = []

    try:
        current_time = datetime.now()
        if current_time.minute > 0 or current_time.second > 0 or current_time.microsecond > 0:
            current_time = current_time.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        start_time = current_time - timedelta(days=1)
        for i in range(8):
            period_start = start_time + timedelta(hours=i*3)
            period_end = start_time + timedelta(hours=(i+1)*3)

           # Define the condition for joining based on the value of ModsecHost.Port
            join_condition = or_(
                (ModsecHost.Port.in_([80, 443]) & (ModsecHost.ServerName == ModsecLog1.request_host)),
                ((ModsecHost.Port.notin_([80, 443])) & ((ModsecHost.ServerName + ":" + ModsecHost.Port.cast(String)) == ModsecLog1.request_host))
            )

            count = db.query(func.count(ModsecLog1.id)).join(
                ModsecHost, join_condition
            ).filter(
                ModsecLog1.event_time >= period_start,
                ModsecLog1.event_time < period_end,
                ModsecHost.id == id
            ).scalar()

            # Thêm kết quả vào danh sách
            list_result.append({
                "time": f"{period_start.strftime('%H.%M')}-{period_end.strftime('%H.%M')}",
                "number_of_prevented": count
            })

        return list_result

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/grap_TOP10_IP_source_addresses_json", tags=["logs"],
         description="This API fetches the top 10 source IP addresses.")
def grap_TOP10_IP_source_addresses_json():
    db = SessionLocal()
    try:
        src_ip_data = db.query(ModsecLog1.remote_address).all()
        
        # Count occurrences of each IP
        src_ip_counter = Counter([data.remote_address for data in src_ip_data])
        top10_ips = src_ip_counter.most_common(10)

        # Prepare the list of results
        list_result = [{"ip": ip, "count": count} for ip, count in top10_ips]

        # Return the list as JSON
        return list_result

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/graph-top20-rule-hit", tags=["logs"],
         description="This API fetches the top 20 rules that have been hit the most.")
def graph_top20_rule_hit():
    db = SessionLocal()
    try:
        # Truy vấn cơ sở dữ liệu để lấy 20 luật được hit nhiều nhất và các trường liên quan
        query = (
            db.query(
                ModsecLog1.message_rule_id,
                ModsecLog1.message_msg.label('rule_msg'),
                ModsecLog1.message_severity.label('rule_severity'),
                ModsecLog1.message_rule_file.label('rule_file'),
                func.count(ModsecLog1.id).label('count')
            )
            .group_by(
                ModsecLog1.message_rule_id,
                ModsecLog1.message_msg,
                ModsecLog1.message_severity,
                ModsecLog1.message_rule_file
            )
            .order_by(
                func.count(ModsecLog1.id).desc()
            )
            .limit(20)
        )

        # Thực thi truy vấn và lấy kết quả
        result = query.all()
        list_result = []
        for item in result:
            # Rút gọn rule_msg nếu dài hơn 30 ký tự
            rule_msg = item.rule_msg
            if len(rule_msg) > 30:
                rule_msg = rule_msg[:27] + '...'
            # Đặt lại rule_msg nếu có điều kiện cụ thể
            if rule_msg == '?' and item.message_rule_id == '-':
                rule_msg = "Unknown rule"  # Sửa lại để phản ánh chuỗi bạn muốn sử dụng

            list_result.append({
                "rule_id": item.message_rule_id,
                "rule_file": item.rule_file,
                "count": item.count,
                "rule_descr": f"id: {item.message_rule_id}, sev: {item.rule_severity}, msg: {rule_msg}"
            })

        # Trả về danh sách dưới dạng JSON
        return list_result

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/graph_TOP10_Attacks_intercepted", tags=["logs"],
         description="This API fetches the top 10 attacks intercepted.")
def graph_TOP10_Attacks_intercepted():
    db = SessionLocal()
    try:
        # Query the database for the top 10 attacks intercepted grouped by action_message
        top_attacks = (
            db.query(
                ModsecLog1.action_message,
                func.count(ModsecLog1.id).label('count')
            )
            .group_by(ModsecLog1.action_message)
            .order_by(func.count(ModsecLog1.id).desc())
            .limit(10)
            .all()
        )

        # Construct a list of dictionaries to be returned as JSON
        top_attacks_list = [
            {"action_message": attack.action_message, "count": attack.count}
            for attack in top_attacks
        ]

        # Return the list as JSON
        return top_attacks_list

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@app.get("/graph_Passed_and_Intercepted", tags=["logs"],
         description="This API fetches the number of requests that have passed and been intercepted.")
def graph_Passed_and_Intercepted(
        time_start: Optional[datetime] = Query(
            None, 
            title="Start Time", 
            description="The start time for filtering logs, format: YYYY-MM-DDTHH:MM:SS", 
            example="2024-02-24T09:00:00"
        ), 
        time_end: Optional[datetime] = Query(
            None, 
            title="End Time", 
            description="The end time for filtering logs, format: YYYY-MM-DDTHH:MM:SS", 
            example="2024-02-27T17:00:00"
        )):
    db = SessionLocal()
    LOG_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S'             
    LOG_TIMESTAMP_FORMAT_TIMEMS = '%d/%b/%Y:%H:%M:%S.%f %z' 
    OUTPUT_TIMESTAMP_FORMAT = '%H:%M:%S %d-%m-%Y'  
    try:
        base_query  = db.query(ModsecLog1.event_time, ModsecLog1.action)
        # Create DataFrame from query results
        if time_start and time_end:
            base_query = base_query.filter(ModsecLog1.event_time.between(time_start, time_end))
        if time_start:
            base_query = base_query.filter(ModsecLog1.event_time >= time_start)
        logs_query  = base_query.all()
        events_df = pd.DataFrame(logs_query, columns=['event_time', 'action'])
        # Function to parse timestamps
        def parse_timestamp(time_str):
            try:
                return datetime.strptime(time_str, LOG_TIMESTAMP_FORMAT).replace(tzinfo=None)
            except ValueError:
                return datetime.strptime(time_str, LOG_TIMESTAMP_FORMAT_TIMEMS).replace(tzinfo=None)
        def reformat_timestamp(dt):
            return dt.strftime(OUTPUT_TIMESTAMP_FORMAT)
        # Convert event_time strings to datetime objects
        events_df['event_time'] = events_df['event_time'].apply(parse_timestamp)
        # Assuming 'intercepted' represents 'Intercepted' and '-' represents 'Passed'
        events_df['intercepted'] = events_df['action'] == 'intercepted'
        events_df['passed'] = events_df['action'] == '-'
        # Determine the period based on the event time range
        event_time_min = events_df['event_time'].min()
        event_time_max = events_df['event_time'].max()
        event_time_range = event_time_max - event_time_min
        event_time_range_minutes = int(event_time_range.total_seconds() / 60)

        if event_time_range_minutes < 60:
            periods = 'S'
        else:
            periods = str(int(event_time_range_minutes / 30)) + 'T'
        # Group by determined period and calculate sum
        grouped_df = events_df.resample(periods, on='event_time').sum()
        grouped_df.index = grouped_df.index.map(reformat_timestamp)
        # Convert DataFrame to dictionary for JSON response
        passed_intercepted_dict = grouped_df[['passed', 'intercepted']].to_dict(orient='index')
        # Return data as JSON
        return passed_intercepted_dict

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

#RULE  

@app.get("/get_rule_each_agent", tags=["rules"],
          description="This API fetches rules for each agent.")
def get_rule_custom(ServerName: str, Port: int):
    rule_file_path = f'/etc/modsecurity/custom_rules/{ServerName}_{Port}_rules.conf'
    try:
        with open(rule_file_path, 'r') as file:
            content = file.read()
            # Trả về nội dung dưới dạng Response với media_type là text/plain
            return Response(content=content, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read ModSecurity rule file: {e}")
#update rule custom
class RuleModel(BaseModel):
    ServerName: str
    Port: str
    rules: str
@app.post("/update_rule_each_agent", tags=["rules"],
          description="Update rules for each agent.")
async def update_rule_custom(ruleModel: RuleModel):

    rule_file_path = f'/etc/modsecurity/custom_rules/{ruleModel.ServerName}_{ruleModel.Port}_rules.conf'
    rules = ruleModel.rules
    
    try:
        with open(rule_file_path, 'w') as f:   
            f.write(rules)
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"Rule for {ruleModel.ServerName} updated and Apache reloaded successfully."}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload Apache: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ModSecurity rule file: {e}")
@app.get("/get_rule_file", tags=["rules"],
         description="The API retrieves the created rule files for all.")
def get_rule_file():
    try:
        rule_files = []
        rule_files_path = '/etc/modsecurity/custom_rule_all'
        for file in os.listdir(rule_files_path):
            if file.endswith(".conf"):
                file_path = os.path.join(rule_files_path, file)
                creation_time = os.path.getctime(file_path)
                modification_time = os.path.getmtime(file_path)
                rule_files.append({
                    "file_name": file,
                    "creation_date": datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S'),
                    "modification_date": datetime.fromtimestamp(modification_time).strftime('%Y-%m-%d %H:%M:%S')
                })
        return rule_files
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read ModSecurity rule files: {e}")
    
@app.post("/create_rule_file", tags=["rules"],
          description="Create a rule file for all agents.")
def create_rule_file(rule_name: str):
    rule_file_path = f'/etc/modsecurity/custom_rule_all/{rule_name}.conf'
    try:
        with open(rule_file_path, 'w') as f:
            f.write("# Rule file for all agents\n")
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"Rule file {rule_name}.conf created successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create ModSecurity rule file: {e}")

@app.delete("/delete_rule_file", tags=["rules"],
            description="Delete a rule file for all agents.")
def delete_rule_file(rule_name: str):
    rule_file_path = f'/etc/modsecurity/custom_rule_all/{rule_name}.conf'
    try:
        os.remove(rule_file_path)
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"Rule file {rule_name}.conf deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete ModSecurity rule file: {e}")

@app.get("/get_rule_file_content", tags=["rules"],
            description="The API retrieves the content of a rule file for all agents.")
def get_rule_file_content(rule_name: str):
    rule_file_path = f'/etc/modsecurity/custom_rule_all/{rule_name}.conf'
    try:
        with open(rule_file_path, 'r') as file:
            content = file.read()
            return Response(content=content, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read ModSecurity rule file: {e}")
    
class RuleAllModel(BaseModel):
    name: str
    rules: str
@app.post("/update_rule_file_content", tags=["rules"],
          description="Update the content of a rule file for all agents.")
async def update_rule_custom(ruleModel: RuleAllModel):
    rule_file_path = f'/etc/modsecurity/custom_rule_all/{ruleModel.name}.conf'
    rules = ruleModel.rules
    try:
        with open(rule_file_path, 'w') as f:
            f.write(rules)
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"Rule file {ruleModel.name}.conf updated and Apache reloaded successfully."}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload Apache: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ModSecurity rule file: {e}")

@app.get("/get_blacklist", tags=["rules"],
         description="Get the list of IP addresses in the blacklist.")
def get_blacklist():
    blacklist_path = '/etc/modsecurity/custom_rule_all/blacklist.txt'
    try:
        with open(blacklist_path, 'r') as file:
            blacklist = file.readlines()
        # Trả về danh sách dưới dạng JSON
        return {"blacklist": [ip.strip() for ip in blacklist]}
    except Exception as e:
        return {"error": str(e)}

@app.post("/add_ip_to_blacklist", tags=["rules"],
          description="Add an IP address to the blacklist.")
def add_IP_into_blacklist(ip_address: str):
    blacklist_path = '/etc/modsecurity/custom_rule_all/blacklist.txt'
    try:
        with open(blacklist_path, 'a') as file:
            file.write(f"{ip_address}\n")
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"IP address {ip_address} added to the blacklist successfully."}
    except Exception as e:
        return {"error": str(e)}
    
@app.delete("/delete_ip_from_blacklist", tags=["rules"],
            description="Delete IP address from blacklist")
def delete_ip_from_blacklist(ip_address: str):
    blacklist_path = '/etc/modsecurity/custom_rule_all/blacklist.txt'
    try:
        with open(blacklist_path, 'r') as file:
            lines = file.readlines()
        with open(blacklist_path, 'w') as file:
            for line in lines:
                if line.strip() != ip_address:
                    file.write(line)
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"IP address {ip_address} deleted from the blacklist successfully."}
    except Exception as e:
        return {"error": str(e)}
    
@app.get("/update_crs", tags=["rules"])
async def update_crs():
    try:
        crs_directory = "/usr/share/modsecurity-crs/CRS"
        if os.path.exists(crs_directory):
            subprocess.check_call(['sudo', 'rm', '-rf', crs_directory])
        subprocess.check_call(['sudo', 'git', 'clone', 'https://github.com/coreruleset/coreruleset.git', crs_directory])
        
        # Đổi tên file cấu hình mẫu
        example_conf = os.path.join(crs_directory, 'crs-setup.conf.example')
        conf = os.path.join(crs_directory, 'crs-setup.conf')
        if os.path.exists(example_conf):
            subprocess.check_call(['sudo', 'mv', example_conf, conf])
        result = subprocess.check_output(
            ['sudo', 'apache2ctl', 'configtest'],
            stderr=subprocess.STDOUT  # Redirect stderr to stdout
        )
        decoded_result = result.decode('utf-8') if isinstance(result, bytes) else result
        print(decoded_result)
        print("decoded")
        print(result)
        if 'Syntax OK' in decoded_result:
            print("Apache config syntax is OK.")
        else:
            print("failed")
            raise Exception('Apache config syntax has errors.')
        subprocess.check_call(['sudo', 'systemctl', 'reload', 'apache2'])
        
        return {"status": "success", "message": "CRS updated and applied successfully."}
    except Exception as e:
        # Trả về thông báo lỗi nếu có
        raise HTTPException(status_code=500, detail=str(e))
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
                "SecRuleEngine": agent.SecRuleEngine,
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

@app.get("/getagent/{host_id}", tags=["agents"])
def get_agent_by_id(host_id: int):
    db = SessionLocal()
    try:
        agent = db.query(ModsecHost).filter(ModsecHost.id == host_id).first()
        if agent is None:
            raise HTTPException(status_code=404, detail="Host not found")
        elif agent.Protocol=="https":
            return {
                "id": agent.id,
                "Port": agent.Port,
                "ServerName": agent.ServerName,
                "ProxyPreserveHost": agent.ProxyPreserveHost,
                "ProxyPass": agent.ProxyPass,
                "ProxyPassReverse": agent.ProxyPassReverse,
                "ErrorLog": agent.ErrorLog,
                "ErrorDocument": agent.ErrorDocument,
                "Protocol": agent.Protocol,
                "SecRuleEngine": agent.SecRuleEngine,
                "SSLCertificateFile": agent.SSLCertificateFile,
                "SSLCertificateKeyFile": agent.SSLCertificateKeyFile,
                "SSLEngine": agent.SSLEngine,
                "SSLProxyEngine": agent.SSLProxyEngine
            }
        else:
            return {
                "id": agent.id,
                "Port": agent.Port,
                "ServerName": agent.ServerName,
                "ProxyPreserveHost": agent.ProxyPreserveHost,
                "ProxyPass": agent.ProxyPass,
                "ProxyPassReverse": agent.ProxyPassReverse,
                "ErrorLog": agent.ErrorLog,
                "ErrorDocument": agent.ErrorDocument,
                "Protocol": agent.Protocol,
                "SecRuleEngine": agent.SecRuleEngine
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()
@app.post("/addagent", tags=["agents"])
def add_agent(agent: HostAdd):
    config_file_path = f'/etc/apache2/sites-available/{agent.ServerName}_{agent.Port}.conf'
    config_file_apache = '/etc/apache2/apache2.conf'
    rule_path = f'/etc/modsecurity/custom_rules/{agent.ServerName}_{agent.Port}_rules.conf'
    error_path = f'/var/log/apache2/{agent.ServerName}_{agent.Port}_error.log'    
    def check_port_in_apache_conf(port, file_content):
        listen_line = f"Listen {port}"
        return any(line.strip() == listen_line for line in file_content)
    db = SessionLocal()
    def check_vhost_exists(port, servername):
    # Kiểm tra xem có bản ghi nào có port hoặc servername như đã cho hay không
        existing_host = db.query(ModsecHost).filter(and_(ModsecHost.Port == port, ModsecHost.ServerName == servername)).first()
        if existing_host:
            print("Host đã tồn tại")
            return True  # Bản ghi đã tồn tại
        else:
            print("Host chưa tồn tại")
            return False  # Bản ghi không tồn tại 

    try:
        with open(config_file_apache, 'r') as file:
            apache_content = file.readlines()
        if not check_vhost_exists(agent.Port, agent.ServerName):
            if agent.Port not in [443, 80]:
                if not check_port_in_apache_conf(agent.Port, apache_content):
                    with open(config_file_apache, 'a') as file:
                        file.write(f"Listen {agent.Port}\n")
                    subprocess.run(['sudo', 'service', 'apache2', 'reload'], check=True)
        else:
            raise HTTPException(status_code=400, detail="VirtualHost with this port and ServerName already exists.")
        with open(config_file_path, 'a') as file:
            pass                
        new_vhost = add_new_vhost_entry(agent.Port, agent.ServerName, agent.ProxyPreserveHost, f'/ {agent.ProxyPass}', f'/ {agent.ProxyPassReverse}', error_path, f'403 {agent.ErrorDocument}', agent.Protocol)
        with open(config_file_path, 'a') as file:
            file.write(new_vhost)
        symlink_command = [
        'sudo', 'ln', '-s', 
        f'/etc/apache2/sites-available/{agent.ServerName}_{agent.Port}.conf', 
        f'/etc/apache2/sites-enabled/{agent.ServerName}_{agent.Port}.conf'
        ]
        try:
            subprocess.run(symlink_command, check=True)
        except subprocess.CalledProcessError as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Failed to create symbolic link: {e}")
    #create rule_path use os
        if not os.path.exists(rule_path):
            with open(rule_path, 'w') as file:
                pass
    #create error_path
        if not os.path.exists(error_path):
            with open(error_path, 'w') as file:
                pass
        restart_apache()                
        new_host = ModsecHost(
            Port=agent.Port,
            ServerName=agent.ServerName,
            ProxyPreserveHost=agent.ProxyPreserveHost,
            ProxyPass=agent.ProxyPass, 
            ProxyPassReverse=agent.ProxyPassReverse,
            ErrorLog= error_path,
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
    config_file_path = f'/etc/apache2/sites-available/{db_host.ServerName}_{db_host.Port}.conf'
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
                elif line.strip().startswith("ErrorDocument") and host_update.ErrorDocument:
                    vhost_content[i] = f"    ErrorDocument 403 {host_update.ErrorDocument}\n"
            elif vhost_started and "</VirtualHost>" in line.strip():
                vhost_started = False
        with open(config_file_path, 'w') as file:
            file.writelines(vhost_content)
    restart_apache()

    return {"message": "Host configuration updated successfully."}

@app.delete("/deleteagent/{host_id}", tags=["agents"])
def delete_agent(host_id: int):
    db = SessionLocal()
    def check_port_in_apache_conf(port, file_content):
        # Find out if there are any other hosts with the same port as host_id        
        listen_line = f"Listen {port}"
        return any(line.strip() == listen_line for line in file_content)
    def check_other_hosts_with_same_port(port, host_id):
        # Kiểm tra xem có host nào khác sử dụng cùng port không
        other_hosts = db.query(ModsecHost).filter(
            and_(ModsecHost.Port == port, ModsecHost.id != host_id)
        ).all()
        return len(other_hosts) > 0
    try:
        # Fetch the host from the database
        try:
        # Fetch the host from the database
            db_host = db.query(ModsecHost).filter(ModsecHost.id == host_id).first()
            if db_host is None:
                raise HTTPException(status_code=404, detail="Host not found")

        # Delete the host from the database
            db.delete(db_host)
            db.commit()

        except SQLAlchemyError as db_error:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Database error: {db_error}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        # Close port
        config_file_path = Path(f'/etc/apache2/sites-available/{db_host.ServerName}_{db_host.Port}.conf')
        config_file_apache = '/etc/apache2/apache2.conf'
        rule_path = f'/etc/modsecurity/custom_rules/{db_host.ServerName}_{db_host.Port}_rules.conf'
        with open(config_file_apache, 'r') as file:
            apache_content = file.readlines()
        if not check_other_hosts_with_same_port(db_host.Port, db_host.id):
            if check_port_in_apache_conf(db_host.Port, apache_content):
                with open(config_file_apache, 'w') as file:
                    for line in apache_content:
                        if line.strip() != f"Listen {db_host.Port}":
                            file.write(line)
                subprocess.run(['sudo', 'service', 'apache2', 'reload'], check=True)
        # Remove the symbolic link
        symbolic_link = Path(f'/etc/apache2/sites-enabled/{db_host.ServerName}_{db_host.Port}.conf')
        if symbolic_link.exists():
            try:
                symbolic_link.unlink()
                if symbolic_link.exists():
                    subprocess.run(['sudo', 'rm', symbolic_link], check=True)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to remove symbolic link: {e}")
        # Delete the Apache configuration file
        if config_file_path.exists():            
            try:
                subprocess.run(['sudo', 'rm', config_file_path], check=True)
            except subprocess.CalledProcessError as e:
                raise HTTPException(status_code=500, detail=f"Failed to delete Apache configuration file: {e}")
        else:
            pass        
        restart_apache()
        #Delete rule path if exits
        if os.path.exists(rule_path):
            os.remove(rule_path)
         # Delete all log files that start with the server name
        log_files_pattern = f'/var/log/apache2/{db_host.ServerName}_{db_host.Port}_error.log*'
        log_files = glob.glob(log_files_pattern)
        for log_file in log_files:
            os.remove(log_file)

        return {"message": "Host deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

#config
@app.get("/get_config_modsecurity", tags=["config"])
async def get_config_modsecurity():
    config_modsecurity_path = "/etc/modsecurity/modsecurity.conf"
    try:
        with open(config_modsecurity_path, 'r') as file:
            config_lines = file.readlines()

        # Define the directives of interest
        directives_of_interest = {
            'SecRuleEngine': '',
            'SecDebugLogLevel': '',
            'SecAuditEngine': '',
            'SecAuditLogRelevantStatus': '',
            'SecAuditLogParts': '',
            'SecAuditLogType': '',
            'SecStatusEngine': ''
        }

        # Prepare a regex pattern to match the directives
        pattern = re.compile(r'(' + '|'.join(directives_of_interest.keys()) + r')\s+(.*)')

        # Parse the file lines for the directives
        for line in config_lines:
            match = pattern.match(line.strip())
            if match:
                key, value = match.groups()
                directives_of_interest[key] = value.strip()

        # Return the directives in the desired format
        return directives_of_interest

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Configuration file not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class ModSecurityConfig(BaseModel):
    SecRuleEngine: Optional[str] = Field(default="")
    SecDebugLogLevel: Optional[str] = Field(default="")
    SecAuditEngine:Optional[str] = Field(default="")
    SecAuditLogRelevantStatus: Optional[str] = Field(default="")
    SecAuditLogParts: Optional[str] = Field(default="")
    SecAuditLogType: Optional[str] = Field(default="")
    SecStatusEngine: Optional[str] = Field(default="")


@app.post("/update_config_modsecurity", tags=["config"])
async def update_config_modsecurity(config: ModSecurityConfig):
    config_modsecurity_path = "/etc/modsecurity/modsecurity.conf"
    try:
        # Read the original configuration file
        with open(config_modsecurity_path, 'r') as file:
            config_lines = file.readlines()

        # Create a dictionary from the Pydantic model for easier processing
        config_dict = config.dict(exclude_unset=True)

        # Update the configuration lines with the new values
        updated_config_lines = []
        for line in config_lines:
            # Check if the line contains a configuration directive we want to update
            match = re.match(r'(Sec[A-Za-z]+)\s+(.+)', line.strip())
            if match and match.group(1) in config_dict:
                # Replace the old value with the new one
                directive = match.group(1)
                new_value = config_dict[directive]
                if new_value:
                    updated_config_lines.append(f"{directive} {new_value}\n")
                else:
                    updated_config_lines.append(line)
            else:
                # Keep the original line
                updated_config_lines.append(line)

        # Write the updated configuration back to the file
        with open(config_modsecurity_path, 'w') as file:
            file.writelines(updated_config_lines)

        return {"message": "Configuration updated successfully."}

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Configuration file not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/update_mode_agent", tags=["config"])
def update_mode_agent(ServerName: str, Port: int, mode: str):
    db = SessionLocal()
    config_file_path = f'/etc/apache2/sites-available/{ServerName}_{Port}.conf'
    if mode not in ['On', 'Off', 'DetectionOnly']:
        raise HTTPException(status_code=400, detail="Invalid mode. Allowed values are On, Off, DetectionOnly.")
    try:
        with open(config_file_path, 'r') as file:
            config_content = file.readlines()
        for i, line in enumerate(config_content):
            if 'SecRuleEngine' in line:
                config_content[i] = re.sub(r'SecRuleEngine\s+\w+', f'SecRuleEngine {mode}', line)
                break
        with open(config_file_path, 'w') as file:
            file.writelines(config_content)
        try:
            subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error restarting Apache: {e}")
        modsec_host = db.query(ModsecHost).filter(
            and_(ModsecHost.ServerName == ServerName, ModsecHost.Port == Port)
        ).first()
        if modsec_host is not None:
            modsec_host.SecRuleEngine = mode  
            db.commit()
        return {"message": "ModSecurity configuration updated successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ModSecurity configuration: {str(e)}")     

@app.get("/get_mode_AI_CNN", tags=["config"],
             description="This endpoint returns the mode of the AI CNN configuration by checking the 'security2.conf' file. If the 'IncludeOptional /etc/modsecurity/ruleAI/CNN.conf' line is commented out, the mode is 'Off'. Otherwise, the mode is 'On'.",
)
def get_mode_AI_CNN():
    security_conf_path = "/etc/apache2/mods-enabled/security2.conf"
    try:
        with open(security_conf_path, 'r') as file:
            lines = file.readlines()
    except IOError:
        raise HTTPException(status_code=500, detail="Could not read security2.conf file")
    for line in lines:
        if 'IncludeOptional /etc/modsecurity/ruleAI/CNN.conf' in line:
            line=line.strip()
            if line.startswith('#'):
                return {"mode": "Off"}
            else:
                return {"mode": "On"}
    return {"mode": "Off"}

@app.post("/update_mode_AI_CNN", tags=["config"])
def update_mode_AI_CNN(mode: str):
    security_conf_path = "/etc/apache2/mods-enabled/security2.conf"
    if mode not in ['On', 'Off']:
        raise HTTPException(status_code=400, detail="Invalid mode value")
    try:
        with open(security_conf_path, 'r') as file:
            lines = file.readlines()
    except IOError:
        raise HTTPException(status_code=500, detail="Could not read security2.conf file")
    new_lines = []
    for line in lines:
        if 'IncludeOptional /etc/modsecurity/ruleAI/CNN.conf' in line:
            if mode == 'On':
                # xóa kí tự # trước 'IncludeOptional /etc/modsecurity/rules/*.conf'
                new_line = line.replace('#IncludeOptional', 'IncludeOptional') if '#IncludeOptional' in line else line
                print(new_line)
            elif mode == 'Off':
                new_line = line.replace('IncludeOptional', '#IncludeOptional') if '#IncludeOptional' not in line else line
            new_lines.append(new_line)
        else:
            new_lines.append(line)
    try:
        with open(security_conf_path, 'w') as file:
            file.writelines(new_lines)
    except IOError:
        raise HTTPException(status_code=500, detail="Could not write to security2.conf file")
    try:
        subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error restarting Apache: {e}")

    return {"detail": "Security2 configuration updated and Apache reloaded successfully"}

@app.get("/get_mode_AI_vtr", tags=["config"])
def get_mode_AI_vtr():
    security_conf_path = "/etc/apache2/mods-enabled/security2.conf"
    try:
        with open(security_conf_path, 'r') as file:
            lines = file.readlines()
    except IOError:
        raise HTTPException(status_code=500, detail="Could not read security2.conf file")
    for line in lines:
        if 'IncludeOptional /etc/modsecurity/ruleAI/vtr_tfidf.conf' in line:
            line=line.strip()
            if line.startswith('#'):
                return {"mode": "Off"}
            else:
                return {"mode": "On"}
    return {"mode": "Off"}

@app.post("/update_mode_AI_vtr", tags=["config"])
def update_mode_AI_vtr(mode: str):
    security_conf_path = "/etc/apache2/mods-enabled/security2.conf"
    if mode not in ['On', 'Off']:
        raise HTTPException(status_code=400, detail="Invalid mode value")
    try:
        with open(security_conf_path, 'r') as file:
            lines = file.readlines()
    except IOError:
        raise HTTPException(status_code=500, detail="Could not read security2.conf file")
    new_lines = []
    for line in lines:
        if 'IncludeOptional /etc/modsecurity/ruleAI/vtr_tfidf.conf' in line:
            if mode == 'On':
                # xóa kí tự # trước 'IncludeOptional /etc/modsecurity/rules/*.conf'
                new_line = line.replace('#IncludeOptional', 'IncludeOptional') if '#IncludeOptional' in line else line
                print(new_line)
            elif mode == 'Off':
                new_line = line.replace('IncludeOptional', '#IncludeOptional') if '#IncludeOptional' not in line else line
            new_lines.append(new_line)
        else:
            new_lines.append(line)
    try:
        with open(security_conf_path, 'w') as file:
            file.writelines(new_lines)
    except IOError:
        raise HTTPException(status_code=500, detail="Could not write to security2.conf file")
    try:
        subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error restarting Apache: {e}")

    return {"detail": "Security2 configuration updated and Apache reloaded successfully"}

# performance
@app.get("/get_performance", tags=["performance"])
def get_system_info():
    # Lấy thông tin CPU
    cpu_usage = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()
    
    # Lấy thông tin RAM
    virtual_mem = psutil.virtual_memory()
    ram_total = virtual_mem.total
    ram_used = virtual_mem.used
    ram_free = virtual_mem.free
    ram_percent = virtual_mem.percent
    
    # Lấy thông tin lưu trữ
    disk_usage = psutil.disk_usage('/')
    storage_total = disk_usage.total
    storage_used = disk_usage.used
    storage_free = disk_usage.free
    storage_percent = disk_usage.percent
    
    # Trả về thông tin dưới dạng JSON
    return {
        "cpu": {
            "usage_percent": cpu_usage,
            "core": cpu_count,
        },
        "ram": {
            "total": ram_total,
            "used": ram_used,
            "free": ram_free,
            "percent": ram_percent,
        },
        "storage": {
            "total": storage_total,
            "used": storage_used,
            "free": storage_free,
            "percent": storage_percent,
        }
    }
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5555, reload=True)

