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
import pandas as pd
import re
import os
from io import BytesIO
from fastapi.responses import StreamingResponse
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta  # Thêm timedelta vào import
from sqlalchemy import func
from sqlalchemy import or_
from ruleEngine import update_modsecurity_config
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

SQLITE_DATABASE_URL  = "sqlite:////home/kali/Desktop/WAF/db/modsec.db"
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
        query = db.query(ModsecLog1, ModsecHost.ServerName).join(
            ModsecHost, ModsecHost.Port == ModsecLog1.local_port
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

@app.get("/get_log_xlsx", tags=["logs"])
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

@app.get("/getLogWithinTime", tags=["logs"])
def get_log_within_time(time: int, number: int = 10, page: int = 1,
    src_ip: str = None, dest_ip: str = None, filters: str = None):
    try:
        db = SessionLocal()
        print(f"time: {time}, number: {number}, page: {page}, src_ip: {src_ip}, dest_ip: {dest_ip}, filters: {filters}")
        query = db.query(ModsecLog1, ModsecHost.ServerName).join(
            ModsecHost, ModsecHost.Port == ModsecLog1.local_port
        )
        # Apply time filter
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time)
        query = query.filter(ModsecLog1.event_time >= start_time, ModsecLog1.event_time <= end_time)

        # Apply IP filters if provided
        if src_ip:
            query = query.filter(ModsecLog1.remote_address == src_ip)
        if dest_ip:
            query = query.filter(ModsecLog1.local_address == dest_ip)
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


@app.get("/get_log_within_time_xlsx", tags=["logs"])
def get_log_within_time_xlsx(
    time: int, src_ip: str = None, dest_ip: str = None, filters: str = None):
    db = SessionLocal()
    try:
        query = db.query(ModsecLog1)
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=time)
        query = query.filter(ModsecLog1.event_time >= start_time, ModsecLog1.event_time <= end_time)
        if src_ip:
            query = query.filter(ModsecLog1.remote_address == src_ip)
        if dest_ip:
            query = query.filter(ModsecLog1.local_address == dest_ip)
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
@app.get("/getIPattackerWithinTime", tags=["logs"])
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

@app.get("/get_Attacks_Map", tags=["logs"])
def get_Attacks_Map():
    db = SessionLocal()
    geoip_reader = Reader('/home/kali/Desktop/WAF/db/GeoLite2-City.mmdb')    
    try:
        recent_attacks = db.query(ModsecLog1.remote_address).distinct().limit(10).all()
        print("recent_attacks: ", recent_attacks)
        attacks_info = []
        for attack in recent_attacks:
            ip = attack.remote_address
            try:
                response = geoip_reader.city(ip)
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

        query = db.query(func.count(ModsecLog1.id)).\
            filter(ModsecLog1.event_time >= datetime.now() - timedelta(hours=time))
        result = query.scalar()

        return {"detected_times": result}

    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

#Graph
@app.get("/graph_count_log_within_24h", tags=["logs"])
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

            count = db.query(func.count(ModsecLog1.id)).filter(
                ModsecLog1.event_time >= period_start,
                ModsecLog1.event_time < period_end
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
@app.get("/grap_TOP10_IP_source_addresses_png", tags=["logs"])
def grap_TOP10_IP_source_addresses_png():
    db = SessionLocal()
    try:
        # query = db.query(ModsecLog.remote_address, func.count(ModsecLog.id)).group_by(ModsecLog.remote_address).order_by(func.count(ModsecLog.id).desc()).limit(10)
        # result = query.all()
        # list_result = []
        # for ip, count in result:
        #     list_result.append({
        #         "ip": ip,
        #         "count": count
        #     })
        # return list_result
        src_ip_data = db.query(ModsecLog1.remote_address).all()
    
    # Count occurrences of each IP
        src_ip_counter = Counter([data.remote_address for data in src_ip_data])
        top10_ips = src_ip_counter.most_common(10)

    # Plot the graph
        fig, ax = plt.subplots()
        ips, counts = zip(*top10_ips)
        ax.bar(ips, counts)
        ax.set_title("TOP 10 IP Source Addresses")
        ax.set_ylabel("Count")
        ax.set_xticklabels(ips, rotation=45, ha="right")

    # Save the graph to a temporary file
        temp_file = NamedTemporaryFile(delete=False, suffix='.png')
        plt.savefig(temp_file.name)
        plt.close(fig)
    
    # Return the graph as a file response
        return FileResponse(path=temp_file.name, filename="top10_ip_source_addresses.png", media_type='image/png')
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()
@app.get("/grap_TOP10_IP_source_addresses_json", tags=["logs"])
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

@app.get("/graph-top20-rule-hit", tags=["logs"])
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

@app.get("/graph_TOP10_Attacks_intercepted", tags=["logs"])
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

@app.get("/graph_Passed_and_Intercepted", tags=["logs"])
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
@app.get("/get_config", tags=["rules"])
def get_config_modsecurity():
    config_modsecurity_path = "/etc/modsecurity/modsecurity.conf"
    try:
        with open(config_modsecurity_path, 'r') as file:
            content = file.read()
            # Trả về nội dung dưới dạng Response với media_type là text/plain
            return Response(content=content, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read ModSecurity rule file: {e}")      

class Config(BaseModel):
    config_content: str
@app.post("/update_config", tags=["rules"])
async def update_config_modsecurity(config_content: Config):

    config_modsecurity_path = "/etc/modsecurity/modsecurity.conf"
    content = config_content.config_content
    try:
        # Mở file với mode 'w' và ghi nội dung rule_content vào đó
        with open(config_modsecurity_path, 'w') as f:   
            f.write(content)
        # Sử dụng subprocess để reload Apache
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": "Config Modsecurity updated and Apache reloaded successfully."}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload Apache: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ModSecurity config file: {e}")

@app.post("/update_mode_agent", tags=["rules"])
def update_mode_agent(ServerName: str, mode: str):
    db = SessionLocal()
    config_file_path = f'/etc/apache2/sites-available/{ServerName}.conf'
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
        modsec_host = db.query(ModsecHost).filter(ModsecHost.ServerName == ServerName).first()
        if modsec_host is not None:
            modsec_host.SecRuleEngine = mode  
            db.commit()
        return {"message": "ModSecurity configuration updated successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ModSecurity configuration: {str(e)}")        

@app.post("/update_mode_AI", tags=["rules"])
def update_mode_AI(mode: str):
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
        if 'IncludeOptional /etc/modsecurity/rules/*.conf' in line:
            if mode == 'On':
                new_line = line.lstrip('#').replace('\n', '') + '\n'
            elif mode == 'Off':
                new_line = f'#{line}' if not line.startswith('#') else line
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

@app.get("/get_rule", tags=["rules"])
def get_rule_custom(ServerName: str):
    rule_file_path = f'/etc/modsecurity/custom_rules/{ServerName}_rules.conf'
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
    rules: str
@app.post("/updaterule", tags=["rules"])
async def update_rule_custom(ruleModel: RuleModel):

    rule_file_path = f'/etc/modsecurity/custom_rules/{ruleModel.ServerName}_rules.conf'
    rules = ruleModel.rules
    
    try:
        # Mở file với mode 'w' và ghi nội dung rule_content vào đó
        with open(rule_file_path, 'w') as f:   
            f.write(rules)
        # Sử dụng subprocess để reload Apache
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"Rule for {ruleModel.ServerName} updated and Apache reloaded successfully."}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload Apache: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update ModSecurity rule file: {e}")

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
    config_file_path = f'/etc/apache2/sites-available/{agent.ServerName}.conf'
    config_file_apache = '/etc/apache2/apache2.conf'
    rule_path = f'/etc/modsecurity/custom_rules/{agent.ServerName}_rules.conf'
    error_path = f'/var/log/apache2/{agent.ServerName}_error.log'
    #create rule_path use os
    if not os.path.exists(rule_path):
        with open(rule_path, 'w') as file:
            pass
    #create error_path
    if not os.path.exists(error_path):
        with open(error_path, 'w') as file:
            pass
    
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
        
        new_vhost = add_new_vhost_entry(agent.Port, agent.ServerName, agent.ProxyPreserveHost, f'/ {agent.ProxyPass}/', f'/ {agent.ProxyPassReverse}/', error_path, f'403 {agent.ErrorDocument}', agent.Protocol)
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
        config_file_path = Path(f'/etc/apache2/sites-available/{db_host.ServerName}.conf')
        config_file_apache = '/etc/apache2/apache2.conf'
        rule_path = f'/etc/modsecurity/custom_rules/{db_host.ServerName}_rules.conf'
        error_path = f'/var/log/apache2/{db_host.ServerName}_error.log'
        with open(config_file_apache, 'r') as file:
            apache_content = file.readlines()
        if check_port_in_apache_conf(db_host.Port, apache_content):
            with open(config_file_apache, 'w') as file:
                for line in apache_content:
                    if line.strip() != f"Listen {db_host.Port}":
                        file.write(line)                        
            subprocess.run(['sudo', 'service', 'apache2', 'reload'], check=True)

        # Delete the Apache configuration file
        if config_file_path.exists():            
            try:
                subprocess.run(['sudo', 'rm', config_file_path], check=True)
            except subprocess.CalledProcessError as e:
                raise HTTPException(status_code=500, detail=f"Failed to delete Apache configuration file: {e}")
        else:
            pass

        # Remove the symbolic link
        symbolic_link = Path(f'/etc/apache2/sites-enabled/{db_host.ServerName}.conf')
        if symbolic_link.exists():
            try:
                symbolic_link.unlink()
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to remove file: {e}")
        else:
            pass
        restart_apache()
        #Delete rule path if exits
        if os.path.exists(rule_path):
            os.remove(rule_path)
        #Delete error path if exits
        if os.path.exists(error_path):
            os.remove(error_path)

        return {"message": "Host deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5555, reload=True)