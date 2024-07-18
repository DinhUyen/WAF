from typing import Optional
from fastapi import APIRouter
from fastapi import Request,HTTPException, Depends
from fastapi import HTTPException
from datetime import datetime
import pandas as pd
from io import BytesIO
from fastapi.responses import StreamingResponse
from sqlalchemy import String
from datetime import datetime, timedelta  # Thêm timedelta vào import
from sqlalchemy import func, distinct
from sqlalchemy import or_
from sqlalchemy.sql import func
from collections import Counter
from fastapi import Query
from geoip2.database import Reader
from geoip2.errors import AddressNotFoundError
from models.item import ModsecHost, ModsecLog1, Request
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException
from database import get_db


router = APIRouter(
    prefix="/log",
    tags=["log"],
    responses={404: {"description": "Not found"}}
)
@router.get("/getlog")
def get_log(number: int = 10, page: int = 1, distinct: int = 0, filters: str = None, db: Session = Depends(get_db)):
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

@router.get("/count_request",
         description="This API fetches the number of requests within a specified time frame.")
def count_request(time:int,  db: Session = Depends(get_db)):
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
@router.get("/count_request_by_servername",
         description="This API fetches the number of requests within a specified time frame for a specific agent.")
def count_request(time:int, local_port: str = None, ServerName: str = None,  db: Session = Depends(get_db)):
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

@router.get("/get_log_xlsx",
         description="This API fetches logs and returns them as an Excel file.")
def get_log_xlsx( db: Session = Depends(get_db)):
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

@router.get("/getLogWithinTime",
         description="This API fetches logs within a specified time frame.")
def get_log_within_time(time: int, number: int = 10, page: int = 1,
    src_ip: str = None, local_port: str = None, ServerName: str = None, filters: str = None,  db: Session = Depends(get_db)):
    try:
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


@router.get("/get_log_within_time_xlsx",
         description="This API fetches logs within a specified time frame and returns them as an Excel file.")
def get_log_within_time_xlsx(
    time: int, src_ip: str = None, local_port: str = None, ServerName: str = None, filters: str = None, db: Session = Depends(get_db)):
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
@router.get("/getIPattackerWithinTime",
         description="This API fetches IP addresses of attackers within a specified time frame.")
def get_IP_attacker_within_time(time: int, number: int = 10, page: int = 1, distinct: int = 0, filters: str = None,  db: Session = Depends(get_db)):
    try:
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

@router.get("/count_IP_attacker_within_time_by_ID",
         description="This API fetches the number of distinct IP addresses that have attacked within a specified time frame for a specific agent.")
def count_IP_attacker_within_time_by_ID(id: int, time: int, db: Session = Depends(get_db)):
    try:
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

@router.get("/get_Attacks_Map",
         description="This API fetches the locations of the most recent attacks.")
def get_Attacks_Map(db: Session = Depends(get_db)):
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
@router.get("/getAttackMapIP",
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
@router.get("/getDetectedTimes",
         description="This API fetches the number of times an attack has been detected within a specified time frame.")
def get_detected_times(time:int, db: Session = Depends(get_db)):
    try:
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

@router.get("/getDetectedTimesByID",
         description="This API fetches the number of times an attack has been detected within a specified time frame for a specific agent.")
def get_detected_times_byID(time: int, id: int, db: Session = Depends(get_db)):
    try:
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
@router.get("/get_severity",
         description="This API fetches the severity of attacks for each agent.")
def get_severity(db: Session = Depends(get_db)):
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
        severity_dict = {}
        for host, port, severity, count in results:
            key = (host, port)
            if key not in severity_dict:
                severity_dict[key] = {
                    "host": host,
                    "port": port,
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "ERROR": 0
                }
            if severity.upper() == "CRITICAL":
                severity_dict[key]["CRITICAL"] += count
            elif severity.upper() == "HIGH":
                severity_dict[key]["HIGH"] += count
            elif severity.upper() == "MEDIUM":
                severity_dict[key]["MEDIUM"] += count
            elif severity.upper() == "ERROR":
                severity_dict[key]["ERROR"] += count
        
        list_result = list(severity_dict.values())
        
        return list_result
    except Exception as e:
        print(e)
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        db.close()

@router.get("/graph_count_log_within_24h",
         description="This API is used to count the number of blocked requests per time interval.")
def graph_count_log_within_24h(db: Session = Depends(get_db)):
    # Tạo kết nối database
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

@router.get("/graph_count_log_within_24h_byID",
         description="This API is used to count the number of blocked requests per time interval for a specific agent.")
def graph_count_log_within_24h_byID(id:int, db: Session = Depends(get_db)):
    # Tạo kết nối database
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

@router.get("/grap_TOP10_IP_source_addresses_json",
         description="This API fetches the top 10 source IP addresses.")
def grap_TOP10_IP_source_addresses_json(db: Session = Depends(get_db)):
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

@router.get("/graph-top20-rule-hit",
         description="This API fetches the top 20 rules that have been hit the most.")
def graph_top20_rule_hit(db: Session = Depends(get_db)):
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

@router.get("/graph_TOP10_Attacks_intercepted",
         description="This API fetches the top 10 attacks intercepted.")
def graph_TOP10_Attacks_intercepted(db: Session = Depends(get_db)):
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

@router.get("/graph_Passed_and_Intercepted",
         description="This API fetches the number of requests that have passed and been intercepted.")
def graph_Passed_and_Intercepted(
         db: Session = Depends(get_db),
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