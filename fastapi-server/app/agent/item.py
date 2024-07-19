from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from fastapi import HTTPException
import subprocess
import os
import glob
from sqlalchemy import and_
from sqlalchemy import or_
from fastapi import Depends
from sqlalchemy.orm import Session
from ruleEngine import restart_apache
from ruleEngine import add_new_vhost_entry
from pathlib import Path
from sqlalchemy.exc import SQLAlchemyError
from models.item import  ModsecHost, HostAdd, HostUpdate
from database import get_db

router = APIRouter(
    prefix="/agent",
    tags=["agent"],
    responses={404: {"description": "Not found"}}
)

@router.get("/getagent")
def get_agent(number: int = 10, page: int = 1, distinct: int = 0, filters: Optional[str] = None, db: Session = Depends(get_db)):
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

@router.get("/getagent/{host_id}")
def get_agent_by_id(host_id: int, db: Session = Depends(get_db)):
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
@router.post("/addagent")
def add_agent(agent: HostAdd, db: Session = Depends(get_db)):
    config_file_path = f'/etc/apache2/sites-available/{agent.ServerName}_{agent.Port}.conf'
    config_file_apache = '/etc/apache2/apache2.conf'
    rule_path = f'/etc/modsecurity/custom_rules/{agent.ServerName}_{agent.Port}_rules.conf'
    error_path = f'/var/log/apache2/{agent.ServerName}_{agent.Port}_error.log'    
    def check_port_in_apache_conf(port, file_content):
        listen_line = f"Listen {port}"
        return any(line.strip() == listen_line for line in file_content)
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
@router.put("/updateagent/{host_id}")
def update_agent(host_id: int, host_update: HostUpdate, db: Session = Depends(get_db)):
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

@router.delete("/deleteagent/{host_id}")
def delete_agent(host_id: int, db: Session = Depends(get_db)):
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