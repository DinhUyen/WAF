
import subprocess
import re
from sqlalchemy import and_
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException
from database import get_db
from models.item import ModsecHost, ModSecurityConfig


router = APIRouter(
    prefix="/config",
    tags=["config"],
    responses={404: {"description": "Not found"}}
) 
@router.get("/get_config_modsecurity")
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

@router.post("/update_config_modsecurity")
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

@router.post("/update_mode_agent")
def update_mode_agent(ServerName: str, Port: int, mode: str,  db: Session = Depends(get_db)):
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

@router.get("/get_mode_AI_CNN",
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

@router.post("/update_mode_AI_CNN")
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

@router.get("/get_mode_AI_vtr")
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

@router.post("/update_mode_AI_vtr")
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