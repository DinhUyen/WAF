from fastapi import HTTPException
from pydantic import BaseModel, Field
from fastapi import APIRouter
from datetime import datetime
import subprocess
import os
from datetime import datetime
from sqlalchemy.orm import Session
from starlette.responses import Response
from typing import List, Dict, Any
from models.item import  RuleModel, RuleAllModel, Rule_Remove
from fastapi import APIRouter, Depends, HTTPException, Query
from database import get_db

router = APIRouter(
    prefix="/rule",
    tags=["rule"],
    responses={404: {"description": "Not found"}}
)

@router.get("/get_rule_each_agent", 
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

@router.post("/update_rule_each_agent", 
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
@router.get("/get_rule_file", 
         description="The API retrieves the created rule files for all.")
def get_rule_file(page: int = Query(1),
                  page_size: int = Query(10)) -> Dict[str, Any]:
    try:
        if page < 1:
            raise HTTPException(status_code=400, detail="Page number must be 1 or greater")
        if page_size < 1:
            raise HTTPException(status_code=400, detail="Page size must be 1 or greater")
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
        total_records = len(rule_files)
        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        if start_index >= total_records:
            raise HTTPException(status_code=404, detail="Page number out of range")
        paginated_rule_files = rule_files[start_index:end_index]
        total_pages = (total_records + page_size - 1) // page_size
        response = {
            "total": total_records,
            "data": paginated_rule_files,
            "limit": page_size,
            "page": page,
            "total_pages": total_pages
        }
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read ModSecurity rule files: {e}")

class RuleAllModel(BaseModel):
    name: str
    rules: str    
@router.post("/create_rule_file", description="Create and update a rule file for all agents.")
async def create_rule_file(rule: RuleAllModel):
    rule_file_path = f'/etc/modsecurity/custom_rule_all/{rule.name}.conf'
    try:
        with open(rule_file_path, 'w') as f:
            f.write("# Rule file for all agents\n")
            f.write(rule.rules)
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"Rule file {rule.name}.conf created and updated successfully."}
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Failed to reload Apache: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create or update ModSecurity rule file: {e}")
    
@router.delete("/delete_rule_file", 
            description="Delete a rule file for all agents.")
def delete_rule_file(rule_name: str):
    rule_file_path = f'/etc/modsecurity/custom_rule_all/{rule_name}.conf'
    try:
        os.remove(rule_file_path)
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"Rule file {rule_name}.conf deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete ModSecurity rule file: {e}")

@router.get("/get_rule_file_content", 
            description="The API retrieves the content of a rule file for all agents.")
def get_rule_file_content(rule_name: str):
    rule_file_path = f'/etc/modsecurity/custom_rule_all/{rule_name}.conf'
    try:
        with open(rule_file_path, 'r') as file:
            content = file.read()
            return Response(content=content, media_type="text/plain")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read ModSecurity rule file: {e}")
    

@router.post("/update_rule_file_content", 
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
@router.get("/get_blacklist", description="Get the list of IP addresses in the blacklist.")
def get_blacklist(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100)) -> Dict[str, Any]:
    blacklist_path = '/etc/modsecurity/custom_rule_conf/blacklist.txt'
    try:
        with open(blacklist_path, 'r') as file:
            blacklist = [ip.strip() for ip in file.readlines()]
        
        total_items = len(blacklist)
        start = (page - 1) * page_size
        end = start + page_size
        
        if start >= total_items:
            raise HTTPException(status_code=404, detail="Page not found")
        
        paginated_blacklist = blacklist[start:end]
        
        response = {
            "total": total_items,
            "data": paginated_blacklist,
            "limit": page_size,
            "page": page,
            "total_pages": (total_items + page_size - 1) // page_size
        }
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read blacklist file: {e}")

@router.post("/add_ip_to_blacklist", 
          description="Add an IP address to the blacklist.")
def add_IP_into_blacklist(ip_address: str):
    blacklist_path = '/etc/modsecurity/custom_rule_conf/blacklist.txt'
    try:
        with open(blacklist_path, 'a') as file:
            file.write(f"{ip_address}\n")
        subprocess.run(["sudo", "systemctl", "reload", "apache2"], check=True)
        return {"message": f"IP address {ip_address} added to the blacklist successfully."}
    except Exception as e:
        return {"error": str(e)}
    
@router.delete("/delete_ip_from_blacklist", 
            description="Delete IP address from blacklist")
def delete_ip_from_blacklist(ip_address: str):
    blacklist_path = '/etc/modsecurity/custom_rule_conf/blacklist.txt'
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
    
@router.get("/get_content_rule",
            description="This API get the content of the rule from CRS")
def get_content_rule(rule_file: str, id_rule: str):
    rule_file_path = f'/usr/share/modsecurity-crs/rules/{rule_file}'
    try:
        with open(rule_file_path, 'r') as file:
            lines = file.readlines()
        
        rule_found = False
        rule_content = []
        rule_start_line = -1
        rule_end_line = -1
        
        for line in lines:
            if rule_found:
                if line.startswith('SecRule') and rule_content:
                    rule_end_line = lines.index(line)-1
                    break
                rule_content.append(line.strip())
            elif id_rule in line:
                rule_found = True
                rule_start_line = lines.index(line)
                for i in range(5):
                    if lines[rule_start_line - i].startswith('SecRule'):
                        rule_start_line -= i
                        break
        if not rule_found:
            raise HTTPException(status_code=404, detail=f"Rule with id {id_rule} not found.")
        if rule_start_line != -1 and rule_end_line == -1:
            rule_end_line = len(lines)-1
        rule_content = lines[rule_start_line:rule_end_line]
        if not rule_content:
            raise HTTPException(status_code=404, detail=f"Rule with id {id_rule} not found.")        
        return rule_content    
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Rule file {rule_file} not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read rule file {rule_file}: {e}")
@router.get("/get_deleted_ID_Rule",
            description="This API gets deleted rule applies")
def get_deleted_ID_Rule(ServerName: str = None, port: int = None,
                        db: Session = Depends(get_db),
                        page: int = Query(1),
                        page_size: int = Query(10)) -> Dict[str, Any]:
    try:
        if page < 1:
            raise HTTPException(status_code=400, detail="Page number must be 1 or greater")
        if page_size < 1:
            raise HTTPException(status_code=400, detail="Page size must be 1 or greater")
        skip = (page - 1) * page_size
        query = db.query(Rule_Remove)
        if ServerName and port:
            query = query.filter(Rule_Remove.servername == ServerName, Rule_Remove.port == port)        
        total_records = query.count()
        rule_removes = query.offset(skip).limit(page_size).all()
        result_list = []
        for rule_remove in rule_removes:
            result_list.append({
                "id_rule": rule_remove.id_rule,
                "rule_file": rule_remove.rule_file,
                "servername": rule_remove.servername,
                "port": rule_remove.port
            })        
        total_pages = (total_records + page_size - 1) // page_size        
        response = {
            "total": total_records,
            "data": result_list,
            "limit": page_size,
            "page": page,
            "total_pages": total_pages
        }
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read rule file: {e}")
    
@router.delete("/remote_rule_CRS",
                description="This API remove rule from CRS")
def remote_rule_CRS(id_rule:str, rule_file:str, db: Session = Depends(get_db)):
    security_config_path= '/etc/apache2/mods-enabled/security2.conf'
    try:
        with open(security_config_path, 'r') as file:
            lines = file.readlines()
        updated_lines = []
        rule_found = False
        ifmodule_found = False
        ifmodule_start_line = -1

        for index, line in enumerate(lines):
            if '<IfModule security2_module>' in line:
                ifmodule_found = True
                ifmodule_start_line = index
            if 'SecRuleRemoveById' in line:
                if id_rule not in line:
                    line = line.strip() + f' {id_rule}\n'
                rule_found = True
            updated_lines.append(line)
        if not rule_found and ifmodule_found:
            for index in range(len(updated_lines) - 1, ifmodule_start_line, -1):
                if '</IfModule>' in updated_lines[index]:
                    updated_lines.insert(index, f'    SecRuleRemoveById {id_rule}\n')
                    break
        with open(security_config_path, 'w') as file:
            file.writelines(updated_lines)
        os.system('sudo systemctl reload apache2')
        # ghi vào sqlite
        new_deleted_rule= Rule_Remove(id_rule=id_rule, rule_file=rule_file, servername="ALL", port="ALL")
        db.add(new_deleted_rule)
        db.commit()
        return f"Rule ID {id_rule} added to SecRuleRemoveById."
    except Exception as e:
        return f"Failed to add rule ID {id_rule} to SecRuleRemoveById: {e}"
        
@router.post("/add_rule_CRS",
            description="This API restore rule to CRS from removed rule")
def add_rule_CRS(id_rule:str, db: Session = Depends(get_db)):
    security_config_path= '/etc/apache2/mods-enabled/security2.conf'
    try:
        with open(security_config_path, 'r') as file:
            lines = file.readlines()
        updated_lines = []
        rule_found = False
        ifmodule_found = False
        ifmodule_start_line = -1

        for index, line in enumerate(lines):
            if '<IfModule security2_module>' in line:
                ifmodule_found = True
                ifmodule_start_line = index
            if 'SecRuleRemoveById' in line:
                if id_rule in line:
                    line = line.replace(f' {id_rule}', '')
                rule_found = True
            updated_lines.append(line)
        if not rule_found and ifmodule_found:
            for index in range(len(updated_lines) - 1, ifmodule_start_line, -1):
                if '</IfModule>' in updated_lines[index]:
                    updated_lines.insert(index, f'    SecRuleRemoveById {id_rule}\n')
                    break
        with open(security_config_path, 'w') as file:
            file.writelines(updated_lines)
        os.system('sudo systemctl reload apache2')
        # xóa trong db
        db.query(Rule_Remove).filter(Rule_Remove.id_rule == id_rule).delete()
        db.commit()
        return f"Rule ID {id_rule} removed from SecRuleRemoveById."
    except Exception as e:
        return f"Failed to remove rule ID {id_rule} from SecRuleRemoveById: {e}"

@router.delete("/delete_rule_CRS_each_agent",
               description="This API delete rule from CRS applies to get each agent")
def delete_rule_CRS_each_agent(id_rule:str, rule_file: str, ServerName: str, Port: int, db: Session = Depends(get_db)):
    rule_file_path = f'/etc/apache2/sites-available/{ServerName}_{Port}.conf'
    try:
        with open(rule_file_path, 'r') as file:
            lines = file.readlines()
        updated_lines = []
        rule_found = False
        ifmodule_found = False
        ifmodule_start_line = -1

        for index, line in enumerate(lines):
            if '<IfModule mod_security2.c>' in line:
                ifmodule_found = True
                ifmodule_start_line = index
            if 'SecRuleRemoveById' in line:
                if id_rule not in line:
                    line = line.strip() + f' {id_rule}\n'
                rule_found = True
            updated_lines.append(line)
        if not rule_found and ifmodule_found:
            for index in range(len(updated_lines) - 1, ifmodule_start_line, -1):
                if '</IfModule>' in updated_lines[index]:
                    updated_lines.insert(index, f'    SecRuleRemoveById {id_rule}\n')
                    break
        with open(rule_file_path, 'w') as file:
            file.writelines(updated_lines)
        os.system('sudo systemctl reload apache2')
        # add db
        new_deleted_rule= Rule_Remove(id_rule=id_rule, rule_file=rule_file, servername=ServerName, port=Port)
        db.add(new_deleted_rule)
        db.commit()
        return f"Rule ID {id_rule} added to SecRuleRemoveById."
    except Exception as e:
        return f"Failed to add rule ID {id_rule} to SecRuleRemoveById: {e}"
    
@router.post("/add_rule_CRS_each_agent",
             description="This API restore rule to CRS applies to get each agent")
def add_rule_CRS_each_agent(id_rule:str, ServerName: str, Port: int, db: Session = Depends(get_db)):
    rule_file_path = f'/etc/apache2/sites-available/{ServerName}_{Port}.conf'
    try:
        with open(rule_file_path, 'r') as file:
            lines = file.readlines()
        updated_lines = []
        rule_found = False
        ifmodule_found = False
        ifmodule_start_line = -1

        for index, line in enumerate(lines):
            if '<IfModule mod_security2.c>' in line:
                ifmodule_found = True
                ifmodule_start_line = index
            if 'SecRuleRemoveById' in line:
                if id_rule in line:
                    line = line.replace(f' {id_rule}', '')
                rule_found = True
            updated_lines.append(line)
        if not rule_found and ifmodule_found:
            for index in range(len(updated_lines) - 1, ifmodule_start_line, -1):
                if '</IfModule>' in updated_lines[index]:
                    updated_lines.insert(index, f'    SecRuleRemoveById {id_rule}\n')
                    break
        with open(rule_file_path, 'w') as file:
            file.writelines(updated_lines)
        os.system('sudo systemctl reload apache2')
        # xóa trong db
        db.query(Rule_Remove).filter(Rule_Remove.id_rule == id_rule).delete()
        db.commit()
        return f"Rule ID {id_rule} removed from SecRuleRemoveById."
    except Exception as e:
        return f"Failed to remove rule ID {id_rule} from SecRuleRemoveById: {e}"

@router.get("/update_crs")
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