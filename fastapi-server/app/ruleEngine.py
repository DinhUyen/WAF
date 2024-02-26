import subprocess
def update_modsecurity_config(file_path, virtual_host_port, rule_engine_mode):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    virtual_host_found = False
    for i, line in enumerate(lines):
        if f"<VirtualHost *:{virtual_host_port}>" in line:
            virtual_host_found = True
            j = i + 1
            while j < len(lines) and "</VirtualHost>" not in lines[j]:
                if "SecRuleEngine" in lines[j]:
                    lines[j] = f"        SecRuleEngine {rule_engine_mode}\n"
                j += 1
            break

    if not virtual_host_found:
        print(f"VirtualHost *:{virtual_host_port} not found in the configuration file.")
        return

    with open(file_path, 'w') as file:
        file.writelines(lines)
    restart_apache()
def restart_apache():
    try:
        subprocess.run(['sudo', 'systemctl', 'reload', 'apache2'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error restarting Apache: {e}")
# Example usage:
#update_modsecurity_config('/etc/apache2/sites-available/www.dvwa.com.conf', 80, 'DetectionOnly')
def add_new_vhost_entry(port, servername, ProxyPreserveHost, ProxyPass, ProxyPassReverse,ErrorLog, ErrorDocument, protocol):
        if protocol.lower() == 'https':
            # Construct the new VirtualHost entry for HTTPS
            return f"""
# HTTPS VirtualHost (Reverse Proxy)
<VirtualHost *:{port}>
    ServerName {servername}

    SSLEngine on
    SSLCertificateFile /home/kali/Desktop/localhost.crt
    SSLCertificateKeyFile /home/kali/Desktop/localhost.key

    ProxyRequests Off

    SSLEngine On
    SSLProxyEngine On
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    ProxyPass {ProxyPass}
    ProxyPassReverse {ProxyPassReverse}

    ErrorLog {ErrorLog}
    ErrorDocument {ErrorDocument}
</VirtualHost>
"""
        else:  # Default to HTTP if not HTTPS
            # Construct the new VirtualHost entry for HTTP
            return f"""
<VirtualHost *:{port}>
    ServerName {servername}
    ProxyPreserveHost {ProxyPreserveHost}
    ProxyPass {ProxyPass}
    ProxyPassReverse {ProxyPassReverse}
    ErrorLog {ErrorLog}
    ErrorDocument {ErrorDocument}
    <IfModule mod_security2.c>
        SecRuleEngine DetectionOnly
        # More ModSecurity configurations if needed
    </IfModule>
</VirtualHost>
"""


