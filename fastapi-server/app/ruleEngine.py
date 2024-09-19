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
def add_new_vhost_entry(port, servername, ProxyPreserveHost, ProxyPass, ProxyPassReverse,ErrorLog, ErrorDocument, protocol, SSLEngine):
        if SSLEngine == 'On' and port != 80:
            # Construct the new VirtualHost entry for HTTPS
            return f"""
# HTTPS VirtualHost (Reverse Proxy)
<VirtualHost *:{port}>
    ServerName {servername}

    SSLEngine On
    SSLCertificateFile /home/kali/Desktop/localhost.crt
    SSLCertificateKeyFile /home/kali/Desktop/localhost.key

    ProxyRequests Off
    SSLProxyEngine On
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    ProxyPreserveHost {ProxyPreserveHost}
    ProxyPass {ProxyPass}
    ProxyPassReverse {ProxyPassReverse}

    ErrorLog {ErrorLog}
    ErrorDocument {ErrorDocument}
    <IfModule mod_security2.c>
        SecRuleEngine DetectionOnly
        Include /etc/modsecurity/custom_rules/{servername}_{port}_rules.conf
    </IfModule>
</VirtualHost>
"""
        if SSLEngine == 'Off' and port != 443:  # Default to HTTP if not HTTPS
            # Construct the new VirtualHost entry for HTTP
            return f"""
<VirtualHost *:{port}>
    ServerName {servername}

    SSLEngine Off
    SSLCertificateFile /home/kali/Desktop/localhost.crt
    SSLCertificateKeyFile /home/kali/Desktop/localhost.key

    ProxyRequests Off
    SSLProxyEngine On
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    ProxyPreserveHost {ProxyPreserveHost}
    ProxyPass {ProxyPass}
    ProxyPassReverse {ProxyPassReverse}

    ErrorLog {ErrorLog}
    ErrorDocument {ErrorDocument}
    <IfModule mod_security2.c>
        SecRuleEngine DetectionOnly
        Include /etc/modsecurity/custom_rules/{servername}_{port}_rules.conf
    </IfModule>
</VirtualHost>
"""
        else:
            return f"Port {port} is not use for this {protocol}."
        