@app.put("/updatehost/{host_id}", tags=["agents"])
def update_host(host_id: int, host_update: HostUpdate):
    db = SessionLocal()
    config_file_path = '/etc/apache2/sites-available/www.dvwa.com.conf'
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
        if value is not None:
            # Update the field in the database
            setattr(db_host, var, value)
            # Check if protocol is being updated
            if var == "protocol":
                protocol_changed = True
                # If changing to HTTPS, add the SSL configuration
                if value.lower() == 'https':
                    db_host.sslcertificatefile = "/home/kali/Desktop/localhost.crt"
                    db_host.sslcertificatekeyfile = "/home/kali/Desktop/localhost.key"
                    db_host.sslengine = "On"
                    db_host.sslproxyengine = "On"
                # If changing to HTTP, remove the SSL configuration
                elif value.lower() == 'http':
                    db_host.sslcertificatefile = None
                    db_host.sslcertificatekeyfile = None
                    db_host.sslengine = None
                    db_host.sslproxyengine = None
            config_changed = True

    db.commit()

    # If the protocol has changed, update the Apache configuration
    if config_changed:
        # Find and update the appropriate configuration directives within the <VirtualHost> block
        vhost_started = False
        for i, line in enumerate(vhost_content):
            if line.strip().startswith(f"<VirtualHost *:{db_host.port}>"):
                vhost_started = True
            if vhost_started and "</VirtualHost>" in line.strip():
                if "ProxyPreserveHost" in line:
                    vhost_content[i] = f"    ProxyPreserveHost {host_update.ProxyPreserveHost}\n"
                elif "ProxyPass" in line:
                    vhost_content[i] = f"    ProxyPass {host_update.ProxyPass}\n"
                elif "ProxyPassReverse" in line:
                    vhost_content[i] = f"    ProxyPassReverse {host_update.ProxyPassReverse}\n"
                elif "ErrorLog" in line:
                    vhost_content[i] = f"    ErrorLog {host_update.ErrorLog}\n"
                elif "ErrorDocument" in line:
                    vhost_content[i] = f"    ErrorDocument {host_update.ErrorDocument}\n"
                elif protocol_changed:
    # Find the correct <VirtualHost> block and update it
        # vhost_started = False
        # for i, line in enumerate(vhost_content):
        #     if line.strip().startswith(f"<VirtualHost *:{db_host.port}>"):
        #         vhost_started = True
        #     if vhost_started and "</VirtualHost>" in line.strip():
                    if db_host.protocol.lower() == 'https':
                # Add SSL configuration lines before the closing tag
                        vhost_content[i:i] = ssl_lines
                    elif db_host.protocol.lower() == 'http':
                # Remove SSL configuration lines
                        vhost_content = [
                            line for line in vhost_content
                            if not any(ssl_config_line.strip() in line for ssl_config_line in ssl_lines)
                        ]
                    break

    # Write the updated content back to the Apache configuration file
        with open(config_file_path, 'w') as file:
            file.writelines(vhost_content)

    # Restart Apache to apply changes
    restart_apache()

    return {"message": "Host configuration updated successfully."}