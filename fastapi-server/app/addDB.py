from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Define the database model
Base = declarative_base()

class ModSecHost(Base):
    __tablename__ = 'MODSECHOST'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    Port = Column(Integer, index=True)
    ServerName = Column(String)
    ProxyPreserveHost = Column(String)
    ProxyPass = Column(String)
    ProxyPassReverse = Column(String)
    ErrorLog = Column(String)
    ErrorDocument = Column(String)
    Protocol = Column(String)
    SSLCertificateFile = Column(String, nullable=True)
    SSLCertificateKeyFile = Column(String, nullable=True)
    SSLEngine = Column(String, nullable=True)
    SSLProxyEngine = Column(String, nullable=True)

# Connect to the SQLite database
engine = create_engine('sqlite:////home/kali/Desktop/WAF/db/modsec.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Add new entries to the database
hosts_data = [
    {
        "Port": 80,
        "ServerName": "www.dvwa.com",
        "ProxyPreserveHost": "On",
        "ProxyPass": "http://192.168.157.139:8005/",
        "ProxyPassReverse": "http://192.168.157.139:8005/",
        "ErrorLog": "/var/log/apache2/errors_80.log",
        "ErrorDocument": "/403.html",
        "Protocol": "http"
    },
    {
        "Port": 81,
        "ServerName": "www.dvwa.com",
        "ProxyPreserveHost": "On",
        "ProxyPass": "http://192.168.157.135/",
        "ProxyPassReverse": "http://192.168.157.135/",
        "ErrorLog": "/var/log/apache2/errors_81.log",
        "ErrorDocument": "/403.html",
        "Protocol": "http"
    },
    {
        "Port": 7071,
        "ServerName": "localhost",
        "Protocol": "https",
        "SSLCertificateFile": "/home/kali/Desktop/localhost.crt",
        "SSLCertificateKeyFile": "/home/kali/Desktop/localhost.key",
        "SSLEngine": "on",
        "SSLProxyEngine": "on",
        "ProxyPass": "https://192.168.157.185:7071/",
        "ProxyPassReverse": "https://192.168.157.185:7071/",
        "ErrorLog": "/var/log/apache2/errors_443.log"
    },
    {
        "Port": 443,
        "ServerName": "localhost",
        "Protocol": "https",
        "SSLCertificateFile": "/home/kali/Desktop/localhost.crt",
        "SSLCertificateKeyFile": "/home/kali/Desktop/localhost.key",
        "SSLEngine": "on",
        "SSLProxyEngine": "on",
        "ProxyPass": "https://192.168.157.185:8443/",
        "ProxyPassReverse": "https://192.168.157.185:8443/",
        "ErrorLog": "/var/log/apache2/errors_443.log"
    },
    {
        "Port": 82,
        "ServerName": "uyen.com",
        "ProxyPreserveHost": "On",
        "ProxyPass": "http://192.168.157.139:8005/",
        "ProxyPassReverse": "http://192.168.157.139:8005/",
        "ErrorLog": "/var/log/apache2/errors_80.log",
        "ErrorDocument": "/403.html",
        "Protocol": "http"
    }
]

# Insert the data into the database
for host in hosts_data:
    new_host = ModSecHost(**host)
    session.add(new_host)

# Commit the changes to the database
session.commit()

# Close the session
session.close()

print("Configurations have been added to the database.")