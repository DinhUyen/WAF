from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Define the database model
Base = declarative_base()

class ModSecHost(Base):
    __tablename__ = 'modsechost'
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    port = Column(Integer, index=True)
    servername = Column(String)
    proxypreservehost = Column(String)
    proxypass = Column(String)
    proxypassreverse = Column(String)
    errorlog = Column(String)
    errordocument = Column(String)
    protocol = Column(String)
    sslcertificatefile = Column(String, nullable=True)
    sslcertificatekeyfile = Column(String, nullable=True)
    sslengine = Column(String, nullable=True)
    sslproxyengine = Column(String, nullable=True)

# Connect to the SQLite database
engine = create_engine('sqlite:////home/kali/Desktop/WAF/db/modsec.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# Add new entries to the database
hosts_data = [
    {
        "port": 80,
        "servername": "www.dvwa.com",
        "proxypreservehost": "On",
        "proxypass": "http://192.168.157.139:8005/",
        "proxypassreverse": "http://192.168.157.139:8005/",
        "errorlog": "/var/log/apache2/errors_80.log",
        "errordocument": "/403.html",
        "protocol": "http"
    },
    {
        "port": 81,
        "servername": "www.dvwa.com",
        "proxypreservehost": "On",
        "proxypass": "http://192.168.157.135/",
        "proxypassreverse": "http://192.168.157.135/",
        "errorlog": "/var/log/apache2/errors_81.log",
        "errordocument": "/403.html",
        "protocol": "http"
    },
    {
        "port": 7071,
        "servername": "localhost",
        "protocol": "https",
        "sslcertificatefile": "/home/kali/Desktop/localhost.crt",
        "sslcertificatekeyfile": "/home/kali/Desktop/localhost.key",
        "sslengine": "on",
        "sslproxyengine": "on",
        "proxypass": "https://192.168.157.185:7071/",
        "proxypassreverse": "https://192.168.157.185:7071/",
        "errorlog": "/var/log/apache2/errors_443.log"
    },
    {
        "port": 443,
        "servername": "localhost",
        "protocol": "https",
        "sslcertificatefile": "/home/kali/Desktop/localhost.crt",
        "sslcertificatekeyfile": "/home/kali/Desktop/localhost.key",
        "sslengine": "on",
        "sslproxyengine": "on",
        "proxypass": "https://192.168.157.185:8443/",
        "proxypassreverse": "https://192.168.157.185:8443/",
        "errorlog": "/var/log/apache2/errors_443.log"
    },
    {
        "port": 82,
        "servername": "uyen.com",
        "proxypreservehost": "On",
        "proxypass": "http://192.168.157.139:8005/",
        "proxypassreverse": "http://192.168.157.139:8005/",
        "errorlog": "/var/log/apache2/errors_80.log",
        "errordocument": "/403.html",
        "protocol": "http"
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