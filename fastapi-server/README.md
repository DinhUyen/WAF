Test: docker run -it -v /root/ModSercurityPaser/fastapi-server/app:/app -v /root/ModSercurityPaser/db:/db -p 5555:80 trung501/modsecurity-parser:fastap1.0 bash

example db in /root/ModSercurityPaser/db/modsec.db

docker run -it --rm -v /root/ModSercurityPaser/db:/db -p 5555:80 trung501/modsecurity-parser:fastap1.1

sudo docker run -it -v /home/kali/Desktop/ModSercurityPaser/fastapi-server/app:/app -v /home/kali/Desktop/ModSercurityPaser/db:/db -p 5555:80 trung501/modsecurity-parser:fastap1.0 bash
