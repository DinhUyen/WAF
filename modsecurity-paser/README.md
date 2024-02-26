# ModSercurityPaser

Run: docker run --rm -it -v /root/log:/log -v /root/db:/db trung501/modsecurity-parser:1.3

OR : docker run --rm -it -e "LOG_PATH=audit.log" -v /root/log:/log -v /root/db:/db trung501/modsecurity-parser:log1.4

With folder log contain /root/log and folder save database is /root/db.

Type /db/audit.log after run.
