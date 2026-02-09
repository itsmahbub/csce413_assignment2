## Honeypot 


### Architecture and Design

I develop SSH honeypot as an event-driven client-server architecture. It emulates the SSH environment using `Paramiko` and captures attacker behaviour. All login attempts are logged, and authentication is validated against a fake credential database. No real system users or services are exposed. It listens on TCP port `22` and handles each connection as a separate thread. Inside the thread, it emulates real SSH protocols. On successful authentication against the fake credentials, it emulates basic shell services like `ls`, `cd`, `pwd`, `cat`, and `exit`. All actions (commands) performed by the attacker are logged for analysis.

### Logging Mechanisms

I have implemented a centralized logging using Python's logging framework to record all events. Developed a custom logger helper that configures both file and console handlers. It shows the log in console and writes logs to /app/logs/honeypot.log for future analysis. Each log entry includes a timestamp, source IP, action performed by that attacker (e.g., login attempt, commands or data sent by the attacker).
In addition to console and file logs, the system records attacker activities in json format in /app/logs/events.jsonl file. It records detailed security events such as connection events, authentication attempts, brute-force detection events, connection attempts from blacklisted IPs, and sensitive resource access attempts.


### Detection Capabilities

The honeypot has real-time detection capabilities to identify and characterize malicious behavior based on observed interaction patterns. It keeps track of authentication attempts for each client and when the client fails to authenticate repeatedly for five times, it is marked as brute-force attack and logged in the system and the client is added to blacklist. If the blacklisted client attempts to connect then the honeypot logs "blaklisted_connection" event. If the client reads particular secret files, then "secret_access_attempt" event is logged. 


### Getting started

1. Run the docker container `docker compose up honeypot --build`
2. SSH into the server `ssh root@172.20.0.30`
3. Guess different username and password combinations. It behaves like real ssh server.
4. Some fake credentails that allow simulation of successful authentication are ("root": "toor", "admin": "admin123", "test": "test").
5. After successful login, run commands like `ls`, `cd`, `cat`.
6. Look logs in `logs/honeypot.log` and security events in `logs/events.jsonl`.

