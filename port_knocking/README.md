## Port Knocking Server

### Arguments

```bash
python knock_server.py --help
usage: knock_server.py [-h] [--sequence SEQUENCE] [--protected-port PROTECTED_PORT] [--window WINDOW]

Port knocking server

options:
  -h, --help            show this help message and exit
  --sequence SEQUENCE   Comma-separated knock ports
  --protected-port PROTECTED_PORT
                        Protected service port
  --window WINDOW       Seconds allowed to complete the sequence
```

### How It Works

1. First, it blocks the protected port (default: `2222`) using `iptables`.
2. The server listens on each port in the knock sequence.
3. For every incoming connection:
   - The client IP and timestamp are recorded.
   - The server checks whether the knock matches the expected sequence.
   - It maintains each client separately, so if one client successfully opens a port, other clients are not automatically allowed. Each client will have to knock the server in correct order in order to be able to access the protected port.
4. If the full sequence is completed within the allowed time window:
   - A firewall rule is inserted to allow the client IP. Only the client IP that sucessfully performs the knocks will be able to access the protected port.
   - A background timer schedules automatic rule removal to close the protected port after 15 minutes for the client.
5. After the access timeout expires, the port is closed again.


### Example usage

```bash
docker compose up port_knocking --build # Listens to port 2222 (dummy server) and starts knock_server.py which blocks requests to the protected port 2222 and listens for port knocking.
nc 172.20.0.40 # Will fail
python knock_client.py --target 172.20.0.20 --sequence 1234,5678,9012
nc 172.20.0.40 # Will succeed
```

## To protect real service

Run the `knock_server.py` on any server where you want to protect a port.
For instance, to protect the ssh service in `secrete_ssh` container, we will modify its startup script in `secret_ssh/Dockerfile` to run this port knocking server on startup. This way, it will block the protected port `2222` by default and will open only to clients who knocks properly.




