## Port Knocking Server


### Implementation Details

The port-knocking server is implemented in Python using standard libraries (socket, threading, and subprocess) and Linux iptables for access control. At startup, the server blocks the protected port by inserting a default REJECT rule. It then listens on a predefined sequence of TCP ports to observe connection attempts (knocks). The protected port and the sequence of ports can be configured by user by passing command line arguments when starting the server.

For each client IP, the server tracks knock progress and timestamps in memory. A knock is accepted only if the ports are contacted in the correct order and within a configurable time window. Incorrect order or timeout immediately resets the client’s state. When a client completes the full knock sequence successfully, the server temporarily inserts an iptables rule allowing that IP to access the protected port. A background thread schedules automatic rule removal after a fixed timeout, restoring the default blocked state.

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
python knock_client.py --target 172.20.0.40 --sequence 1234,5678,9012
nc 172.20.0.40 # Will succeed
```

## To protect real service

Run the `knock_server.py` on any server where you want to protect a port.
For instance, to protect the ssh service in `secrete_ssh` container, we will ssh into that container and run `python3 /apps/knock_server.py`. This way, it will block the protected port `2222` by default and will open only to clients who knocks properly.





