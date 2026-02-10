### Port Scanner

### Design and Implementation
The port scanner is designed as a multithreaded TCP scanning tool. It uses Python’s socket module to perform TCP scans. The scanner allows specifying the target hosts and ports in flexible ways like CIDR ranges, port ranges, IPs, and comma separate combinations. The scanner keeps all (target, port) pairs in a queue and multiple worker threads retrieve and process them concurrently. If the worker finds the port open, then it attempts to perform lightweight service fingerprinting through banner grabbing and HTTP probing. Responses are analyzed to identify which service is running on that port. Results are stored as a json file.


```bash
python port_scanner/main.py --target 172.20.0.0/24 --ports 1-65535 --threads 500 --timeout 0.1
```

Results are stored in `results.json`
