## MITM Starter Template

This directory is a starter template for the MITM portion of the assignment.

### What you need to implement
- Capture traffic between the web app and database.
- Analyze packets for sensitive data and explain the impact.
- Record your findings.
- Include evidence (pcap files or screenshots) alongside your report.

### Getting started
1. Run your capture workflow from this directory or the repo root.
2. Save artifacts (pcap or screenshots) in this folder.
3. Document everything.


Captured packet dumps or intercepted data (store them in mitm/)
Explanation of the vulnerability and its impact


##
docker network ls
sudo tcpdump -i br-e0376de1ebe7 -A -s 0 'port 3306'

FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}

curl -H "Authorization: Bearer FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}" 172.20.0.21:8888/flag