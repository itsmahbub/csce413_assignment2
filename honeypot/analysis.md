# Honeypot Analysis

## Summary of Observed Attacks

The collected honeypot security events reveal attack behaviors such as automated credential-guessing and post-compromise reconnaissance attempts. Analysis of the event records shows repeated login attempts using common usernames and weak password variants, indicating brute-force and dictionary-based attacks. Once predefined thresholds are exceeded, attackers are correctly flagged and blacklisted, demonstrating the system's ability to identify persistent threats. Subsequent connection attempts from blacklisted sources further confirm continued probing behavior. In some cases, attackers attempt to access sensitive resources, such as secret files, reflecting data exfiltration attempts. Overall, the captured data highlights typical attacker behaviour and demonstrates the honeypot's effectiveness in monitoring and documenting these activities.

## Notable Patterns

- Login attempts with various credentials.
- Navigating different directories to look for secret data.

## Recommendations

- On detecting brute-force attack, the IP should be blocked in all legitimate services so that the attacker can not harm real services.
- Based on the patter of the attacker activites, protect sensitive resources in real services (e.g., ensure least privilege on protected resources)
