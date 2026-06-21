# Validation Screenshots

Evidence that each detection fires on simulated attacks and raises incidents.

Place these images here (exact filenames matter — they're referenced from the detection files):

| Filename | What it shows |
|----------|---------------|
| `01-brute-force-detection.png` | Brute-force query returning 25 failed attempts with attacker accounts |
| `01-brute-force-incident.png` | Brute-force incident raised in Defender (Credential Access) |
| `02-powershell-detection.png` | Suspicious PowerShell query showing flagged command lines |
| `02-powershell-incident.png` | Suspicious PowerShell incidents in Defender (Execution) |
| `03-persistence-detection.png` | Registry persistence query catching the planted entry |
| `03-persistence-incident.png` | Registry persistence incident, High severity, T1547.001 |
| `04-reconnaissance-command-burst-detection.png` | Recon detection showing 9 distinct recon commands clustered |
| `04-reconnaissance-command-burst-incident.png` | Reconnaissance command burst incident in Defender (Discovery) |
| `05-mfa-registration-signin.png` | Sign-in log entry showing the untrusted-IP (Proton VPN, Seattle/US) sign-in correlated with the security-info registration |
| `05-mfa-registration-detection.png` | MFA registration KQL query and deduped correlation result |
| `05-mfa-registration-rule-config.png` | Analytics rule configuration — High severity, T1556.006 mapping, entity mapping (Account/IP) |
| `05-mfa-registration-logicapp.png` | Logic App workflow — incident trigger wired to the "Add comment to incident" action |
| `05-mfa-registration-automation-rule.png` | Automation rule — "When incident is created" → "Run playbook" wiring |
| `05-mfa-registration-incident.png` | MFA registration incident in Defender (Persistence, T1556.006), with the automated triage comment from the Logic App visible |
