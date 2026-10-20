# ATT&CK coverage report

Run: `20261020T123007Z`

**13 detected, 1 missed, 0 not run** of 14 techniques (92.9% of executed techniques detected)

| Technique | Name | Tactic | Status | Detected by / Reason |
|---|---|---|---|---|
| T1595.002 | Active Scanning: Vulnerability Scanning | reconnaissance | detected | web-scanner-user-agent |
| T1595.003 | Active Scanning: Wordlist Scanning | reconnaissance | detected | web-404-flood |
| T1190 | Exploit Public-Facing Application | initial-access | detected | web-path-traversal, web-rce-probe, web-sqli |
| T1110.001 | Brute Force: Password Guessing | credential-access | detected | ssh-brute-force |
| T1110.003 | Brute Force: Password Spraying | credential-access | detected | ssh-password-spraying |
| T1078 | Valid Accounts | initial-access | detected | ssh-root-login |
| T1082 | System Information Discovery | discovery | detected | discovery-system-info |
| T1033 | System Owner/User Discovery | discovery | detected | discovery-whoami |
| T1083 | File and Directory Discovery | discovery | detected | discovery-file-listing |
| T1057 | Process Discovery | discovery | detected | discovery-process-list |
| T1016 | System Network Configuration Discovery | discovery | detected | discovery-network-config |
| T1087.001 | Account Discovery: Local Account | discovery | detected | discovery-local-accounts |
| T1036.005 | Masquerading: Match Legitimate Name or Location | defense-evasion | missed | no-rule |
| T1053.003 | Scheduled Task/Job: Cron | persistence | detected | cron-persistence |

## Gaps by tactic

- defense-evasion: T1036.005 Masquerading: Match Legitimate Name or Location (no-rule)

## Untested detections

- sudo-root-shell: T1548.003
- user-created: T1136.001

## Unattributed alerts

None.
