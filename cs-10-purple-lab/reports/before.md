# ATT&CK coverage report

Run: `20261020T122543Z`

**7 detected, 7 missed, 0 not run** of 14 techniques (50.0% of executed techniques detected)

| Technique | Name | Tactic | Status | Detected by / Reason |
|---|---|---|---|---|
| T1595.002 | Active Scanning: Vulnerability Scanning | reconnaissance | detected | web-scanner-user-agent |
| T1595.003 | Active Scanning: Wordlist Scanning | reconnaissance | detected | web-404-flood |
| T1190 | Exploit Public-Facing Application | initial-access | detected | web-path-traversal, web-rce-probe, web-sqli |
| T1110.001 | Brute Force: Password Guessing | credential-access | detected | ssh-brute-force |
| T1110.003 | Brute Force: Password Spraying | credential-access | detected | ssh-password-spraying |
| T1078 | Valid Accounts | initial-access | detected | ssh-root-login |
| T1082 | System Information Discovery | discovery | missed | no-rule |
| T1033 | System Owner/User Discovery | discovery | missed | no-rule |
| T1083 | File and Directory Discovery | discovery | missed | no-rule |
| T1057 | Process Discovery | discovery | missed | no-rule |
| T1016 | System Network Configuration Discovery | discovery | missed | no-rule |
| T1087.001 | Account Discovery: Local Account | discovery | missed | no-rule |
| T1036.005 | Masquerading: Match Legitimate Name or Location | defense-evasion | missed | no-rule |
| T1053.003 | Scheduled Task/Job: Cron | persistence | detected | cron-persistence |

## Gaps by tactic

- defense-evasion: T1036.005 Masquerading: Match Legitimate Name or Location (no-rule)
- discovery: T1016 System Network Configuration Discovery (no-rule)
- discovery: T1033 System Owner/User Discovery (no-rule)
- discovery: T1057 Process Discovery (no-rule)
- discovery: T1082 System Information Discovery (no-rule)
- discovery: T1083 File and Directory Discovery (no-rule)
- discovery: T1087.001 Account Discovery: Local Account (no-rule)

## Untested detections

- sudo-root-shell: T1548.003
- user-created: T1136.001

## Unattributed alerts

None.
