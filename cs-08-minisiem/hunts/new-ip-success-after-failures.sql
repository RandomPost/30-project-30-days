-- Hypothesis: an account was compromised by password guessing. Look for a successful
-- SSH login for a user from a source IP that user has never successfully logged in
-- from before, preceded within 10 minutes by failed logins against the same account.
SELECT s.user,
       s.src_ip,
       s.ts AS success_ts,
       (SELECT COUNT(*) FROM events f
         WHERE f.user = s.user
           AND f.action = 'login' AND f.outcome = 'failure'
           AND f.ts BETWEEN strftime('%Y-%m-%dT%H:%M:%SZ', s.ts, '-10 minutes')
                        AND s.ts) AS failures_before,
       (SELECT COUNT(DISTINCT f.src_ip) FROM events f
         WHERE f.user = s.user
           AND f.action = 'login' AND f.outcome = 'failure'
           AND f.ts BETWEEN strftime('%Y-%m-%dT%H:%M:%SZ', s.ts, '-10 minutes')
                        AND s.ts) AS failing_ips,
       (SELECT COUNT(*) FROM events p
         WHERE p.user = s.user AND p.action = 'login' AND p.outcome = 'success'
           AND p.ts < s.ts) AS prior_successes
FROM events s
WHERE s.action = 'login' AND s.outcome = 'success'
  AND s.src_ip IS NOT NULL AND s.program = 'sshd'
  AND NOT EXISTS (SELECT 1 FROM events p
                   WHERE p.user = s.user AND p.src_ip = s.src_ip
                     AND p.action = 'login' AND p.outcome = 'success'
                     AND p.ts < s.ts)
GROUP BY s.user, s.src_ip, s.ts
HAVING failures_before >= 1
ORDER BY failures_before DESC, success_ts;
