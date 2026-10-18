-- Hypothesis: an attacker guessed an SSH password. Look for a successful login from
-- an address that failed many logins in the 10 minutes before it.
SELECT s.src_ip,
       s.user,
       s.ts AS success_ts,
       (SELECT COUNT(*) FROM events f
         WHERE f.src_ip = s.src_ip
           AND f.action = 'login' AND f.outcome = 'failure'
           AND f.ts BETWEEN strftime('%Y-%m-%dT%H:%M:%SZ', s.ts, '-10 minutes')
                        AND s.ts) AS failures_before
FROM events s
WHERE s.action = 'login' AND s.outcome = 'success' AND s.src_ip IS NOT NULL
GROUP BY s.id
HAVING failures_before >= 5
ORDER BY failures_before DESC;
