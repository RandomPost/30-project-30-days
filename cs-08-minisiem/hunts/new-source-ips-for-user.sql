-- Hypothesis: a valid account is being used from somewhere it has never been used
-- before. List each successful login whose source IP is new for that user.
SELECT user, src_ip, MIN(ts) AS first_seen, COUNT(*) AS logins
FROM events
WHERE action = 'login' AND outcome = 'success'
GROUP BY user, src_ip
HAVING first_seen > (SELECT MIN(ts) FROM events e2
                      WHERE e2.user = events.user AND e2.action = 'login'
                        AND e2.outcome = 'success')
ORDER BY first_seen;
