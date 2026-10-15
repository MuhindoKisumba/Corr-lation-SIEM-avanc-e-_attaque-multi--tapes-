/* =========================================================
    CORRÉLATION SIEM AVANCÉE (MULTI-ÉTAPES)
   Détection d’attaque complète :
   1. Scan de ports
   2. Bruteforce SSH
   3. Connexion réussie
   4. Escalade / activité suspecte
   ========================================================= */


/* =========================================================
   1. TABLE SCÉNARIOS D’ATTAQUE
   ========================================================= */
CREATE TABLE IF NOT EXISTS siem_scenarios (
    id SERIAL PRIMARY KEY,
    nom TEXT,
    description TEXT,
    niveau_risque TEXT
);

INSERT INTO siem_scenarios (nom, description, niveau_risque)
VALUES 
('ATTACK_CHAIN_SSH', 'Scan + Bruteforce + Login + Action', 'CRITIQUE')
ON CONFLICT DO NOTHING;


/* =========================================================
   2. TABLE ALERTES CORRÉLÉES
   ========================================================= */
CREATE TABLE IF NOT EXISTS alertes_correlation (
    id SERIAL PRIMARY KEY,
    date_detection TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_source TEXT,
    scenario TEXT,
    niveau_risque TEXT,
    details JSONB
);


/* =========================================================
   3. DÉTECTION CHAÎNE D’ATTAQUE (FENÊTRE TEMPORELLE)
   ========================================================= */
WITH scan AS (
    SELECT ip_source, MIN(date_log) AS t_scan
    FROM logs_securite
    WHERE source = 'firewall'
    GROUP BY ip_source
),

bruteforce AS (
    SELECT ip_source, MIN(date_log) AS t_brute, COUNT(*) AS tentatives
    FROM logs_securite
    WHERE source = 'ssh'
      AND message ILIKE '%failed%'
    GROUP BY ip_source
    HAVING COUNT(*) > 5
),

login_success AS (
    SELECT ip_source, MIN(date_log) AS t_login
    FROM logs_securite
    WHERE source = 'ssh'
      AND message ILIKE '%accepted%'
    GROUP BY ip_source
),

post_activity AS (
    SELECT ip_source, MIN(date_log) AS t_action
    FROM logs_securite
    WHERE source = 'system'
      AND message ILIKE '%sudo%' -- ou activité critique
    GROUP BY ip_source
),

attack_chain AS (
    SELECT 
        s.ip_source,
        s.t_scan,
        b.t_brute,
        l.t_login,
        p.t_action,

        EXTRACT(EPOCH FROM (b.t_brute - s.t_scan)) AS delta_scan_brute,
        EXTRACT(EPOCH FROM (l.t_login - b.t_brute)) AS delta_brute_login,
        EXTRACT(EPOCH FROM (p.t_action - l.t_login)) AS delta_login_action

    FROM scan s
    JOIN bruteforce b ON s.ip_source = b.ip_source
    JOIN login_success l ON b.ip_source = l.ip_source
    LEFT JOIN post_activity p ON l.ip_source = p.ip_source

    WHERE b.t_brute > s.t_scan
      AND l.t_login > b.t_brute
      AND (p.t_action IS NULL OR p.t_action > l.t_login)
      AND (l.t_login - s.t_scan) < INTERVAL '30 minutes'
)

/* =========================================================
   4. INSERTION ALERTE SI CHAÎNE COMPLÈTE
   ========================================================= */
INSERT INTO alertes_correlation (
    ip_source,
    scenario,
    niveau_risque,
    details
)
SELECT 
    ip_source,
    'ATTACK_CHAIN_SSH',
    'CRITIQUE',
    jsonb_build_object(
        'scan_time', t_scan,
        'bruteforce_time', t_brute,
        'login_time', t_login,
        'action_time', t_action,
        'delta_scan_brute_sec', delta_scan_brute,
        'delta_brute_login_sec', delta_brute_login,
        'delta_login_action_sec', delta_login_action
    )
FROM attack_chain;


/* =========================================================
   5. SCORE DE RISQUE (SCORING INTELLIGENT)
   ========================================================= */
SELECT 
    ip_source,
    scenario,
    niveau_risque,
    details,

    (
        CASE WHEN details->>'action_time' IS NOT NULL THEN 50 ELSE 20 END +
        CASE WHEN (details->>'delta_brute_login_sec')::numeric < 60 THEN 30 ELSE 10 END +
        CASE WHEN (details->>'delta_scan_brute_sec')::numeric < 120 THEN 20 ELSE 5 END
    ) AS risk_score

FROM alertes_correlation
ORDER BY risk_score DESC;


/* =========================================================
   6. DÉTECTION MULTI-IP (ATTAQUE DISTRIBUÉE)
   ========================================================= */
SELECT 
    COUNT(DISTINCT ip_source) AS nb_ip,
    MIN(date_log) AS debut,
    MAX(date_log) AS fin
FROM logs_securite
WHERE source = 'ssh'
  AND message ILIKE '%failed%'
  AND date_log > NOW() - INTERVAL '10 minutes'
HAVING COUNT(DISTINCT ip_source) > 10;


/* =========================================================
   7. VUE SIEM (EXPORT JSON)
   ========================================================= */
CREATE OR REPLACE VIEW vue_siem_correlation AS
SELECT 
    id,
    date_detection,
    ip_source,
    scenario,
    niveau_risque,
    details,
    jsonb_build_object(
        'timestamp', date_detection,
        'scenario', scenario,
        'severity', niveau_risque,
        'ip', ip_source,
        'attack_chain', details
    ) AS siem_event
FROM alertes_correlation;


/* =========================================================
   8. INDEX PERFORMANCE
   ========================================================= */
CREATE INDEX IF NOT EXISTS idx_corr_ip ON alertes_correlation(ip_source);
CREATE INDEX IF NOT EXISTS idx_corr_date ON alertes_correlation(date_detection);


/* =========================================================
   9. CONSULTATION
   ========================================================= */
SELECT * FROM alertes_correlation ORDER BY date_detection DESC;


/* =========================================================
   10. AUTOMATISATION (CRON / SCHEDULER)
   ========================================================= */
-- À exécuter toutes les 1-5 minutes :
-- SELECT * FROM vue_siem_correlation;
