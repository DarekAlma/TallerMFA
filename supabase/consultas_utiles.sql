-- =====================================================================
-- Consultas útiles para la sustentación (SQL Editor de Supabase)
-- =====================================================================

-- Usuarios con su estado 2FA
select u.username,
       coalesce(m.status, 'NOT_CONFIGURED') as mfa_status,
       m.activated_at,
       (select count(*) from backup_codes b where b.user_id = u.id and b.used_at is null) as backup_codes_disponibles
from users u
left join mfa_configurations m on m.user_id = u.id
order by u.created_at desc;

-- Últimos eventos de autenticación (incluye REPLAY_ATTACK_DETECTED) con su flow run de Prefect
select a.created_at, u.username, a.event, a.detail, a.flow_run_id
from auth_audit_log a
left join users u on u.id = a.user_id
order by a.created_at desc
limit 50;

-- Intentos de replay detectados
select u.username, count(*) as intentos, max(a.created_at) as ultimo
from auth_audit_log a join users u on u.id = a.user_id
where a.event = 'REPLAY_ATTACK_DETECTED'
group by u.username;

-- Códigos de respaldo usados
select u.username, b.used_at
from backup_codes b join users u on u.id = b.user_id
where b.used_at is not null
order by b.used_at desc;

-- Reiniciar la 2FA de un usuario (para repetir la demo)
-- delete from mfa_configurations where user_id = (select id from users where username = 'ana');
-- delete from backup_codes       where user_id = (select id from users where username = 'ana');
