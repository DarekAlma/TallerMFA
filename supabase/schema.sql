-- =====================================================================
-- TallerMFA – Esquema de base de datos (Supabase / PostgreSQL)
-- Ejecutar completo en: Supabase Dashboard > SQL Editor > New query > Run
-- =====================================================================

create extension if not exists pgcrypto;  -- gen_random_uuid()

-- 1. Usuarios (factor 1: usuario + contraseña con hash bcrypt)
create table if not exists public.users (
    id            uuid primary key default gen_random_uuid(),
    username      text not null unique
                  check (username ~ '^[a-z0-9_.\-]{3,40}$'),
    password_hash text not null,
    created_at    timestamptz not null default now()
);

-- 2. Configuración 2FA (máquina de estados del Process Manager)
--    Sin fila            => NOT_CONFIGURED
--    PENDING_VERIFICATION => QR generado, aún no se ha enviado el primer código válido
--    ACTIVE               => 2FA obligatoria en cada login
create table if not exists public.mfa_configurations (
    user_id          uuid primary key references public.users(id) on delete cascade,
    secret_encrypted text not null,                -- semilla Base32 cifrada con Fernet
    status           text not null default 'PENDING_VERIFICATION'
                     check (status in ('PENDING_VERIFICATION', 'ACTIVE')),
    created_at       timestamptz not null default now(),
    activated_at     timestamptz,
    updated_at       timestamptz not null default now(),
    constraint active_requires_activated_at
        check (status <> 'ACTIVE' or activated_at is not null)
);

-- 3. Códigos de respaldo de un solo uso (BackupCodeStrategy). Solo se guarda el hash.
create table if not exists public.backup_codes (
    id         uuid primary key default gen_random_uuid(),
    user_id    uuid not null references public.users(id) on delete cascade,
    code_hash  text not null,
    used_at    timestamptz,
    created_at timestamptz not null default now(),
    unique (user_id, code_hash)
);
create index if not exists backup_codes_user_unused_idx
    on public.backup_codes (user_id) where used_at is null;

-- 4. Bitácora de auditoría (enlaza cada evento con su flow run de Prefect)
create table if not exists public.auth_audit_log (
    id          bigint generated always as identity primary key,
    user_id     uuid references public.users(id) on delete set null,
    event       text not null,
    detail      text,
    flow_run_id text,
    created_at  timestamptz not null default now()
);
create index if not exists auth_audit_log_user_idx on public.auth_audit_log (user_id, created_at desc);

-- 5. Seguridad: RLS activado SIN políticas => las llaves públicas (anon/publishable)
--    no pueden leer ni escribir nada. Solo el backend, con la llave secreta
--    (service_role / sb_secret_...), accede a estas tablas.
alter table public.users              enable row level security;
alter table public.mfa_configurations enable row level security;
alter table public.backup_codes       enable row level security;
alter table public.auth_audit_log     enable row level security;

revoke all on public.users, public.mfa_configurations, public.backup_codes, public.auth_audit_log
    from anon, authenticated;
