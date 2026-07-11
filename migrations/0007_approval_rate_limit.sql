-- =============================================================================
-- Migration: 0007_approval_rate_limit.sql
--
-- Adds the one helper the 04 approval Edge Function needs, and confirms the
-- approval RPCs are callable by service_role (the only role 04 uses).
--
-- Why an RPC and not a direct insert: private.rate_limits lives in the private
-- schema, which is deliberately OFF the PostgREST surface (T7 — service_role
-- itself gets a 404 on it). The Edge Function speaks only PostgREST, so it
-- cannot write that table directly. This security-definer function is the one
-- narrow, audited door in: it records the attempt and reports whether the
-- caller is still within the limit. Nothing else about private leaks.
--
-- Fails safe on a missing or malformed IP by bucketing under 0.0.0.0, rather
-- than erroring (which would break approvals) or skipping the limiter (which
-- would let a header-stripping attacker spray freely).
-- =============================================================================

begin;

create or replace function public.check_approval_rate_limit(
  p_ip             text,
  p_endpoint       text,
  p_max            integer default 10,
  p_window_minutes integer default 10
) returns boolean
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_ip    inet;
  v_count integer;
begin
  begin
    v_ip := coalesce(nullif(p_ip, ''), '0.0.0.0')::inet;
  exception when others then
    v_ip := '0.0.0.0'::inet;   -- unparseable IP -> shared bucket, still limited
  end;

  insert into private.rate_limits (ip, endpoint) values (v_ip, p_endpoint);

  select count(*) into v_count
    from private.rate_limits
   where ip = v_ip
     and endpoint = p_endpoint
     and request_at > now() - make_interval(mins => greatest(p_window_minutes, 1));

  return v_count <= greatest(p_max, 1);   -- true = still allowed, false = blocked
end;
$function$;

-- Callable only by the Edge Function's role. Not agents, not anon, not n8n.
revoke all on function public.check_approval_rate_limit(text, text, integer, integer) from public;
grant execute on function public.check_approval_rate_limit(text, text, integer, integer) to service_role;

-- The Edge Function (service_role) must be able to call the approval RPCs.
-- Idempotent — harmless if 0003 already granted these.
grant execute on function public.redeem_approval_token(uuid, inet)             to service_role;
grant execute on function public.reject_approval_token(uuid, text, text, inet) to service_role;

commit;

-- =============================================================================
-- VERIFY (run separately, not part of the transaction):
--
--   set role service_role;
--   select public.check_approval_rate_limit('1.2.3.4', 'approve');  -- t (1st)
--   reset role;
--
-- And confirm an agent CANNOT call it:
--   the isolation test (test-isolation.sh) already asserts approval RPCs are
--   not callable by authenticated — re-run it after this migration.
-- =============================================================================
