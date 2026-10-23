-- COLAW Fantasy: site-wide transfer/roster locks + manual player points.
-- Run once in Supabase SQL Editor as the project owner.
-- This does not alter wallet balances, squads, existing scores, or player prices.

CREATE TABLE IF NOT EXISTS public.fantasy_competition_controls (
  id integer PRIMARY KEY CHECK (id = 1),
  transfers_locked boolean NOT NULL DEFAULT false,
  roster_locked boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid REFERENCES auth.users(id)
);

INSERT INTO public.fantasy_competition_controls (id, transfers_locked, roster_locked)
VALUES (1, false, false)
ON CONFLICT (id) DO NOTHING;

ALTER TABLE public.fantasy_competition_controls ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Authenticated users can read competition controls"
ON public.fantasy_competition_controls;
CREATE POLICY "Authenticated users can read competition controls"
ON public.fantasy_competition_controls
FOR SELECT TO authenticated USING (true);

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.fantasy_competition_controls
FROM anon, authenticated;
GRANT SELECT ON public.fantasy_competition_controls TO authenticated;

CREATE OR REPLACE FUNCTION public.admin_set_competition_control(
  p_control text,
  p_locked boolean
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
DECLARE
  v_admin uuid := auth.uid();
BEGIN
  IF v_admin IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = v_admin AND p.is_admin = true AND p.is_approved = true
  ) THEN
    RAISE EXCEPTION 'Approved administrator access is required.';
  END IF;

  IF p_control NOT IN ('transfers_locked', 'roster_locked') THEN
    RAISE EXCEPTION 'Unknown competition control.';
  END IF;

  UPDATE public.fantasy_competition_controls
  SET transfers_locked = CASE WHEN p_control = 'transfers_locked' THEN p_locked ELSE transfers_locked END,
      roster_locked = CASE WHEN p_control = 'roster_locked' THEN p_locked ELSE roster_locked END,
      updated_at = now(),
      updated_by = v_admin
  WHERE id = 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Competition controls have not been initialized.';
  END IF;

  RETURN jsonb_build_object('success', true, 'control', p_control, 'locked', p_locked);
END;
$function$;

REVOKE ALL ON FUNCTION public.admin_set_competition_control(text, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.admin_set_competition_control(text, boolean) TO authenticated;

-- Enforce transfer lock at the database transaction boundary. If a buy/sell
-- RPC inserts its history row while transfers are locked, the whole transaction
-- is rolled back.
CREATE OR REPLACE FUNCTION public.guard_fantasy_transfer_lock()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.fantasy_competition_controls c
    WHERE c.id = 1 AND c.transfers_locked = true
  ) THEN
    RAISE EXCEPTION 'Fantasy transfers are temporarily locked by the administrator.';
  END IF;
  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS enforce_fantasy_transfer_lock
ON public.fantasy_transfer_history;
CREATE TRIGGER enforce_fantasy_transfer_lock
BEFORE INSERT ON public.fantasy_transfer_history
FOR EACH ROW EXECUTE FUNCTION public.guard_fantasy_transfer_lock();

-- Freeze player roster writes while roster lock is enabled. This also applies
-- to privileged SECURITY DEFINER player-management RPCs.
CREATE OR REPLACE FUNCTION public.guard_fantasy_roster_lock()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.fantasy_competition_controls c
    WHERE c.id = 1 AND c.roster_locked = true
  ) THEN
    RAISE EXCEPTION 'Player management is locked by the administrator.';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS enforce_fantasy_roster_lock
ON public.players;
CREATE TRIGGER enforce_fantasy_roster_lock
BEFORE INSERT OR UPDATE OR DELETE ON public.players
FOR EACH ROW EXECUTE FUNCTION public.guard_fantasy_roster_lock();

-- Manual per-player points, per gameweek.
CREATE TABLE IF NOT EXISTS public.fantasy_player_gameweek_points (
  gameweek_id bigint NOT NULL REFERENCES public.fantasy_gameweeks(id) ON DELETE CASCADE,
  player_id bigint NOT NULL REFERENCES public.players(id) ON DELETE CASCADE,
  points integer NOT NULL CHECK (points >= 0 AND points <= 10000),
  entered_by uuid NOT NULL REFERENCES auth.users(id),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gameweek_id, player_id)
);

ALTER TABLE public.fantasy_player_gameweek_points ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Authenticated users can read player gameweek points"
ON public.fantasy_player_gameweek_points;
CREATE POLICY "Authenticated users can read player gameweek points"
ON public.fantasy_player_gameweek_points
FOR SELECT TO authenticated USING (true);

REVOKE INSERT, UPDATE, DELETE, TRUNCATE
ON public.fantasy_player_gameweek_points FROM anon, authenticated;
GRANT SELECT ON public.fantasy_player_gameweek_points TO authenticated;

CREATE OR REPLACE FUNCTION public.admin_save_player_gameweek_points(
  p_gameweek_id bigint,
  p_player_id bigint,
  p_points integer
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO ''
AS $function$
DECLARE
  v_admin uuid := auth.uid();
  v_week public.fantasy_gameweeks%rowtype;
BEGIN
  IF v_admin IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.profiles p
    WHERE p.id = v_admin AND p.is_admin = true AND p.is_approved = true
  ) THEN
    RAISE EXCEPTION 'Approved administrator access is required.';
  END IF;

  IF p_points IS NULL OR p_points < 0 OR p_points > 10000 THEN
    RAISE EXCEPTION 'Player points must be between 0 and 10000.';
  END IF;

  SELECT * INTO v_week
  FROM public.fantasy_gameweeks
  WHERE id = p_gameweek_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Gameweek not found.';
  END IF;

  IF v_week.status NOT IN ('locked', 'completed') THEN
    RAISE EXCEPTION 'Lock the gameweek before entering player points.';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM public.players p WHERE p.id = p_player_id) THEN
    RAISE EXCEPTION 'Player not found.';
  END IF;

  INSERT INTO public.fantasy_player_gameweek_points
    (gameweek_id, player_id, points, entered_by, updated_at)
  VALUES
    (p_gameweek_id, p_player_id, p_points, v_admin, now())
  ON CONFLICT (gameweek_id, player_id)
  DO UPDATE SET points = EXCLUDED.points, entered_by = EXCLUDED.entered_by, updated_at = now();

  RETURN jsonb_build_object(
    'success', true,
    'gameweek_id', p_gameweek_id,
    'player_id', p_player_id,
    'points', p_points
  );
END;
$function$;

REVOKE ALL ON FUNCTION public.admin_save_player_gameweek_points(bigint, bigint, integer) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.admin_save_player_gameweek_points(bigint, bigint, integer) TO authenticated;
