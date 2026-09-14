-- 0001_airspace_zone.sql
-- Persistence for the sovereign NFZ / GACA sync channel.
--
-- Milestone 0. Establishes the `AirspaceZone` entity (Master Plan Sec.4 data model)
-- and the feed-state record that makes the freshness window durable across a
-- restart -- a process that restarts must come back up STALE, not empty-and-
-- optimistic.
--
-- Deliberately NOT in this migration:
--   * `IncidentZone`. It is the root authorization envelope and is still open as
--     TM-01. Defining it half-way here would invite code to depend on a shape that
--     has not been reviewed.
--   * Any mission, command, or flight-plan table. Those are Milestone 1, and
--     Master Plan Sec.6 forbids flight-capable code before the Milestone-0 gate closes.
--
-- Requires: PostgreSQL 14+ with PostGIS 3.x.

BEGIN;

CREATE EXTENSION IF NOT EXISTS postgis;

-- ---------------------------------------------------------------------------
-- Enumerations. Mirrored from dronez.airspace.schema; an unrecognised value must
-- fail at the database boundary too, not just in application code.
-- ---------------------------------------------------------------------------

CREATE TYPE airspace_zone_type AS ENUM (
    'prohibited',
    'restricted',
    'danger',
    'temporary_restriction',
    'aerodrome',
    'critical_infrastructure',
    'emergency_management',
    'military'
);

CREATE TYPE airspace_severity AS ENUM ('blocking', 'advisory');

-- ---------------------------------------------------------------------------
-- Feed state: one row per issuing authority.
-- ---------------------------------------------------------------------------

CREATE TABLE nfz_feed_state (
    authority              TEXT PRIMARY KEY,
    last_sequence          BIGINT      NOT NULL,
    last_bulletin_id       TEXT        NOT NULL,
    last_sync_utc          TIMESTAMPTZ NOT NULL,
    bulletin_valid_until   TIMESTAMPTZ NOT NULL,
    signing_key_id         TEXT        NOT NULL,
    consecutive_failures   INTEGER     NOT NULL DEFAULT 0,

    -- Monotonic sequence is the replay defence (Zero-Trust Sec.4.3). Enforced here as
    -- well as in the client so a direct write cannot roll the feed backwards.
    CONSTRAINT nfz_feed_state_sequence_non_negative CHECK (last_sequence >= 0),
    CONSTRAINT nfz_feed_state_failures_non_negative CHECK (consecutive_failures >= 0)
);

COMMENT ON TABLE nfz_feed_state IS
    'Sync state per issuing authority. Durable so a restarted process resumes as '
    'stale rather than treating an empty cache as clear airspace.';

CREATE OR REPLACE FUNCTION nfz_feed_state_forbid_sequence_rollback()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.last_sequence <= OLD.last_sequence THEN
        RAISE EXCEPTION
            'refusing to roll NFZ feed % back from sequence % to %; replay rejected',
            OLD.authority, OLD.last_sequence, NEW.last_sequence
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER nfz_feed_state_no_rollback
    BEFORE UPDATE ON nfz_feed_state
    FOR EACH ROW
    WHEN (NEW.last_sequence IS DISTINCT FROM OLD.last_sequence)
    EXECUTE FUNCTION nfz_feed_state_forbid_sequence_rollback();

-- ---------------------------------------------------------------------------
-- Airspace zones.
-- ---------------------------------------------------------------------------

CREATE TABLE airspace_zone (
    zone_id                 TEXT PRIMARY KEY,
    authority               TEXT NOT NULL
                                REFERENCES nfz_feed_state (authority)
                                ON DELETE RESTRICT,
    designation             TEXT NOT NULL,
    zone_type               airspace_zone_type NOT NULL,
    severity                airspace_severity  NOT NULL,

    -- SRID 4326 (WGS-84). PostGIS is authoritative for geometry from Milestone 1;
    -- dronez.airspace.geometry is a conservative stand-in until then (TM-06).
    geometry                GEOGRAPHY(POLYGON, 4326) NOT NULL,

    altitude_floor_m_agl    DOUBLE PRECISION NOT NULL,
    altitude_ceiling_m_agl  DOUBLE PRECISION NOT NULL,
    effective_from          TIMESTAMPTZ NOT NULL,
    effective_until         TIMESTAMPTZ,
    source_ref              TEXT NOT NULL,

    -- UNTRUSTED free text controlled by an external party. Display only, escaped at
    -- render time, never placed in an LLM context without an untrusted-content
    -- label (Zero-Trust Sec.4.2, threat T-38).
    remarks                 TEXT NOT NULL DEFAULT '',

    ingested_from_bulletin  TEXT NOT NULL,
    ingested_at_utc         TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT airspace_zone_altitude_ordered
        CHECK (altitude_floor_m_agl < altitude_ceiling_m_agl),
    CONSTRAINT airspace_zone_altitude_plausible
        CHECK (altitude_floor_m_agl >= -500 AND altitude_ceiling_m_agl <= 20000),
    CONSTRAINT airspace_zone_window_ordered
        CHECK (effective_until IS NULL OR effective_until > effective_from),
    -- Reject a degenerate polygon at the storage boundary as well as in the parser.
    CONSTRAINT airspace_zone_geometry_valid
        CHECK (ST_IsValid(geometry::geometry))
);

COMMENT ON COLUMN airspace_zone.remarks IS
    'UNTRUSTED external free text. Display only; never interpreted as an instruction.';
COMMENT ON COLUMN airspace_zone.designation IS
    'UNTRUSTED external free text. Display only; never interpreted as an instruction.';

-- Spatial index: the clearance path filters by geometry on every dispatch.
CREATE INDEX airspace_zone_geometry_gist ON airspace_zone USING GIST (geometry);

-- The clearance query filters active, blocking zones first.
CREATE INDEX airspace_zone_active_lookup
    ON airspace_zone (severity, effective_from, effective_until);

CREATE INDEX airspace_zone_authority ON airspace_zone (authority);

-- ---------------------------------------------------------------------------
-- Append-only ingestion audit.
--
-- Zero-Trust Sec.8.1 requires an immutable audit trail. This table is the in-database
-- half only; the primary control is asynchronous shipping to WORM object storage
-- with object lock, where no identity holds delete or modify permission.
--
-- Append-only is enforced by GRANT, not by this file: the application role receives
-- INSERT and SELECT and no UPDATE or DELETE on this table. Those grants live in the
-- Terraform module under infra/ so that database privileges are version-controlled
-- infrastructure (Zero-Trust Sec.6.1), never a manual console change.
-- ---------------------------------------------------------------------------

CREATE TABLE nfz_bulletin_audit (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    received_at_utc     TIMESTAMPTZ NOT NULL DEFAULT now(),
    authority           TEXT        NOT NULL,
    bulletin_id         TEXT,
    sequence            BIGINT,
    signing_key_id      TEXT,
    accepted            BOOLEAN     NOT NULL,
    -- Machine-readable rejection reason. A rejected bulletin is a security signal and
    -- is recorded, never silently dropped.
    rejection_reason    TEXT,
    payload_sha256      TEXT        NOT NULL,
    payload_bytes       INTEGER     NOT NULL,

    CONSTRAINT nfz_bulletin_audit_reason_present
        CHECK (accepted OR rejection_reason IS NOT NULL)
);

CREATE INDEX nfz_bulletin_audit_received ON nfz_bulletin_audit (received_at_utc DESC);
CREATE INDEX nfz_bulletin_audit_rejections
    ON nfz_bulletin_audit (authority, received_at_utc DESC)
    WHERE NOT accepted;

COMMIT;
