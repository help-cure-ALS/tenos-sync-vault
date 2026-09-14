// routes.ts
import type { FastifyInstance } from "fastify";
import { createHash, hkdfSync, randomUUID, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { pool } from "./db";
import nacl = require("tweetnacl");
import { b64ToBytes, bytesToB64, utf8Bytes, ed25519Verify } from "./crypto_util";

const MAX_BATCH = Number(process.env.MAX_BATCH_EVENTS ?? "500");
const MAX_PULL = Number(process.env.MAX_PULL_LIMIT ?? "2000");

// Hard limit for device count (audit-friendly)
// Devices per subject. Counts only ACTIVE devices (revoked ones free
// their slot). Generous by default — the limit exists to cap abuse,
// not to constrain households with many devices. Override via env.
const MAX_DEVICES_PER_SUBJECT = Number(process.env.MAX_DEVICES_PER_SUBJECT ?? "50");

// Challenge TTL in seconds
const CHALLENGE_TTL_SECONDS = Number(process.env.AUTH_CHALLENGE_TTL_SECONDS ?? "60");
const KEY_FPR_LENGTH = 16;
const BUNDLE_CIPHER_HKDF_SALT = "hca/bundle-cipher-v1";
const BUNDLE_CIPHER_KEY_BYTES = 32;
const BUNDLE_CIPHER_KID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

// App version gate: clients below min_version must update via the store.
// Operational metadata only — no subject, device, or payload relation.
// Empty/unset env values disable the gate for that platform.
function appConfigValue(name: string): string | null {
    const value = process.env[name]?.trim();
    return value ? value : null;
}

const EventSchema = z.object({
    event_id: z.string().uuid(),
    device_id: z.string().uuid(),
    lamport: z.number().int().nonnegative(),
    device_seq: z.number().int().nonnegative().optional(),

    entity_type: z.string().min(1).max(64).optional(),
    entity_id: z.string().uuid().optional(),
    op_kind: z.enum(["create", "update", "delete"]).optional(),

    client_created_at: z.string().datetime().optional(),

    alg: z.string().min(3).max(64),
    nonce_b64: z.string().min(8),
    ciphertext_b64: z.string().min(8),
    ciphertext_hash_b64: z.string().min(8)
});

const BatchSchema = z.object({
    events: z.array(EventSchema).min(1).max(MAX_BATCH)
});

const RegisterSchema = z.object({
    subject_id: z.string().uuid(),
    public_key_b64: z.string().min(8), // 32 bytes base64
    signature_b64: z.string().min(8) // 64 bytes base64
});

const ChallengeSchema = z.object({
    subject_id: z.string().uuid(),
    device_id: z.string().uuid()
});

const IssueSchema = z.object({
    subject_id: z.string().uuid(),
    device_id: z.string().uuid(),
    challenge_id: z.string().uuid(),
    signature_b64: z.string().min(8)
});

// v2 cursor: stable order by (server_received_at, event_id)
const CursorSchema = z.object({
    since_ts: z.string().datetime(),
    since_id: z.string().uuid()
});

const BundleCipherKidParamsSchema = z.object({
    kid: z.string().min(1).max(128).regex(BUNDLE_CIPHER_KID_RE)
});

// Grant a recipient device its own public key and capability, signed by the subject root key.
const AuthorizeDeviceSchema = z.object({
    subject_id: z.string().uuid(),
    target_device_id: z.string().uuid(),
    target_public_key_b64: z.string().min(8),
    capability: z.enum(["read_write"]),
    signature_b64: z.string().min(8)
});

// Disable another device of the same subject. This is owner-only and uses a sync JWT.
const DisableDeviceSchema = z.object({
    target_device_id: z.string().uuid()
});

// Pre-auth rendezvous mailbox.
const RendezvousTokenParamsSchema = z.object({
    token: z.string().min(16).max(128).regex(/^[A-Za-z0-9._-]+$/)
});
const RendezvousPostSchema = z.object({
    slot: z.enum(["offer", "reply"]),
    payload: z.record(z.any())
});

const RENDEZVOUS_TTL_SECONDS = Number(process.env.RENDEZVOUS_TTL_SECONDS ?? "300");
const RENDEZVOUS_MAX_PAYLOAD_BYTES = Number(process.env.RENDEZVOUS_MAX_PAYLOAD_BYTES ?? "8192");

// Used for stable signing message formats (audit clarity)
function msgRegister(subjectId: string, pubKeyB64: string) {
    return utf8Bytes(`register|${ subjectId }|${ pubKeyB64 }`);
}

function msgIssue(subjectId: string, deviceId: string, challengeId: string, challengeB64: string) {
    return utf8Bytes(`issue|${ subjectId }|${ deviceId }|${ challengeId }|${ challengeB64 }`);
}

// Deterministic message a subject root key signs to authorize a recipient device.
function msgAuthorize(subjectId: string, targetDeviceId: string, targetPubKeyB64: string, capability: string) {
    return utf8Bytes(`authorize|${ subjectId }|${ targetDeviceId }|${ targetPubKeyB64 }|${ capability }`);
}

function keyFingerprint(bytes: Uint8Array | Buffer): string {
    return createHash("sha256").update(bytes).digest("base64url").slice(0, KEY_FPR_LENGTH);
}

function requireAppToken(req: any, reply: any): boolean {
    const appToken = process.env.APP_ISSUE_TOKEN;
    if (!appToken) {
        req.log.error("APP_ISSUE_TOKEN missing");
        reply.code(500).send({ error: "server_misconfigured" });
        return false;
    }
    const provided = req.headers["x-app-token"];
    if (typeof provided !== "string" || provided !== appToken) {
        reply.code(401).send({ error: "unauthorized" });
        return false;
    }
    return true;
}

function safeSecretEqual(provided: string, expected: string): boolean {
    const providedBytes = Buffer.from(provided, "utf8");
    const expectedBytes = Buffer.from(expected, "utf8");
    return providedBytes.length === expectedBytes.length && timingSafeEqual(providedBytes, expectedBytes);
}

function toNumber(value: unknown): number {
    const n = Number(value ?? 0);
    return Number.isFinite(n) ? n : 0;
}

function requireAdminStatsToken(req: any, reply: any): boolean {
    const adminToken = process.env.ADMIN_STATS_TOKEN?.trim() ?? "";
    if (!adminToken) {
        req.log.error("ADMIN_STATS_TOKEN missing");
        reply.code(500).send({ error: "server_misconfigured" });
        return false;
    }

    const authorization = req.headers.authorization;
    if (typeof authorization !== "string" || !authorization.startsWith("Bearer ")) {
        reply.code(401).send({ error: "unauthorized" });
        return false;
    }

    const provided = authorization.slice("Bearer ".length).trim();
    if (!provided || !safeSecretEqual(provided, adminToken)) {
        reply.code(401).send({ error: "unauthorized" });
        return false;
    }

    return true;
}

type BundleCipherMaterial = {
    kid: string;
    keyB64: string;
};

function deriveBundleCipherKeyB64(secret: string): string {
    const derived = hkdfSync(
        "sha256",
        Buffer.from(secret, "utf8"),
        Buffer.from(BUNDLE_CIPHER_HKDF_SALT, "utf8"),
        Buffer.alloc(0),
        BUNDLE_CIPHER_KEY_BYTES
    );
    return Buffer.from(derived).toString("base64");
}

function parseBundleCipherMaterial(kid: string | undefined, secret: string | undefined): BundleCipherMaterial | null {
    const trimmedKid = kid?.trim() ?? "";
    const trimmedSecret = secret?.trim() ?? "";

    if (!trimmedKid && !trimmedSecret) {
        return null;
    }
    if (!trimmedKid || !trimmedSecret) {
        throw new Error("bundle_cipher_pair_incomplete");
    }
    if (!BUNDLE_CIPHER_KID_RE.test(trimmedKid)) {
        throw new Error("bundle_cipher_kid_invalid");
    }
    if (trimmedSecret.length < 8) {
        throw new Error("bundle_cipher_secret_invalid");
    }

    return {
        kid: trimmedKid,
        keyB64: deriveBundleCipherKeyB64(trimmedSecret)
    };
}

function loadBundleCipherConfig(req: any, reply: any): { current: BundleCipherMaterial; previous: BundleCipherMaterial | null } | null {
    try {
        const current = parseBundleCipherMaterial(
            process.env.BUNDLE_CIPHER_CURRENT_KID,
            process.env.BUNDLE_CIPHER_CURRENT_SECRET
        );
        if (!current) {
            req.log.error("BUNDLE_CIPHER_CURRENT_* missing");
            reply.code(503).send({ error: "bundle_cipher_unavailable" });
            return null;
        }

        const previous = parseBundleCipherMaterial(
            process.env.BUNDLE_CIPHER_PREVIOUS_KID,
            process.env.BUNDLE_CIPHER_PREVIOUS_SECRET
        );

        return { current, previous };
    } catch (error: any) {
        req.log.error({ err: error }, "Invalid bundle cipher configuration");
        reply.code(503).send({ error: "bundle_cipher_unavailable" });
        return null;
    }
}

async function loadSubject(subjectId: string) {
    const res = await pool.query(
        `select subject_id,
                public_key,
                token_version,
                disabled_at,
                max_events_total,
                max_bytes_total,
                max_events_day,
                max_bytes_day,
                events_total,
                bytes_total,
                day_date,
                events_day,
                bytes_day
         from subjects
         where subject_id = $1`,
        [subjectId]
    );
    return res.rows[0] ?? null;
}

async function enforceSubjectActiveAndTokenVersion(req: any, reply: any) {
    const subjectId = req.user.sub as string;
    const tokenTv = Number((req.user as any).tv ?? 0);
    const tokenDeviceId = req.user.device_id as string;

    if (typeof tokenDeviceId !== "string" || tokenDeviceId.length < 8) {
        return reply.code(401).send({ error: "invalid_token" });
    }

    const s = await loadSubject(subjectId);
    if (!s) {
        return reply.code(401).send({ error: "unknown_subject" });
    }
    if (s.disabled_at) {
        return reply.code(403).send({ error: "subject_disabled" });
    }
    if (tokenTv !== Number(s.token_version)) {
        return reply.code(401).send({ error: "token_revoked" });
    }

    const d = await pool.query(
        `select status, capability
         from devices
         where subject_id = $1
           and device_id = $2`,
        [subjectId, tokenDeviceId]
    );
    if (d.rowCount === 0) {
        return reply.code(403).send({ error: "device_not_registered" });
    }
    if (d.rows[0].status !== "active") {
        return reply.code(403).send({ error: "device_disabled" });
    }

    // Expose the device capability to route handlers for write and owner gating.
    (s as any).device_capability = d.rows[0].capability ?? "owner";

    return s; // subject row for quotas, etc.
}

// Owner actions are owner-only. read_write devices may push events but not do owner actions.
function requireOwner(subject: any, reply: any): boolean {
    if ((subject as any).device_capability !== "owner") {
        reply.code(403).send({ error: "owner_required" });
        return false;
    }
    return true;
}

function canWriteEvents(subject: any): boolean {
    const cap = (subject as any).device_capability;
    return cap === "owner" || cap === "read_write";
}

function decodeEventSizes(e: any) {
    const nonce = Buffer.from(e.nonce_b64, "base64");
    const ciphertext = Buffer.from(e.ciphertext_b64, "base64");
    const hash = Buffer.from(e.ciphertext_hash_b64, "base64");
    const bytes = nonce.length + ciphertext.length + hash.length;
    return { nonce, ciphertext, hash, bytes };
}

// Stable ISO string from DB (UTC, MICROSECOND precision).
// This prevents cursor loops caused by driver Date conversion / rounding / locale differences.
//
// Microseconds are required: server_received_at defaults to now(), which is
// the transaction timestamp — every row of one /events/batch insert shares
// the exact same microsecond value. A millisecond-truncated cursor compared
// against the full-precision column re-matches the whole batch on the next
// page (identical page, identical next cursor), which clients detect as
// "no progress" and abort — leaving the pull incomplete.
const SERVER_RECEIVED_AT_ISO_SQL =
    `to_char(server_received_at at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

export async function routes(app: FastifyInstance) {
    app.get("/healthz", async () => ({ ok: true }));

    // Public, unauthenticated. The mobile app checks this on cold start and
    // foreground; values are maintained via env vars (restart to apply).
    app.get(
        "/app-config",
        {
            config: {
                rateLimit: { max: 60, timeWindow: "1 minute" }
            }
        },
        async () => ({
            min_version: {
                ios: appConfigValue("MIN_APP_VERSION_IOS"),
                android: appConfigValue("MIN_APP_VERSION_ANDROID")
            },
            store_url: {
                ios: appConfigValue("APP_STORE_URL_IOS"),
                android: appConfigValue("APP_STORE_URL_ANDROID")
            }
        })
    );

    app.get(
        "/admin/stats/summary",
        {
            config: {
                rateLimit: { max: 30, timeWindow: "1 minute" }
            }
        },
        async (req: any, reply) => {
            if (!requireAdminStatsToken(req, reply)) {
                return;
            }

            try {
                const { rows } = await pool.query(
                    `
                    with
                    patient_counts as (
                        select
                            count(*)::bigint as total,
                            count(*) filter (where disabled_at is null) as active,
                            count(*) filter (where disabled_at is not null) as disabled,
                            coalesce(sum(events_total), 0)::bigint as accounted_events_total,
                            coalesce(sum(bytes_total), 0)::bigint as accounted_bytes_total
                        from subjects
                    ),
                    patient_activity as (
                        select
                            count(distinct subject_id) filter (where occurred_at >= now() - interval '24 hours') as active_24h,
                            count(distinct subject_id) filter (where occurred_at >= now() - interval '7 days') as active_7d,
                            count(distinct subject_id) filter (where occurred_at >= now() - interval '30 days') as active_30d
                        from (
                            select e.subject_id, e.server_received_at as occurred_at
                            from events e
                            join subjects s on s.subject_id = e.subject_id and s.disabled_at is null
                            where e.server_received_at >= now() - interval '30 days'
                            union all
                            select d.subject_id, d.last_seen_at as occurred_at
                            from devices d
                            join subjects s on s.subject_id = d.subject_id and s.disabled_at is null
                            where d.last_seen_at >= now() - interval '30 days'
                        ) activity
                    ),
                    device_counts as (
                        select
                            count(*)::bigint as total,
                            count(*) filter (where status = 'active') as active,
                            count(*) filter (where status = 'disabled') as disabled,
                            count(*) filter (where capability = 'owner') as owner,
                            count(*) filter (where capability = 'read_write') as read_write,
                            count(*) filter (where last_seen_at >= now() - interval '24 hours') as active_24h,
                            count(*) filter (where last_seen_at >= now() - interval '7 days') as active_7d,
                            count(*) filter (where last_seen_at >= now() - interval '30 days') as active_30d
                        from devices
                    ),
                    device_distribution as (
                        select
                            coalesce(avg(device_count), 0)::numeric as avg_per_patient,
                            coalesce(percentile_cont(0.5) within group (order by device_count), 0)::numeric as p50_per_patient,
                            coalesce(percentile_cont(0.95) within group (order by device_count), 0)::numeric as p95_per_patient
                        from (
                            select s.subject_id, count(d.device_id)::numeric as device_count
                            from subjects s
                            left join devices d on d.subject_id = s.subject_id
                            group by s.subject_id
                        ) per_patient
                    ),
                    event_counts as (
                        select
                            count(*)::bigint as total,
                            count(*) filter (where server_received_at >= now() - interval '24 hours') as last_24h,
                            count(*) filter (where server_received_at >= now() - interval '7 days') as last_7d,
                            count(*) filter (where server_received_at >= now() - interval '30 days') as last_30d,
                            coalesce(sum(octet_length(nonce) + octet_length(ciphertext) + octet_length(ciphertext_hash)), 0)::bigint as encrypted_bytes
                        from events
                    ),
                    rendezvous_counts as (
                        select
                            count(*) filter (where slot = 'offer' and expires_at > now()) as open_offers,
                            count(*) filter (where slot = 'reply' and expires_at > now()) as open_replies,
                            count(*) filter (where expires_at <= now()) as expired
                        from rendezvous
                    ),
                    challenge_counts as (
                        select
                            count(*) filter (where used_at is null and expires_at > now()) as open,
                            count(*) filter (where used_at is not null) as used,
                            count(*) filter (where used_at is null and expires_at <= now()) as expired
                        from auth_challenges
                    ),
                    quota_counts as (
                        select
                            count(*) filter (
                                where disabled_at is null
                                  and max_events_total > 0
                                  and events_total::numeric / max_events_total::numeric >= 0.8
                            ) as patients_above_80_percent_events,
                            count(*) filter (
                                where disabled_at is null
                                  and max_bytes_total > 0
                                  and bytes_total::numeric / max_bytes_total::numeric >= 0.8
                            ) as patients_above_80_percent_bytes
                        from subjects
                    )
                    select
                        now() as generated_at,
                        patient_counts.*,
                        patient_activity.active_24h as patients_active_24h,
                        patient_activity.active_7d as patients_active_7d,
                        patient_activity.active_30d as patients_active_30d,
                        device_counts.total as devices_total,
                        device_counts.active as devices_active,
                        device_counts.disabled as devices_disabled,
                        device_counts.owner as devices_owner,
                        device_counts.read_write as devices_read_write,
                        device_counts.active_24h as devices_active_24h,
                        device_counts.active_7d as devices_active_7d,
                        device_counts.active_30d as devices_active_30d,
                        device_distribution.avg_per_patient as devices_avg_per_patient,
                        device_distribution.p50_per_patient as devices_p50_per_patient,
                        device_distribution.p95_per_patient as devices_p95_per_patient,
                        event_counts.total as events_total,
                        event_counts.last_24h as events_last_24h,
                        event_counts.last_7d as events_last_7d,
                        event_counts.last_30d as events_last_30d,
                        event_counts.encrypted_bytes as events_encrypted_bytes,
                        rendezvous_counts.open_offers as pairing_open_offers,
                        rendezvous_counts.open_replies as pairing_open_replies,
                        rendezvous_counts.expired as pairing_expired,
                        challenge_counts.open as auth_challenges_open,
                        challenge_counts.used as auth_challenges_used,
                        challenge_counts.expired as auth_challenges_expired,
                        quota_counts.patients_above_80_percent_events,
                        quota_counts.patients_above_80_percent_bytes
                    from patient_counts, patient_activity, device_counts, device_distribution,
                         event_counts, rendezvous_counts, challenge_counts, quota_counts
                    `
                );

                const row = rows[0] ?? {};
                const patientsTotal = toNumber(row.total);
                const accountedBytesTotal = toNumber(row.accounted_bytes_total);

                reply.header("Cache-Control", "no-store");
                return {
                    generated_at: row.generated_at,
                    patients: {
                        total: patientsTotal,
                        active: toNumber(row.active),
                        disabled: toNumber(row.disabled),
                        active_24h: toNumber(row.patients_active_24h),
                        active_7d: toNumber(row.patients_active_7d),
                        active_30d: toNumber(row.patients_active_30d)
                    },
                    devices: {
                        total: toNumber(row.devices_total),
                        active: toNumber(row.devices_active),
                        disabled: toNumber(row.devices_disabled),
                        owner: toNumber(row.devices_owner),
                        read_write: toNumber(row.devices_read_write),
                        active_24h: toNumber(row.devices_active_24h),
                        active_7d: toNumber(row.devices_active_7d),
                        active_30d: toNumber(row.devices_active_30d),
                        avg_per_patient: toNumber(row.devices_avg_per_patient),
                        p50_per_patient: toNumber(row.devices_p50_per_patient),
                        p95_per_patient: toNumber(row.devices_p95_per_patient)
                    },
                    events: {
                        total: toNumber(row.events_total),
                        accounted_total: toNumber(row.accounted_events_total),
                        last_24h: toNumber(row.events_last_24h),
                        last_7d: toNumber(row.events_last_7d),
                        last_30d: toNumber(row.events_last_30d)
                    },
                    storage: {
                        encrypted_bytes: toNumber(row.events_encrypted_bytes),
                        accounted_bytes: accountedBytesTotal,
                        avg_accounted_bytes_per_patient: patientsTotal > 0
                            ? Math.round(accountedBytesTotal / patientsTotal)
                            : 0
                    },
                    pairing: {
                        open_offers: toNumber(row.pairing_open_offers),
                        open_replies: toNumber(row.pairing_open_replies),
                        expired: toNumber(row.pairing_expired)
                    },
                    auth_challenges: {
                        open: toNumber(row.auth_challenges_open),
                        used: toNumber(row.auth_challenges_used),
                        expired: toNumber(row.auth_challenges_expired)
                    },
                    quotas: {
                        patients_above_80_percent_events: toNumber(row.patients_above_80_percent_events),
                        patients_above_80_percent_bytes: toNumber(row.patients_above_80_percent_bytes)
                    }
                };
            } catch (err: any) {
                req.log.error({ err }, "admin stats summary failed");
                return reply.code(500).send({ error: "server_error" });
            }
        }
    );

    app.get(
        "/bundle-cipher/current",
        {
            config: {
                rateLimit: { max: 60, timeWindow: "1 minute" }
            }
        },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) {
                return;
            }

            const cfg = loadBundleCipherConfig(req, reply);
            if (!cfg) {
                return;
            }

            reply.header("Cache-Control", "no-store, max-age=0");
            return {
                kid: cfg.current.kid,
                key_b64: cfg.current.keyB64,
                previous_kid: cfg.previous?.kid ?? null
            };
        }
    );

    app.get(
        "/bundle-cipher/:kid",
        {
            config: {
                rateLimit: { max: 60, timeWindow: "1 minute" }
            }
        },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) {
                return;
            }

            const parsed = BundleCipherKidParamsSchema.safeParse(req.params);
            if (!parsed.success) {
                return reply.code(400).send({ error: "invalid_request", details: parsed.error.flatten() });
            }

            const cfg = loadBundleCipherConfig(req, reply);
            if (!cfg) {
                return;
            }

            const match = [cfg.current, cfg.previous].find((entry) => entry?.kid === parsed.data.kid);
            if (!match) {
                return reply.code(404).send({ error: "unknown_bundle_cipher_key" });
            }

            reply.header("Cache-Control", "no-store, max-age=0");
            return {
                kid: match.kid,
                key_b64: match.keyB64
            };
        }
    );

    /* ============================================================
       Subject registration (one-time)
       ============================================================ */

    app.post(
        "/subjects/register",
        {
            config: {
                rateLimit: { max: 30, timeWindow: "1 minute" }
            }
        },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) {
                return;
            }

            const parsed = RegisterSchema.safeParse(req.body);
            if (!parsed.success) {
                return reply.code(400).send({ error: "invalid_request", details: parsed.error.flatten() });
            }

            const { subject_id, public_key_b64, signature_b64 } = parsed.data;

            const pub = b64ToBytes(public_key_b64);
            const sig = b64ToBytes(signature_b64);

            if (pub.length !== 32) {
                return reply.code(400).send({ error: "invalid_public_key" });
            }
            if (sig.length !== 64) {
                return reply.code(400).send({ error: "invalid_signature" });
            }

            // Verify self-assertion: signature by the provided key
            const ok = ed25519Verify(msgRegister(subject_id, public_key_b64), sig, pub);
            if (!ok) {
                return reply.code(401).send({ error: "bad_signature" });
            }

            // Upsert register: if exists, must match key (prevents takeover)
            const client = await pool.connect();
            try {
                await client.query("begin");

                const existing = await client.query(
                    `select public_key
                     from subjects
                     where subject_id = $1`,
                    [subject_id]
                );

                if ((existing.rowCount ?? 0) > 0) {
                    const old = existing.rows[0].public_key as Buffer;
                    if (!Buffer.from(pub).equals(old)) {
                        const incoming_pubkey_fpr = keyFingerprint(pub);
                        const existing_pubkey_fpr = keyFingerprint(old);
                        req.log.warn(
                            {
                                subject_id,
                                incoming_pubkey_fpr,
                                existing_pubkey_fpr,
                                request_id: req.id,
                                ip: req.ip,
                                user_agent: req.headers["user-agent"] ?? null,
                            },
                            "subjects/register key mismatch"
                        );
                        await client.query("rollback");
                        return reply.code(409).send({
                            error: "subject_exists_with_different_key",
                            diag: {
                                code: "key_mismatch",
                                incoming_pubkey_fpr,
                                existing_pubkey_fpr,
                                fpr_length: KEY_FPR_LENGTH,
                            }
                        });
                    }

                    await client.query(
                        `update subjects
                         set updated_at = now()
                         where subject_id = $1`,
                        [subject_id]
                    );
                } else {
                    await client.query(
                        `insert into subjects (subject_id, public_key)
                         values ($1, $2)`,
                        [subject_id, Buffer.from(pub)]
                    );
                }

                await client.query("commit");
                return { ok: true };
            }
            catch (err: any) {
                await client.query("rollback");
                req.log.error({ err }, "subjects/register failed");
                return reply.code(500).send({ error: "server_error" });
            }
            finally {
                client.release();
            }
        }
    );

    /* ============================================================
       Auth: challenge -> issue JWT (proof of possession)
       ============================================================ */

    app.post(
        "/auth/challenge",
        {
            config: {
                rateLimit: { max: 60, timeWindow: "1 minute" }
            }
        },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) {
                return;
            }

            const parsed = ChallengeSchema.safeParse(req.body);
            if (!parsed.success) {
                return reply.code(400).send({ error: "invalid_request", details: parsed.error.flatten() });
            }

            const { subject_id, device_id } = parsed.data;

            const s = await loadSubject(subject_id);
            if (!s) {
                return reply.code(404).send({ error: "unknown_subject" });
            }
            if (s.disabled_at) {
                return reply.code(403).send({ error: "subject_disabled" });
            }

            const challenge_id = randomUUID();
            const challengeBytes = nacl.randomBytes(32);
            const challenge_b64 = bytesToB64(challengeBytes);

            const client = await pool.connect();
            try {
                await client.query("begin");

                // Prevent challenge-flooding: allow at most one active challenge per (subject, device)
                await client.query(
                    `delete
                     from auth_challenges
                     where subject_id = $1
                       and device_id = $2
                       and used_at is null`,
                    [subject_id, device_id]
                );

                await client.query(
                    `insert into auth_challenges (challenge_id, subject_id, device_id, challenge, expires_at)
                     values ($1, $2, $3, $4, now() + ($5::text)::interval)`,
                    [challenge_id, subject_id, device_id, Buffer.from(challengeBytes), `${ CHALLENGE_TTL_SECONDS } seconds`]
                );

                await client.query("commit");

                return { challenge_id, challenge_b64, expires_in: CHALLENGE_TTL_SECONDS };
            }
            catch (err: any) {
                await client.query("rollback");
                req.log.error({ err }, "auth/challenge failed");
                return reply.code(500).send({ error: "server_error" });
            }
            finally {
                client.release();
            }
        }
    );

    app.post(
        "/auth/issue",
        {
            config: {
                rateLimit: { max: 60, timeWindow: "1 minute" }
            }
        },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) {
                return;
            }

            const parsed = IssueSchema.safeParse(req.body);
            if (!parsed.success) {
                return reply.code(400).send({ error: "invalid_request", details: parsed.error.flatten() });
            }

            const { subject_id, device_id, challenge_id, signature_b64 } = parsed.data;
            const sig = b64ToBytes(signature_b64);
            if (sig.length !== 64) {
                return reply.code(400).send({ error: "invalid_signature" });
            }

            const s = await loadSubject(subject_id);
            if (!s) {
                return reply.code(404).send({ error: "unknown_subject" });
            }
            if (s.disabled_at) {
                return reply.code(403).send({ error: "subject_disabled" });
            }

            const subjectPub = new Uint8Array(
                (s.public_key as Buffer).buffer,
                (s.public_key as Buffer).byteOffset,
                32
            );

            const client = await pool.connect();
            try {
                await client.query("begin");

                // Serialize device cap checks against concurrent auth/issue calls
                await client.query(
                    `select subject_id
                     from subjects
                     where subject_id = $1 for update`,
                    [subject_id]
                );

                // Load + consume challenge (anti-replay)
                const ch = await client.query(
                    `select challenge, expires_at, used_at
                     from auth_challenges
                     where challenge_id = $1
                       and subject_id = $2
                       and device_id = $3
                         for update`,
                    [challenge_id, subject_id, device_id]
                );

                if (ch.rowCount === 0) {
                    await client.query("rollback");
                    return reply.code(400).send({ error: "invalid_challenge" });
                }

                const row = ch.rows[0];
                if (row.used_at) {
                    await client.query("rollback");
                    return reply.code(400).send({ error: "challenge_used" });
                }

                const expiresAt = new Date(row.expires_at).getTime();
                if (Date.now() > expiresAt) {
                    await client.query("rollback");
                    return reply.code(400).send({ error: "challenge_expired" });
                }

                const challengeBytes = row.challenge as Buffer;
                const challenge_b64 = bytesToB64(new Uint8Array(challengeBytes));

                // Load the device row to decide whether this is a recipient auth,
                // an owner auth, or an owner reclaim of a stale/disabled device_id.
                const devRes = await client.query(
                    `select status, public_key, capability
                     from devices
                     where subject_id = $1
                       and device_id = $2
                       for update`,
                    [subject_id, device_id]
                );
                const deviceExists = (devRes.rowCount ?? 0) > 0;
                const devRow = deviceExists ? devRes.rows[0] : null;

                const issueMsg = msgIssue(subject_id, device_id, challenge_id, challenge_b64);
                const rootSignatureOk = ed25519Verify(issueMsg, sig, subjectPub);
                let recipientSignatureOk = false;
                if (devRow?.public_key) {
                    const dpk = devRow.public_key as Buffer;
                    const recipientKey = new Uint8Array(dpk.buffer, dpk.byteOffset, 32);
                    recipientSignatureOk = ed25519Verify(issueMsg, sig, recipientKey);
                }

                if (devRow && devRow.status !== "active" && !rootSignatureOk) {
                    await client.query("rollback");
                    return reply.code(403).send({ error: "device_disabled" });
                }

                // Existing recipient devices normally verify against their own key. A request
                // signed by the subject root key is an explicit patient-owner restore/reclaim
                // for this device_id and converts the row to owner below.
                const signatureOk = devRow?.public_key
                    ? recipientSignatureOk || rootSignatureOk
                    : rootSignatureOk;
                if (!signatureOk) {
                    await client.query("rollback");
                    return reply.code(401).send({ error: "bad_signature" });
                }

                // Mark challenge used (anti-replay)
                await client.query(
                    `update auth_challenges
                     set used_at = now()
                     where challenge_id = $1`,
                    [challenge_id]
                );

                if (deviceExists) {
                    if (rootSignatureOk && (devRow.public_key || devRow.status !== "active")) {
                        await client.query(
                            `update devices
                             set status = 'active',
                                 public_key = null,
                                 capability = 'owner',
                                 last_seen_at = now()
                             where subject_id = $1 and device_id = $2`,
                            [subject_id, device_id]
                        );
                    } else {
                        // Existing active device: refresh last_seen only.
                        // Do NOT touch status/capability/public_key here.
                        await client.query(
                            `update devices
                             set last_seen_at = now()
                             where subject_id = $1 and device_id = $2`,
                            [subject_id, device_id]
                        );
                    }
                } else {
                    // New device with no row = OWNER first-auth (recipients are pre-created via
                    // /devices/authorize). Verified against the subject root key above.
                    // Only ACTIVE devices count against the limit — a
                    // revoked/disabled device frees its slot.
                    const devCount = await client.query(
                        `select count(*) ::int as n
                         from devices
                         where subject_id = $1 and status = 'active'`,
                        [subject_id]
                    );
                    if ((devCount.rows[0]?.n ?? 0) >= MAX_DEVICES_PER_SUBJECT) {
                        await client.query("rollback");
                        return reply.code(403).send({ error: "device_limit_reached" });
                    }
                    await client.query(
                        `insert into devices (subject_id, device_id, status, public_key, capability, last_seen_at)
                         values ($1, $2, 'active', null, 'owner', now())`,
                        [subject_id, device_id]
                    );
                }

                await client.query("commit");
            }
            catch (err: any) {
                await client.query("rollback");
                req.log.error({ err }, "auth/issue failed");
                return reply.code(500).send({ error: "server_error" });
            }
            finally {
                client.release();
            }

            // Mint JWT (capability token)
            const ttlSeconds = Number(process.env.JWT_TTL_SECONDS ?? "15552000"); // 180d
            const nowSeconds = Math.floor(Date.now() / 1000);
            const jti = randomUUID();

            const token = await reply.jwtSign({
                sub: subject_id,
                scope: "sync",
                device_id,
                tv: Number(s.token_version),

                iss: app.jwtCfg.issuer,
                aud: app.jwtCfg.audience,
                iat: nowSeconds,
                exp: nowSeconds + ttlSeconds,
                jti
            });

            return { access_token: token, token_type: "Bearer", expires_in: ttlSeconds };
        }
    );

    /* ============================================================
       Device management
       ============================================================ */

    // Deactivate current device (used when clearing app data)
    app.post("/devices/deactivate", { preHandler: app.auth }, async (req: any, reply) => {
        const subject = await enforceSubjectActiveAndTokenVersion(req, reply);
        if (!subject || (subject as any).error) {
            return;
        }

        const subjectId = req.user.sub as string;
        const deviceId = req.user.device_id as string;

        if (!deviceId) {
            return reply.code(400).send({ error: "missing_device_id" });
        }

        try {
            await pool.query(
                `update devices
                 set status = 'disabled', last_seen_at = now()
                 where subject_id = $1 and device_id = $2`,
                [subjectId, deviceId]
            );

            return { ok: true, device_id: deviceId, status: "disabled" };
        } catch (err: any) {
            req.log.error({ err }, "devices/deactivate failed");
            return reply.code(500).send({ error: "server_error" });
        }
    });

    /* ============================================================
       Grant a recipient device its own identity and capability.
       Authorized by a signature from the subject ROOT key (not a JWT) -
       the patient holds the subject secret key and signs the grant.
       ============================================================ */
    app.post(
        "/devices/authorize",
        { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) return;

            const parsed = AuthorizeDeviceSchema.safeParse(req.body);
            if (!parsed.success) {
                return reply.code(400).send({ error: "invalid_request", details: parsed.error.flatten() });
            }
            const { subject_id, target_device_id, target_public_key_b64, capability, signature_b64 } = parsed.data;

            const targetPub = b64ToBytes(target_public_key_b64);
            const sig = b64ToBytes(signature_b64);
            if (targetPub.length !== 32) return reply.code(400).send({ error: "invalid_public_key" });
            if (sig.length !== 64) return reply.code(400).send({ error: "invalid_signature" });

            const s = await loadSubject(subject_id);
            if (!s) return reply.code(404).send({ error: "unknown_subject" });
            if (s.disabled_at) return reply.code(403).send({ error: "subject_disabled" });

            // Verify the grant signature against the subject ROOT key.
            const rootKey = new Uint8Array(
                (s.public_key as Buffer).buffer,
                (s.public_key as Buffer).byteOffset,
                32
            );
            const ok = ed25519Verify(
                msgAuthorize(subject_id, target_device_id, target_public_key_b64, capability),
                sig,
                rootKey
            );
            if (!ok) return reply.code(401).send({ error: "bad_signature" });

            const client = await pool.connect();
            try {
                await client.query("begin");
                await client.query(`select subject_id from subjects where subject_id = $1 for update`, [subject_id]);

                const existing = await client.query(
                    `select public_key, status from devices where subject_id = $1 and device_id = $2`,
                    [subject_id, target_device_id]
                );

                if ((existing.rowCount ?? 0) === 0) {
                    // Only ACTIVE devices count against the limit — a
                    // revoked/disabled device frees its slot.
                    const devCount = await client.query(
                        `select count(*) ::int as n from devices
                         where subject_id = $1 and status = 'active'`,
                        [subject_id]
                    );
                    if ((devCount.rows[0]?.n ?? 0) >= MAX_DEVICES_PER_SUBJECT) {
                        await client.query("rollback");
                        return reply.code(403).send({ error: "device_limit_reached" });
                    }
                    await client.query(
                        `insert into devices (subject_id, device_id, status, public_key, capability, last_seen_at)
                         values ($1, $2, 'active', $3, $4, now())`,
                        [subject_id, target_device_id, Buffer.from(targetPub), capability]
                    );
                } else {
                    // An OWNER device (public_key NULL) must NOT be converted into a granted device.
                    const old = existing.rows[0].public_key as Buffer | null;
                    if (!old) {
                        await client.query("rollback");
                        return reply.code(409).send({ error: "owner_device_conflict" });
                    }
                    // Re-grant: the recipient generates a FRESH keypair on every pairing, so the
                    // pubkey legitimately differs from a previous grant (e.g. re-pairing a device
                    // that was revoked/disabled). This request is signed by the subject ROOT key -
                    // only the patient can produce it - so update the pubkey + capability and
                    // re-activate the device.
                    await client.query(
                        `update devices
                         set public_key = $3, capability = $4, status = 'active', last_seen_at = now()
                         where subject_id = $1 and device_id = $2`,
                        [subject_id, target_device_id, Buffer.from(targetPub), capability]
                    );
                }

                await client.query("commit");
                return { ok: true, device_id: target_device_id, capability };
            } catch (err: any) {
                await client.query("rollback");
                req.log.error({ err }, "devices/authorize failed");
                return reply.code(500).send({ error: "server_error" });
            } finally {
                client.release();
            }
        }
    );

    /* ============================================================
       Disable another device of the same subject (owner-only, via JWT).
       Self-disable uses /devices/deactivate.
       ============================================================ */
    app.post("/devices/disable", { preHandler: app.auth }, async (req: any, reply) => {
        const subject = await enforceSubjectActiveAndTokenVersion(req, reply);
        if (!subject || (subject as any).error) return;
        if (!requireOwner(subject, reply)) return;

        const parsed = DisableDeviceSchema.safeParse(req.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: "invalid_request", details: parsed.error.flatten() });
        }
        const subjectId = req.user.sub as string;
        const callerDeviceId = req.user.device_id as string;
        const { target_device_id } = parsed.data;

        if (target_device_id === callerDeviceId) {
            return reply.code(409).send({ error: "use_deactivate_for_self" });
        }

        try {
            const r = await pool.query(
                `update devices set status = 'disabled', last_seen_at = now()
                 where subject_id = $1 and device_id = $2 and status = 'active'
                 returning device_id`,
                [subjectId, target_device_id]
            );
            if ((r.rowCount ?? 0) === 0) {
                return reply.code(404).send({ error: "device_not_found_or_already_disabled" });
            }
            return { ok: true, device_id: target_device_id, status: "disabled" };
        } catch (err: any) {
            req.log.error({ err }, "devices/disable failed");
            return reply.code(500).send({ error: "server_error" });
        }
    });

    /* ============================================================
       Pre-auth rendezvous mailbox (pairing).
       Stores ONLY public material / ciphertext. Short TTL. No medical content.
       ============================================================ */
    app.post(
        "/rendezvous/:token",
        { config: { rateLimit: { max: 60, timeWindow: "1 minute" } } },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) return;

            const params = RendezvousTokenParamsSchema.safeParse(req.params);
            if (!params.success) return reply.code(400).send({ error: "invalid_token" });

            const body = RendezvousPostSchema.safeParse(req.body);
            if (!body.success) {
                return reply.code(400).send({ error: "invalid_request", details: body.error.flatten() });
            }
            const payloadStr = JSON.stringify(body.data.payload);
            if (Buffer.byteLength(payloadStr, "utf8") > RENDEZVOUS_MAX_PAYLOAD_BYTES) {
                return reply.code(413).send({ error: "payload_too_large" });
            }

            try {
                await pool.query(
                    `insert into rendezvous (token, slot, payload, expires_at)
                     values ($1, $2, $3::jsonb, now() + ($4::text)::interval)
                     on conflict (token, slot)
                     do update set payload = excluded.payload, created_at = now(), expires_at = excluded.expires_at`,
                    [params.data.token, body.data.slot, payloadStr, `${ RENDEZVOUS_TTL_SECONDS } seconds`]
                );
                reply.header("Cache-Control", "no-store");
                return { ok: true, expires_in: RENDEZVOUS_TTL_SECONDS };
            } catch (err: any) {
                req.log.error({ err }, "rendezvous post failed");
                return reply.code(500).send({ error: "server_error" });
            }
        }
    );

    app.get(
        "/rendezvous/:token",
        { config: { rateLimit: { max: 120, timeWindow: "1 minute" } } },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) return;

            const params = RendezvousTokenParamsSchema.safeParse(req.params);
            if (!params.success) return reply.code(400).send({ error: "invalid_token" });

            try {
                const r = await pool.query(
                    `select slot, payload from rendezvous
                     where token = $1 and expires_at > now()`,
                    [params.data.token]
                );
                const slots: Record<string, any> = {};
                for (const row of r.rows) slots[row.slot] = row.payload;

                // Rendezvous is discarded after retrieval. Once the reply
                // is delivered, the handshake is complete - drop all slots for this token.
                if (slots.reply) {
                    await pool.query(`delete from rendezvous where token = $1`, [params.data.token]);
                }

                reply.header("Cache-Control", "no-store");
                return { offer: slots.offer ?? null, reply: slots.reply ?? null };
            } catch (err: any) {
                req.log.error({ err }, "rendezvous get failed");
                return reply.code(500).send({ error: "server_error" });
            }
        }
    );

    /* ============================================================
       Events (guards + quotas)
       ============================================================ */
    app.post("/events/batch", { preHandler: app.auth }, async (req: any, reply) => {
        const parsed = BatchSchema.safeParse(req.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: "invalid_request", details: parsed.error.flatten() });
        }

        const subject = await enforceSubjectActiveAndTokenVersion(req, reply);
        if (!subject || (subject as any).error) {
            return;
        } // reply already sent

        // Only owner and read_write devices may push events.
        if (!canWriteEvents(subject)) {
            return reply.code(403).send({ error: "write_forbidden" });
        }

        const subjectId = req.user.sub as string;
        const tokenDeviceId = req.user.device_id as string;
        const events = parsed.data.events;

        const client = await pool.connect();
        const acked: string[] = [];

        // Track only ACTUALLY inserted rows for quota accounting
        let insertedEvents = 0;
        let insertedBytes = 0;

        try {
            await client.query("begin");

            // Reset daily counters if the date rolled over
            await client.query(
                `update subjects
                 set day_date   = current_date,
                     events_day = case when day_date = current_date then events_day else 0 end,
                     bytes_day  = case when day_date = current_date then bytes_day else 0 end
                 where subject_id = $1`,
                [subjectId]
            );

            // Lock subject row for quota check + update (serializes concurrent batch writes)
            const sRes = await client.query(
                `select max_events_total,
                        max_bytes_total,
                        max_events_day,
                        max_bytes_day,
                        events_total,
                        bytes_total,
                        events_day,
                        bytes_day
                 from subjects
                 where subject_id = $1
                     for update`,
                [subjectId]
            );
            const s = sRes.rows[0];
            if (!s) {
                await client.query("rollback");
                return reply.code(401).send({ error: "unknown_subject" });
            }

            const allowedDevices = new Set<string>();
            const touchedDevices = new Set<string>(); // track devices seen in this batch

            // Insert events (idempotent) and count only inserted ones
            for (const e of events) {
                if (e.device_id !== tokenDeviceId) {
                    await client.query("rollback");
                    return reply.code(403).send({ error: "device_id_mismatch" });
                }

                const { nonce, ciphertext, hash, bytes } = decodeEventSizes(e);

                // Minimal sanity
                if (nonce.length < 8 || ciphertext.length < 1 || hash.length !== 32) {
                    continue;
                }

                if (!allowedDevices.has(e.device_id)) {
                    const dev = await client.query(
                        `select status
                         from devices
                         where subject_id = $1
                           and device_id = $2`,
                        [subjectId, e.device_id]
                    );
                    if (dev.rowCount === 0 || dev.rows[0].status !== "active") {
                        await client.query("rollback");
                        return reply.code(403).send({ error: "device_not_registered" });
                    }
                    allowedDevices.add(e.device_id);
                }

                touchedDevices.add(e.device_id);

                const q = `
                    insert into events (subject_id, event_id, device_id,
                                        lamport, device_seq,
                                        entity_type, entity_id, op_kind,
                                        client_created_at,
                                        alg, nonce, ciphertext, ciphertext_hash)
                    values ($1, $2, $3,
                            $4, $5,
                            $6, $7, $8,
                            $9,
                            $10, $11, $12, $13) on conflict (subject_id, event_id) do nothing
          returning 1 as inserted
                `;

                const res = await client.query(q, [
                    subjectId,
                    e.event_id,
                    e.device_id,
                    e.lamport,
                    e.device_seq ?? null,
                    e.entity_type ?? null,
                    e.entity_id ?? null,
                    e.op_kind ?? null,
                    e.client_created_at ?? null,
                    e.alg,
                    nonce,
                    ciphertext,
                    hash
                ]);

                // Always ack event_id (idempotent API)
                acked.push(e.event_id);

                // Only count if actually inserted
                if ((res.rowCount ?? 0) > 0) {
                    insertedEvents += 1;
                    insertedBytes += bytes;

                    const nextEventsTotal = Number(s.events_total) + insertedEvents;
                    const nextBytesTotal = Number(s.bytes_total) + insertedBytes;
                    const nextEventsDay = Number(s.events_day) + insertedEvents;
                    const nextBytesDay = Number(s.bytes_day) + insertedBytes;

                    // Enforce quotas; rollback ensures we never persist over-quota inserts
                    if (nextEventsTotal > Number(s.max_events_total) || nextBytesTotal > Number(s.max_bytes_total)) {
                        await client.query("rollback");
                        return reply.code(403).send({ error: "quota_exceeded_total" });
                    }
                    if (nextEventsDay > Number(s.max_events_day) || nextBytesDay > Number(s.max_bytes_day)) {
                        await client.query("rollback");
                        return reply.code(429).send({ error: "quota_exceeded_daily" });
                    }
                }
            }

            // Update device last_seen_at for devices used in this batch (audit-friendly)
            if (touchedDevices.size > 0) {
                await client.query(
                    `update devices
                     set last_seen_at = now()
                     where subject_id = $1
                       and device_id = any ($2::uuid[])
                       and status = 'active'`,
                    [subjectId, Array.from(touchedDevices)]
                );
            }

            // Apply counters for inserted-only
            if (insertedEvents > 0 || insertedBytes > 0) {
                await client.query(
                    `update subjects
                     set events_total = events_total + $2,
                         bytes_total  = bytes_total + $3,
                         events_day   = events_day + $2,
                         bytes_day    = bytes_day + $3,
                         updated_at   = now()
                     where subject_id = $1`,
                    [subjectId, insertedEvents, insertedBytes]
                );
            }

            await client.query("commit");
            return { acked };
        }
        catch (err: any) {
            await client.query("rollback");
            req.log.error({ err }, "batch insert failed");
            return reply.code(500).send({ error: "server_error" });
        }
        finally {
            client.release();
        }
    });

    // Pull events using stable cursor order (server_received_at, event_id)
    //
    // Query params:
    //  - since_ts (ISO timestamptz) + since_id (uuid): resume after this tuple
    //  - limit: max events
    //
    // Response:
    //  - next: { since_ts, since_id } or null
    app.get("/events", { preHandler: app.auth }, async (req: any, reply) => {
        const subject = await enforceSubjectActiveAndTokenVersion(req, reply);
        if (!subject || (subject as any).error) {
            return;
        }

        const subjectId = req.user.sub as string;

        const limitRaw = req.query?.limit;
        const limit = Math.min(Math.max(Number(limitRaw ?? 500), 1), MAX_PULL);

        // v2 cursor
        const since_ts = (req.query?.since_ts ?? "") as string;
        const since_id = (req.query?.since_id ?? "") as string;

        const hasTs = !!since_ts;
        const hasId = !!since_id;

        if (hasTs !== hasId) {
            return reply.code(400).send({ error: "invalid_cursor" });
        }

        let rows: any[] = [];

        if (!since_ts && !since_id) {
            // from the beginning
            const res = await pool.query(
                `select event_id,
                        device_id,
                        lamport,
                        device_seq,
                        entity_type,
                        entity_id,
                        op_kind,
                        client_created_at,
                        ${ SERVER_RECEIVED_AT_ISO_SQL }   as server_received_at,
                        alg,
                        encode(nonce, 'base64')           as nonce_b64,
                        encode(ciphertext, 'base64')      as ciphertext_b64,
                        encode(ciphertext_hash, 'base64') as ciphertext_hash_b64
                 from events
                 where subject_id = $1
                 order by server_received_at asc, event_id asc
                     limit $2`,
                [subjectId, limit]
            );
            rows = res.rows;
        } else {
            const ok = CursorSchema.safeParse({ since_ts, since_id });
            if (!ok.success) {
                return reply.code(400).send({ error: "invalid_cursor" });
            }

            const res = await pool.query(
                `select event_id,
                        device_id,
                        lamport,
                        device_seq,
                        entity_type,
                        entity_id,
                        op_kind,
                        client_created_at,
                        ${ SERVER_RECEIVED_AT_ISO_SQL }   as server_received_at,
                        alg,
                        encode(nonce, 'base64')           as nonce_b64,
                        encode(ciphertext, 'base64')      as ciphertext_b64,
                        encode(ciphertext_hash, 'base64') as ciphertext_hash_b64
                 from events
                 where subject_id = $1
                   and (server_received_at, event_id) > ($2::timestamptz, $3::uuid)
                 order by server_received_at asc, event_id asc
                     limit $4`,
                [subjectId, since_ts, since_id, limit]
            );
            rows = res.rows;
        }

        const last = rows.length ? rows[rows.length - 1] : null;

        // IMPORTANT:
        // server_received_at is already a stable ISO string from SQL.
        // Do NOT wrap it in `new Date()` (that caused cursor loops).
        const next = last
            ? {
                since_ts: last.server_received_at,
                since_id: last.event_id
            }
            : null;

        return { events: rows, next };
    });

    // Convenience: current head cursor (server_received_at, event_id)
    app.get("/events/head", { preHandler: app.auth }, async (req: any, reply) => {
        const subject = await enforceSubjectActiveAndTokenVersion(req, reply);
        if (!subject || (subject as any).error) {
            return;
        }

        const subjectId = req.user.sub as string;
        const res = await pool.query(
            `select event_id,
                    ${ SERVER_RECEIVED_AT_ISO_SQL } as server_received_at
             from events
             where subject_id = $1
             order by server_received_at desc, event_id desc limit 1`,
            [subjectId]
        );

        const row = res.rows[0];
        if (!row) {
            return { head: null };
        }

        return {
            head: {
                since_ts: row.server_received_at,
                since_id: row.event_id
            }
        };
    });

    /* ============================================================
       Recovery: lookup subject by public key
       ============================================================ */

    const ByPubkeySchema = z.object({
        public_key_b64: z.string().min(8),
    });

    app.post(
        "/subjects/by-pubkey",
        {
            config: {
                rateLimit: { max: 10, timeWindow: "1 minute" }
            }
        },
        async (req: any, reply) => {
            if (!requireAppToken(req, reply)) return;

            const parsed = ByPubkeySchema.safeParse(req.body);
            if (!parsed.success) {
                return reply.code(400).send({ error: "invalid_request" });
            }

            const pub = b64ToBytes(parsed.data.public_key_b64);
            if (pub.length !== 32) {
                return reply.code(400).send({ error: "invalid_public_key" });
            }

            const res = await pool.query(
                `SELECT subject_id FROM subjects WHERE public_key = $1 AND disabled_at IS NULL`,
                [Buffer.from(pub)]
            );

            if (res.rowCount === 0) {
                return reply.code(404).send({ error: "not_found" });
            }

            return { subject_id: res.rows[0].subject_id };
        }
    );

    /* ============================================================
       Key rotation: update public key (signed with old key)
       ============================================================ */

    const UpdateKeySchema = z.object({
        new_public_key_b64: z.string().min(8),
        signature_b64: z.string().min(8),
    });

    function msgUpdateKey(subjectId: string, newPubKeyB64: string) {
        return utf8Bytes(`update-key|${subjectId}|${newPubKeyB64}`);
    }

    /* ============================================================
       Subject deletion (GDPR hard-delete)
       ============================================================ */

    app.post(
        "/subjects/delete",
        {
            preHandler: app.auth,
            config: { rateLimit: { max: 3, timeWindow: "1 minute" } },
        },
        async (req: any, reply) => {
            const subjectId = req.user.sub as string;
            const client = await pool.connect();

            try {
                await client.query("begin");

                // Lock subject row - prevents races with concurrent /events/batch.
                const sRes = await client.query(
                    `SELECT subject_id, token_version, disabled_at
                     FROM subjects WHERE subject_id = $1 FOR UPDATE`,
                    [subjectId]
                );

                if (sRes.rowCount === 0) {
                    // Already deleted (idempotent) - return success.
                    await client.query("commit");
                    return reply.send({ ok: true, deleted_events: 0 });
                }

                const s = sRes.rows[0];

                // Validate token claims
                const tokenDeviceId = req.user.device_id as string;
                if (typeof tokenDeviceId !== "string" || tokenDeviceId.length < 8) {
                    await client.query("commit");
                    return reply.code(401).send({ error: "invalid_token" });
                }

                // Enforce same checks as enforceSubjectActiveAndTokenVersion
                if (s.disabled_at) {
                    await client.query("commit");
                    return reply.code(403).send({ error: "subject_disabled" });
                }
                const tokenTv = Number((req.user as any).tv ?? 0);
                if (tokenTv !== Number(s.token_version)) {
                    await client.query("commit");
                    return reply.code(401).send({ error: "token_revoked" });
                }

                // Check device status
                const dRes = await client.query(
                    `SELECT status, capability FROM devices
                     WHERE subject_id = $1 AND device_id = $2`,
                    [subjectId, tokenDeviceId]
                );
                if (dRes.rowCount === 0) {
                    await client.query("commit");
                    return reply.code(403).send({ error: "device_not_registered" });
                }
                if (dRes.rows[0].status !== "active") {
                    await client.query("commit");
                    return reply.code(403).send({ error: "device_disabled" });
                }
                // Subject hard-delete is owner-only.
                if (dRes.rows[0].capability !== "owner") {
                    await client.query("commit");
                    return reply.code(403).send({ error: "owner_required" });
                }

                // Delete events first (no CASCADE on this table)
                const evResult = await client.query(
                    `DELETE FROM events WHERE subject_id = $1`,
                    [subjectId]
                );

                // Delete subject (CASCADE to devices + auth_challenges).
                await client.query(
                    `DELETE FROM subjects WHERE subject_id = $1`,
                    [subjectId]
                );

                await client.query("commit");

                return reply.send({
                    ok: true,
                    deleted_events: evResult.rowCount ?? 0,
                });
            } catch (err) {
                await client.query("rollback").catch(() => {});
                req.log.error(err, "subjects/delete failed");
                return reply.code(500).send({ error: "server_error" });
            } finally {
                client.release();
            }
        }
    );

    app.post("/subjects/update-key", { preHandler: app.auth }, async (req: any, reply) => {
        const s = await enforceSubjectActiveAndTokenVersion(req, reply);
        if (!s || (s as any).error) return;
        if (!requireOwner(s, reply)) return; // Root rotation is owner-only.

        const parsed = UpdateKeySchema.safeParse(req.body);
        if (!parsed.success) {
            return reply.code(400).send({ error: "invalid_request" });
        }

        const newPub = b64ToBytes(parsed.data.new_public_key_b64);
        const sig = b64ToBytes(parsed.data.signature_b64);
        if (newPub.length !== 32) {
            return reply.code(400).send({ error: "invalid_public_key" });
        }

        // Verify signature with CURRENT (old) key
        const msg = msgUpdateKey(s.subject_id, parsed.data.new_public_key_b64);
        const currentKey = new Uint8Array(
            (s.public_key as Buffer).buffer,
            (s.public_key as Buffer).byteOffset,
            32
        );
        if (!ed25519Verify(msg, sig, currentKey)) {
            return reply.code(401).send({ error: "bad_signature" });
        }

        // Update key + increment token_version (invalidates all existing JWTs)
        const client = await pool.connect();
        try {
            await client.query("begin");
            await client.query(
                `SELECT subject_id FROM subjects WHERE subject_id = $1 FOR UPDATE`,
                [s.subject_id]
            );
            await client.query(
                `UPDATE subjects
                 SET public_key = $1, token_version = token_version + 1, updated_at = now()
                 WHERE subject_id = $2`,
                [Buffer.from(newPub), s.subject_id]
            );
            await client.query("commit");
        } catch (err: any) {
            await client.query("rollback");
            req.log.error({ err }, "subjects/update-key failed");
            return reply.code(500).send({ error: "server_error" });
        } finally {
            client.release();
        }

        return { ok: true };
    });
}
