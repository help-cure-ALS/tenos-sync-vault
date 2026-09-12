import { Pool } from "pg";

export const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 100,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

// Arbitrary constant, shared by all api replicas of this service.
const MIGRATION_LOCK_KEY = 810_001;

export async function runMigrations() {
    const { readFileSync, readdirSync } = await import("node:fs");
    const { join } = await import("node:path");

    const dir = join(process.cwd(), "migrations");
    const files = readdirSync(dir).filter(f => f.endsWith(".sql")).sort();

    // naive migrator: run all files each boot in a transaction; each file uses IF NOT EXISTS
    const client = await pool.connect();
    try {
        // Serialize across replicas: with several instances booting at
        // once, concurrent DDL on the same tables deadlocks (40P01).
        // The advisory lock lets the replicas run the (idempotent)
        // files strictly one after another; the lock is tied to this
        // connection and released in finally.
        await client.query("select pg_advisory_lock($1)", [MIGRATION_LOCK_KEY]);
        await client.query("begin");
        for (const f of files) {
            const sql = readFileSync(join(dir, f), "utf8");
            await client.query(sql);
        }
        await client.query("commit");
    } catch (e) {
        await client.query("rollback");
        throw e;
    } finally {
        await client.query("select pg_advisory_unlock($1)", [MIGRATION_LOCK_KEY]).catch(() => {});
        client.release();
    }
}
