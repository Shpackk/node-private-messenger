import { Pool, migrate } from "./index.js";

const pool = new Pool({
	connectionString: process.env.DATABASE_URL ?? "postgres://messenger:messenger@localhost:5432/messenger",
});
await migrate(pool);
await pool.end();
