
const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "16kb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const hash = value =>
  crypto.createHash("sha256").update(value).digest("hex");

const makeCode = () =>
  "MAX-" + crypto.randomBytes(12).toString("hex").toUpperCase();

const requireAdmin = (req, res, next) => {
  const expected = process.env.ADMIN_SECRET;
  const supplied = req.get("x-admin-secret");

  if (!expected || !supplied ||
      Buffer.byteLength(expected) !== Buffer.byteLength(supplied) ||
      !crypto.timingSafeEqual(
        Buffer.from(expected),
        Buffer.from(supplied)
      )) {
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
};

app.get("/", (req, res) => {
  res.json({ app: "MAX TV", status: "online" });
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok", database: "connected" });
  } catch (err) {   console.error("DATABASE ERROR:", err.message);
    res.status(503).json({ status: "error", database: "disconnected" });
  }
});

// إنشاء 100 كود شهري و100 كود لثلاثة أشهر
app.post("/api/admin/generate-codes", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const codes = [];
    await client.query("BEGIN");

    for (const duration of [30, 90]) {
      for (let i = 0; i < 100; i++) {
        const code = makeCode();

        await client.query(
          `INSERT INTO public.max_tv_activation_codes
           (code_hash, duration_days)
           VALUES ($1, $2)`,
          [hash(code), duration]
        );

        codes.push({ code, duration_days: duration });
      }
    }

    await client.query("COMMIT");
    res.json({ created: codes.length, codes });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Code generation failed" });
  } finally {
    client.release();
  }
});

// إنشاء حساب وتفعيل كود اشتراك
app.post("/api/activate", async (req, res) => {
  const { username, password, code } = req.body || {};

  if (
    typeof username !== "string" ||
    !/^[a-zA-Z0-9_]{3,32}$/.test(username) ||
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 128 ||
    typeof code !== "string" ||
    !/^MAX-[A-F0-9]{24}$/.test(code)
  ) {
    return res.status(400).json({ error: "Invalid input" });
  }

  const client = await pool.connect();

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    await client.query("BEGIN");

    const result = await client.query(
      `SELECT id, duration_days
       FROM public.max_tv_activation_codes
       WHERE code_hash = $1 AND user_id IS NULL
       FOR UPDATE`,
      [hash(code)]
    );

    if (!result.rowCount) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Invalid or used code" });
    }

    const user = await client.query(
      `INSERT INTO public.max_tv_users
       (username, password_hash)
       VALUES ($1, $2)
       RETURNING id, username`,
      [username, passwordHash]
    );

    const duration = result.rows[0].duration_days;

    await client.query(
      `UPDATE public.max_tv_activation_codes
       SET user_id = $1,
           activated_at = NOW(),
           expires_at = NOW() + ($2 * INTERVAL '1 day')
       WHERE id = $3`,
      [user.rows[0].id, duration, result.rows[0].id]
    );

    await client.query("COMMIT");

    res.status(201).json({
      success: true,
      username: user.rows[0].username,
      duration_days: duration
    });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username already exists" });
    }
    console.error(err);
    res.status(500).json({ error: "Activation failed" });
  } finally {
    client.release();
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`MAX TV Server running on ${PORT}`);
});
