const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

// ============================================================
// DATABASE
// ============================================================

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL haijawekwa.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(__dirname));

// ============================================================
// HELPERS
// ============================================================

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

function parseCookies(req) {
  const cookies = {};

  const header = req.headers.cookie || "";

  header.split(";").forEach((part) => {
    const index = part.indexOf("=");

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    try {
      cookies[key] = decodeURIComponent(value);
    } catch (_) {
      cookies[key] = value;
    }
  });

  return cookies;
}

function getSchoolAdminToken(req) {
  const cookies = parseCookies(req);
  return cookies.school_admin_token || null;
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(String(token))
    .digest("hex");
}

function generateApplicationNumber() {
  return (
    "SPT-" +
    new Date().getFullYear() +
    "-" +
    Date.now() +
    "-" +
    crypto
      .randomBytes(2)
      .toString("hex")
      .toUpperCase()
  );
}

function generatePaymentReference() {
  return (
    "PAY-" +
    new Date().getFullYear() +
    "-" +
    Date.now() +
    "-" +
    crypto
      .randomBytes(2)
      .toString("hex")
      .toUpperCase()
  );
}

// ============================================================
// DATABASE SETUP
// ============================================================

async function setupDatabase() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // ========================================================
    // SCHOOLS
    // ========================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS schools (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        region VARCHAR(255),
        district VARCHAR(255),
        school_type VARCHAR(255),
        form_price NUMERIC(12,2) DEFAULT 0,
        phone VARCHAR(100),
        address TEXT,
        email VARCHAR(255),
        application_start TIMESTAMP NULL,
        application_end TIMESTAMP NULL,
        status VARCHAR(50) DEFAULT 'draft',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // ========================================================
    // APPLICATIONS
    // ========================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        application_number VARCHAR(100) UNIQUE,
        school_id INTEGER,
        student_name VARCHAR(255),
        gender VARCHAR(50),
        date_of_birth DATE,
        class_level VARCHAR(100),
        parent_name VARCHAR(255),
        phone VARCHAR(100),
        email VARCHAR(255),
        address TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        payment_status VARCHAR(50) DEFAULT 'unpaid',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(100)
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS gender VARCHAR(50)
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS date_of_birth DATE
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS class_level VARCHAR(100)
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS parent_name VARCHAR(255)
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS phone VARCHAR(100)
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS email VARCHAR(255)
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS address TEXT
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS status VARCHAR(50)
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS payment_status VARCHAR(50)
    `);

    // ========================================================
    // PAYMENTS
    // ========================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        application_id INTEGER,
        application_number VARCHAR(100),
        payment_reference VARCHAR(100),
        amount NUMERIC(12,2) DEFAULT 0,
        status VARCHAR(50) DEFAULT 'pending',
        provider VARCHAR(100),
        provider_reference VARCHAR(255),
        paid_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(100)
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS payment_reference VARCHAR(100)
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS amount NUMERIC(12,2) DEFAULT 0
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending'
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS provider VARCHAR(100)
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS provider_reference VARCHAR(255)
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS paid_at TIMESTAMP NULL
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    `);

    await client.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    `);

    // ========================================================
    // SCHOOL ADMINS
    // ========================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS school_admins (
        id SERIAL PRIMARY KEY,
        school_id INTEGER,
        full_name VARCHAR(255),
        email VARCHAR(255) UNIQUE,
        phone VARCHAR(100),
        password_hash TEXT,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      ALTER TABLE school_admins
      ADD COLUMN IF NOT EXISTS last_login TIMESTAMP NULL
    `);

    // ========================================================
    // SCHOOL ADMIN SESSIONS
    // ========================================================

    await client.query(`
      CREATE TABLE IF NOT EXISTS school_admin_sessions (
        id SERIAL PRIMARY KEY,
        school_admin_id INTEGER,
        token_hash TEXT UNIQUE,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // ========================================================
    // SCHOOL PROFILE COLUMNS
    // ========================================================

    await client.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS description TEXT
    `);

    await client.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS logo_url TEXT
    `);

    await client.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS classes_offered TEXT
    `);

    await client.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS requirements TEXT
    `);

    await client.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS profile_completed BOOLEAN DEFAULT FALSE
    `);

    // ========================================================
    // INDEXES
    // ========================================================

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_school_id
      ON applications(school_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_application_number
      ON applications(application_number)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_payments_application_id
      ON payments(application_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_payments_application_number
      ON payments(application_number)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_school_admins_school_id
      ON school_admins(school_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_school_admin_sessions_token_hash
      ON school_admin_sessions(token_hash)
    `);

    // ========================================================
    // REPAIR APPLICATION NUMBERS
    // ========================================================

    await client.query(`
      UPDATE applications
      SET application_number =
        'SPT-' ||
        EXTRACT(YEAR FROM CURRENT_DATE)::TEXT ||
        '-' ||
        id::TEXT
      WHERE
        application_number IS NULL
        OR application_number = ''
    `);

    // ========================================================
    // REPAIR PAYMENT APPLICATION NUMBERS
    // ========================================================

    await client.query(`
      UPDATE payments p
      SET application_number = a.application_number
      FROM applications a
      WHERE
        p.application_id = a.id
        AND (
          p.application_number IS NULL
          OR p.application_number = ''
        )
        AND a.application_number IS NOT NULL
    `);

    // ========================================================
    // DEFAULT VALUES
    // ========================================================

    await client.query(`
      UPDATE applications
      SET status = 'pending'
      WHERE status IS NULL
    `);

    await client.query(`
      UPDATE applications
      SET payment_status = 'unpaid'
      WHERE payment_status IS NULL
    `);

    await client.query("COMMIT");

    console.log("Database setup completed successfully.");
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(
      "Database setup error:",
      error
    );

    throw error;
  } finally {
    client.release();
  }
}

// ============================================================
// SCHOOL ADMIN AUTH MIDDLEWARE
// ============================================================

async function requireSchoolAdmin(req, res, next) {
  try {
    const token = getSchoolAdminToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message:
          "Hujaingia kama Admin wa Shule.",
        error:
          "Hujaingia kama Admin wa Shule."
      });
    }

    const tokenHash = hashToken(token);

    const result = await pool.query(
      `
      SELECT
        sa.id,
        sa.school_id,
        sa.full_name,
        sa.email,
        sa.phone,
        sa.status AS admin_status,

        s.name AS school_name,
        s.region,
        s.district,
        s.school_type,
        s.form_price,
        s.status AS school_status,
        s.profile_completed

      FROM school_admin_sessions sas

      JOIN school_admins sa
        ON sa.id = sas.school_admin_id

      JOIN schools s
        ON s.id = sa.school_id

      WHERE
        sas.token_hash = $1
        AND sas.expires_at > CURRENT_TIMESTAMP
        AND sa.status = 'active'

      LIMIT 1
      `,
      [tokenHash]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message:
          "Session ya Admin wa Shule imekwisha.",
        error:
          "Session ya Admin wa Shule imekwisha."
      });
    }

    const admin = result.rows[0];

    if (
      admin.school_status === "inactive" ||
      admin.school_status === "suspended"
    ) {
      return res.status(403).json({
        success: false,
        message:
          "Shule hii haipo active.",
        error:
          "Shule hii haipo active."
      });
    }

    req.schoolAdmin = admin;

    next();
  } catch (error) {
    console.error(
      "School admin auth error:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Hitilafu ya authentication.",
      error:
        error.message
    });
  }
}

// ============================================================
// HOME
// ============================================================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// ============================================================
// STATUS
// ============================================================

app.get(
  "/api/status",
  async (req, res) => {
    res.json({
      success: true,
      status: "online",
      service:
        "Shule Portal Tanzania"
    });
  }
);

// ============================================================
// DATABASE CHECK
// ============================================================

app.get(
  "/api/database-check",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          "SELECT NOW() AS now"
        );

      res.json({
        success: true,
        database: "connected",
        time:
          result.rows[0].now
      });
    } catch (error) {
      console.error(
        "Database check error:",
        error
      );

      res.status(500).json({
        success: false,
        database: "not connected",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// PUBLIC SCHOOLS
// ============================================================

app.get(
  "/api/schools",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            id,
            name,
            region,
            district,
            school_type,
            school_type AS type,
            form_price,
            form_price AS price,
            phone,
            address,
            email,
            application_start,
            application_end,
            status,
            description,
            logo_url,
            classes_offered,
            requirements,
            profile_completed,
            created_at,
            updated_at
          FROM schools
          WHERE status = 'active'
          ORDER BY name ASC
        `);

      res.json({
        success: true,
        schools:
          result.rows,
        count:
          result.rows.length
      });
    } catch (error) {
      console.error(
        "Schools error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// GET ONE SCHOOL
// ============================================================

app.get(
  "/api/schools/:id",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            region,
            district,
            school_type,
            form_price,
            phone,
            address,
            email,
            application_start,
            application_end,
            status,
            description,
            logo_url,
            classes_offered,
            requirements,
            profile_completed,
            created_at,
            updated_at
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Shule haikupatikana."
        });
      }

      res.json({
        success: true,
        school:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Get school error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - CREATE SCHOOL
// ============================================================

app.post(
  "/api/admin/schools",
  async (req, res) => {
    const {
      name,
      region,
      district,
      school_type,
      form_price,
      phone,
      address,
      email,
      application_start,
      application_end
    } = req.body;

    if (!name) {
      return res.status(400).json({
        success: false,
        message:
          "Jina la shule linahitajika.",
        error:
          "Jina la shule linahitajika."
      });
    }

    const price =
      Number(form_price || 0);

    try {
      const result =
        await pool.query(
          `
          INSERT INTO schools (
            name,
            region,
            district,
            school_type,
            form_price,
            phone,
            address,
            email,
            application_start,
            application_end,
            status,
            profile_completed
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            'draft',
            FALSE
          )
          RETURNING *
          `,
          [
            name,
            region || null,
            district || null,
            school_type || null,
            price,
            phone || null,
            address || null,
            email || null,
            application_start || null,
            application_end || null
          ]
        );

      res.status(201).json({
        success: true,
        message:
          "Shule imesajiliwa.",
        school:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Create school error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kusajili shule.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - LIST ALL SCHOOLS
// ============================================================

app.get(
  "/api/admin/schools",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            s.*,

            (
              SELECT COUNT(*)
              FROM applications a
              WHERE a.school_id = s.id
            ) AS application_count,

            (
              SELECT COUNT(*)
              FROM school_admins sa
              WHERE sa.school_id = s.id
            ) AS admin_count

          FROM schools s

          ORDER BY
            s.created_at DESC
        `);

      res.json({
        success: true,
        schools:
          result.rows
      });
    } catch (error) {
      console.error(
        "Admin schools error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata shule.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - CREATE SCHOOL ADMIN
// ============================================================

app.post(
  "/api/admin/school-admins",
  async (req, res) => {
    const {
      school_id,
      full_name,
      email,
      phone,
      password
    } = req.body;

    if (
      !school_id ||
      !full_name ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message:
          "school_id, full_name, email na password vinahitajika.",
        error:
          "school_id, full_name, email na password vinahitajika."
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        success: false,
        message:
          "Password lazima iwe na angalau herufi 6.",
        error:
          "Password lazima iwe na angalau herufi 6."
      });
    }

    try {
      const schoolResult =
        await pool.query(
          `
          SELECT id, name
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [Number(school_id)]
        );

      if (schoolResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Shule haikupatikana.",
          error:
            "Shule haikupatikana."
        });
      }

      const passwordHash =
        hashPassword(password);

      const result =
        await pool.query(
          `
          INSERT INTO school_admins (
            school_id,
            full_name,
            email,
            phone,
            password_hash,
            status
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            'active'
          )
          RETURNING
            id,
            school_id,
            full_name,
            email,
            phone,
            status,
            created_at,
            updated_at
          `,
          [
            Number(school_id),
            String(full_name).trim(),
            normalizeEmail(email),
            phone
              ? String(phone).trim()
              : null,
            passwordHash
          ]
        );

      res.status(201).json({
        success: true,
        message:
          "Admin wa shule ameundwa.",
        admin:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Create school admin error:",
        error
      );

      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          message:
            "Barua pepe hii tayari inatumika.",
          error:
            "Barua pepe hii tayari inatumika."
        });
      }

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuunda Admin wa shule.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - LIST SCHOOL ADMINS
// ============================================================

app.get(
  "/api/admin/school-admins",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            sa.id,
            sa.school_id,
            sa.full_name,
            sa.email,
            sa.phone,
            sa.status,
            sa.last_login,
            sa.created_at,
            sa.updated_at,
            s.name AS school_name
          FROM school_admins sa
          LEFT JOIN schools s
            ON s.id = sa.school_id
          ORDER BY
            sa.created_at DESC
          `
        );

      res.json({
        success: true,
        admins:
          result.rows,
        count:
          result.rows.length
      });
    } catch (error) {
      console.error(
        "Admin list error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata Admin wa shule.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - GET ONE SCHOOL ADMIN
// ============================================================

app.get(
  "/api/admin/school-admins/:id",
  async (req, res) => {
    const id =
      Number(req.params.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "ID ya Admin si sahihi.",
        error:
          "ID ya Admin si sahihi."
      });
    }

    try {
      const result =
        await pool.query(
          `
          SELECT
            sa.id,
            sa.school_id,
            sa.full_name,
            sa.phone,
            sa.email,
            sa.status,
            sa.last_login,
            sa.created_at,
            sa.updated_at,

            s.name AS school_name,
            s.region AS school_region,
            s.district AS school_district

          FROM school_admins sa

          LEFT JOIN schools s
            ON s.id = sa.school_id

          WHERE sa.id = $1

          LIMIT 1
          `,
          [id]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hakupatikana.",
          error:
            "Admin wa shule hakupatikana."
        });
      }

      res.json({
        success: true,
        admin:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Get school admin error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata Admin wa shule.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - UPDATE SCHOOL ADMIN
// ============================================================

app.put(
  "/api/admin/school-admins/:id",
  async (req, res) => {
    const id =
      Number(req.params.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "ID ya Admin si sahihi.",
        error:
          "ID ya Admin si sahihi."
      });
    }

    const {
      school_id,
      full_name,
      email,
      phone,
      status,
      password
    } = req.body;

    if (!full_name || !email) {
      return res.status(400).json({
        success: false,
        message:
          "Jina na email vinahitajika.",
        error:
          "Jina na email vinahitajika."
      });
    }

    const allowedStatuses = [
      "active",
      "inactive"
    ];

    const finalStatus =
      allowedStatuses.includes(status)
        ? status
        : "active";

    try {
      const existing =
        await pool.query(
          `
          SELECT id
          FROM school_admins
          WHERE id = $1
          LIMIT 1
          `,
          [id]
        );

      if (existing.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hakupatikana.",
          error:
            "Admin wa shule hakupatikana."
        });
      }

      if (school_id) {
        const schoolResult =
          await pool.query(
            `
            SELECT id
            FROM schools
            WHERE id = $1
            LIMIT 1
            `,
            [Number(school_id)]
          );

        if (schoolResult.rows.length === 0) {
          return res.status(404).json({
            success: false,
            message:
              "Shule haikupatikana.",
            error:
              "Shule haikupatikana."
          });
        }
      }

      let result;

      if (
        password &&
        String(password).trim() !== ""
      ) {
        if (String(password).length < 6) {
          return res.status(400).json({
            success: false,
            message:
              "Password lazima iwe na angalau herufi 6.",
            error:
              "Password lazima iwe na angalau herufi 6."
          });
        }

        result =
          await pool.query(
            `
            UPDATE school_admins
            SET
              school_id = COALESCE($1, school_id),
              full_name = $2,
              email = $3,
              phone = $4,
              password_hash = $5,
              status = $6,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = $7

            RETURNING
              id,
              school_id,
              full_name,
              email,
              phone,
              status,
              created_at,
              updated_at
            `,
            [
              school_id
                ? Number(school_id)
                : null,
              String(full_name).trim(),
              normalizeEmail(email),
              phone
                ? String(phone).trim()
                : null,
              hashPassword(password),
              finalStatus,
              id
            ]
          );
      } else {
        result =
          await pool.query(
            `
            UPDATE school_admins
            SET
              school_id = COALESCE($1, school_id),
              full_name = $2,
              email = $3,
              phone = $4,
              status = $5,
              updated_at = CURRENT_TIMESTAMP
            WHERE id = $6

            RETURNING
              id,
              school_id,
              full_name,
              email,
              phone,
              status,
              created_at,
              updated_at
            `,
            [
              school_id
                ? Number(school_id)
                : null,
              String(full_name).trim(),
              normalizeEmail(email),
              phone
                ? String(phone).trim()
                : null,
              finalStatus,
              id
            ]
          );
      }

      res.json({
        success: true,
        message:
          "Taarifa za Admin wa shule zimebadilishwa.",
        admin:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Update school admin error:",
        error
      );

      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          message:
            "Barua pepe hii tayari inatumika na Admin mwingine.",
          error:
            "Barua pepe hii tayari inatumika na Admin mwingine."
        });
      }

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kubadilisha taarifa za Admin.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - CHANGE SCHOOL ADMIN STATUS
// ============================================================

app.put(
  "/api/admin/school-admins/:id/status",
  async (req, res) => {
    const id =
      Number(req.params.id);

    const { status } = req.body;

    const allowedStatuses = [
      "active",
      "inactive"
    ];

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "ID ya Admin si sahihi.",
        error:
          "ID ya Admin si sahihi."
      });
    }

    if (
      !allowedStatuses.includes(status)
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Status lazima iwe active au inactive.",
        error:
          "Status lazima iwe active au inactive."
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            status = $1,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $2

          RETURNING
            id,
            school_id,
            full_name,
            email,
            phone,
            status,
            created_at,
            updated_at
          `,
          [
            status,
            id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hakupatikana.",
          error:
            "Admin wa shule hakupatikana."
        });
      }

      res.json({
        success: true,
        message:
          status === "active"
            ? "Admin wa shule amewashwa."
            : "Admin wa shule amezimwa.",
        admin:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Change school admin status error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kubadilisha status ya Admin.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - RESET SCHOOL ADMIN PASSWORD
// ============================================================

app.put(
  "/api/admin/school-admins/:id/reset-password",
  async (req, res) => {
    const id =
      Number(req.params.id);

    const { password } = req.body;

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "ID ya Admin si sahihi.",
        error:
          "ID ya Admin si sahihi."
      });
    }

    if (
      !password ||
      String(password).trim() === ""
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Password mpya inahitajika.",
        error:
          "Password mpya inahitajika."
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        success: false,
        message:
          "Password lazima iwe na angalau herufi 6.",
        error:
          "Password lazima iwe na angalau herufi 6."
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            password_hash = $1,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $2

          RETURNING
            id,
            school_id,
            full_name,
            phone,
            email,
            status,
            created_at,
            updated_at
          `,
          [
            hashPassword(password),
            id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hakupatikana.",
          error:
            "Admin wa shule hakupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Password imebadilishwa kikamilifu.",
        admin:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Reset school admin password error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kubadilisha password.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// OLD PASSWORD ENDPOINT
// ============================================================
// Inaachwa kwa compatibility kama kuna page ya zamani.

app.put(
  "/api/admin/school-admins/:id/password",
  async (req, res) => {
    const id =
      Number(req.params.id);

    const { password } = req.body;

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "ID ya Admin si sahihi.",
        error:
          "ID ya Admin si sahihi."
      });
    }

    if (
      !password ||
      String(password).length < 6
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Password lazima iwe na angalau herufi 6.",
        error:
          "Password lazima iwe na angalau herufi 6."
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            password_hash = $1,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $2
          RETURNING
            id,
            full_name,
            email
          `,
          [
            hashPassword(password),
            id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hakupatikana.",
          error:
            "Admin wa shule hakupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Password imebadilishwa.",
        admin:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Old reset password error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kubadilisha password.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - DELETE SCHOOL ADMIN
// ============================================================

app.delete(
  "/api/admin/school-admins/:id",
  async (req, res) => {
    const id =
      Number(req.params.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "ID ya Admin si sahihi.",
        error:
          "ID ya Admin si sahihi."
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      await client.query(
        `
        DELETE FROM school_admin_sessions
        WHERE school_admin_id = $1
        `,
        [id]
      );

      const result =
        await client.query(
          `
          DELETE FROM school_admins
          WHERE id = $1
          RETURNING
            id,
            full_name,
            email
          `,
          [id]
        );

      if (result.rows.length === 0) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hakupatikana.",
          error:
            "Admin wa shule hakupatikana."
        });
      }

      await client.query(
        "COMMIT"
      );

      res.json({
        success: true,
        message:
          "Admin wa shule amefutwa.",
        admin:
          result.rows[0]
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) {}

      console.error(
        "Delete school admin error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kufuta Admin wa shule.",
        error:
          error.message
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// CREATE APPLICATION
// ============================================================

app.post(
  "/api/applications",
  async (req, res) => {
    const {
      school_id,
      student_name,
      gender,
      date_of_birth,
      class_level,
      parent_name,
      phone,
      email,
      address
    } = req.body;

    if (!school_id) {
      return res.status(400).json({
        success: false,
        error:
          "school_id inahitajika."
      });
    }

    if (!student_name) {
      return res.status(400).json({
        success: false,
        error:
          "Jina la mwanafunzi linahitajika."
      });
    }

    if (!gender) {
      return res.status(400).json({
        success: false,
        error:
          "Jinsia inahitajika."
      });
    }

    if (!date_of_birth) {
      return res.status(400).json({
        success: false,
        error:
          "Tarehe ya kuzaliwa inahitajika."
      });
    }

    if (!class_level) {
      return res.status(400).json({
        success: false,
        error:
          "Darasa/Kidato kinahitajika."
      });
    }

    if (!parent_name) {
      return res.status(400).json({
        success: false,
        error:
          "Jina la mzazi/mlezi linahitajika."
      });
    }

    if (!phone) {
      return res.status(400).json({
        success: false,
        error:
          "Namba ya simu inahitajika."
      });
    }

    const client =
      await pool.connect();

    try {
      await client.query("BEGIN");

      const schoolResult =
        await client.query(
          `
          SELECT
            id,
            name,
            region,
            district,
            school_type,
            form_price,
            status
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [Number(school_id)]
        );

      if (schoolResult.rows.length === 0) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          error:
            "Shule haikupatikana."
        });
      }

      const school =
        schoolResult.rows[0];

      if (school.status !== "active") {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          error:
            "Shule hii haipokei maombi kwa sasa."
        });
      }

      const schoolFormPrice =
        Number(
          school.form_price
        );

      if (
        !Number.isFinite(
          schoolFormPrice
        ) ||
        schoolFormPrice <= 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          success: false,
          error:
            "Bei ya fomu ya shule haijawekwa vizuri."
        });
      }

      const applicationNumber =
        generateApplicationNumber();

      const applicationResult =
        await client.query(
          `
          INSERT INTO applications (
            application_number,
            school_id,
            student_name,
            gender,
            date_of_birth,
            class_level,
            parent_name,
            phone,
            email,
            address,
            status,
            payment_status
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            'pending',
            'unpaid'
          )
          RETURNING *
          `,
          [
            applicationNumber,
            Number(school_id),
            student_name.trim(),
            gender,
            date_of_birth,
            class_level,
            parent_name.trim(),
            phone.trim(),
            normalizeEmail(email),
            address || null
          ]
        );

      const application =
        applicationResult.rows[0];

      const paymentReference =
        generatePaymentReference();

      const paymentResult =
        await client.query(
          `
          INSERT INTO payments (
            application_id,
            application_number,
            payment_reference,
            amount,
            status,
            provider
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            'pending',
            'manual'
          )
          RETURNING *
          `,
          [
            application.id,
            applicationNumber,
            paymentReference,
            schoolFormPrice
          ]
        );

      const payment =
        paymentResult.rows[0];

      const savedAmount =
        Number(payment.amount);

      if (
        !Number.isFinite(
          savedAmount
        ) ||
        savedAmount <= 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(500).json({
          success: false,
          error:
            "Payment amount haijahifadhiwa vizuri."
        });
      }

      await client.query(
        "COMMIT"
      );

      return res.status(201).json({
        success: true,
        message:
          "Maombi yamehifadhiwa kikamilifu.",
        application,
        payment,
        school: {
          id: school.id,
          name: school.name,
          form_price:
            schoolFormPrice
        }
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) {}

      console.error(
        "CREATE APPLICATION ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Imeshindikana kuhifadhi maombi."
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// GET APPLICATION BY NUMBER
// ============================================================

app.get(
  "/api/application-by-number/:number",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            a.*,

            s.name AS school_name,
            s.region AS school_region,
            s.district AS school_district,
            s.school_type,
            s.form_price,

            p.id AS payment_id,
            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_status_detail,
            p.provider,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments
            WHERE application_id = a.id
            ORDER BY
              created_at DESC,
              id DESC
            LIMIT 1
          ) p
            ON TRUE

          WHERE
            a.application_number = $1

          LIMIT 1
          `,
          [req.params.number]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Maombi hayajapatikana."
        });
      }

      res.json({
        success: true,
        application:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Get application error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// GET APPLICATION BY ID
// ============================================================

app.get(
  "/api/applications/:id",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            a.*,

            s.name AS school_name,
            s.region AS school_region,
            s.district AS school_district,
            s.school_type,
            s.form_price,

            p.id AS payment_id,
            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_detail_status,
            p.provider,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments
            WHERE application_id = a.id
            ORDER BY created_at DESC, id DESC
            LIMIT 1
          ) p
            ON TRUE

          WHERE a.id = $1

          LIMIT 1
          `,
          [req.params.id]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Application haikupatikana."
        });
      }

      res.json({
        success: true,
        application:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Get application by id error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - ALL APPLICATIONS
// ============================================================

app.get(
  "/api/admin/applications",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            a.*,

            s.name AS school_name,
            s.region AS school_region,
            s.district AS school_district,

            p.id AS payment_id,
            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_status_detail,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments
            WHERE application_id = a.id
            ORDER BY created_at DESC, id DESC
            LIMIT 1
          ) p
            ON TRUE

          ORDER BY
            a.created_at DESC
        `);

      res.json({
        success: true,
        applications:
          result.rows,
        count:
          result.rows.length
      });
    } catch (error) {
      console.error(
        "Admin applications error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - UPDATE APPLICATION STATUS
// ============================================================

app.put(
  "/api/admin/applications/:id/status",
  async (req, res) => {
    const { status } = req.body;

    const allowed = [
      "pending",
      "approved",
      "rejected"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        success: false,
        error:
          "Status si sahihi."
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE applications
          SET
            status = $1,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $2
          RETURNING *
          `,
          [
            status,
            req.params.id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Application haikupatikana."
        });
      }

      res.json({
        success: true,
        application:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Update application status error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// MAIN ADMIN - PAYMENT LIST
// ============================================================

app.get(
  "/api/admin/payments",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            p.*,

            a.student_name,
            a.parent_name,
            a.phone,
            a.application_number,

            s.name AS school_name

          FROM payments p

          LEFT JOIN applications a
            ON a.id = p.application_id

          LEFT JOIN schools s
            ON s.id = a.school_id

          ORDER BY
            p.created_at DESC
        `);

      res.json({
        success: true,
        payments:
          result.rows,
        count:
          result.rows.length
      });
    } catch (error) {
      console.error(
        "Admin payments error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// CONFIRM PAYMENT - MAIN ADMIN
// ============================================================

app.put(
  "/api/admin/payments/:id/confirm",
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      const paymentResult =
        await client.query(
          `
          SELECT *
          FROM payments
          WHERE id = $1
          FOR UPDATE
          `,
          [req.params.id]
        );

      if (
        paymentResult.rows.length === 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          error:
            "Payment haikupatikana."
        });
      }

      const payment =
        paymentResult.rows[0];

      const updatedPayment =
        await client.query(
          `
          UPDATE payments
          SET
            status = 'paid',
            paid_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $1
          RETURNING *
          `,
          [payment.id]
        );

      await client.query(
        `
        UPDATE applications
        SET
          payment_status = 'paid',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        `,
        [payment.application_id]
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        success: true,
        message:
          "Malipo yamethibitishwa.",
        payment:
          updatedPayment.rows[0]
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (_) {}

      console.error(
        "Confirm payment error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// SCHOOL ADMIN LOGIN
// ============================================================

app.post(
  "/api/school-admin/login",
  async (req, res) => {
    const {
      email,
      password
    } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error:
          "Email na password vinahitajika."
      });
    }

    try {
      const result =
        await pool.query(
          `
          SELECT
            sa.*,

            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,
            s.status AS school_status

          FROM school_admins sa

          LEFT JOIN schools s
            ON s.id = sa.school_id

          WHERE
            LOWER(sa.email) = LOWER($1)

          LIMIT 1
          `,
          [
            normalizeEmail(email)
          ]
        );

      if (result.rows.length === 0) {
        return res.status(401).json({
          success: false,
          error:
            "Email au password si sahihi."
        });
      }

      const admin =
        result.rows[0];

      if (admin.status !== "active") {
        return res.status(403).json({
          success: false,
          error:
            "Account hii haipo active."
        });
      }

      if (
        !verifyPassword(
          password,
          admin.password_hash
        )
      ) {
        return res.status(401).json({
          success: false,
          error:
            "Email au password si sahihi."
        });
      }

      if (
        admin.school_status === "inactive" ||
        admin.school_status === "suspended"
      ) {
        return res.status(403).json({
          success: false,
          error:
            "Shule hii haipo active."
        });
      }

      const token =
        crypto
          .randomBytes(32)
          .toString("hex");

      const tokenHash =
        hashToken(token);

      await pool.query(
        `
        INSERT INTO school_admin_sessions (
          school_admin_id,
          token_hash,
          expires_at
        )
        VALUES (
          $1,
          $2,
          CURRENT_TIMESTAMP + INTERVAL '12 hours'
        )
        `,
        [
          admin.id,
          tokenHash
        ]
      );

      await pool.query(
        `
        UPDATE school_admins
        SET
          last_login = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        `,
        [admin.id]
      );

      res.cookie(
        "school_admin_token",
        token,
        {
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          maxAge:
            12 * 60 * 60 * 1000,
          path: "/"
        }
      );

      res.json({
        success: true,
        message:
          "Umeingia kikamilifu.",
        admin: {
          id: admin.id,
          school_id:
            admin.school_id,
          full_name:
            admin.full_name,
          email:
            admin.email,
          phone:
            admin.phone,
          school_name:
            admin.school_name
        }
      });
    } catch (error) {
      console.error(
        "School admin login error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN ME
// ============================================================

app.get(
  "/api/school-admin/me",
  requireSchoolAdmin,
  async (req, res) => {
    res.json({
      success: true,
      admin:
        req.schoolAdmin
    });
  }
);

// ============================================================
// SCHOOL ADMIN LOGOUT
// ============================================================

app.post(
  "/api/school-admin/logout",
  async (req, res) => {
    try {
      const token =
        getSchoolAdminToken(req);

      if (token) {
        await pool.query(
          `
          DELETE FROM school_admin_sessions
          WHERE token_hash = $1
          `,
          [
            hashToken(token)
          ]
        );
      }

      res.clearCookie(
        "school_admin_token",
        {
          path: "/"
        }
      );

      res.json({
        success: true,
        message:
          "Umetoka kwenye mfumo."
      });
    } catch (error) {
      console.error(
        "Logout error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN PROFILE
// ============================================================

app.get(
  "/api/school-admin/profile",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT *
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [
            req.schoolAdmin.school_id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Shule haikupatikana."
        });
      }

      res.json({
        success: true,
        school:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "School profile error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN UPDATE PROFILE
// ============================================================

app.put(
  "/api/school-admin/profile",
  requireSchoolAdmin,
  async (req, res) => {
    const {
      description,
      logo_url,
      classes_offered,
      requirements,
      phone,
      address,
      email,
      form_price,
      application_start,
      application_end
    } = req.body;

    try {
      const result =
        await pool.query(
          `
          UPDATE schools
          SET
            description = $1,
            logo_url = $2,
            classes_offered = $3,
            requirements = $4,
            phone = $5,
            address = $6,
            email = $7,
            form_price = $8,
            application_start = $9,
            application_end = $10,
            profile_completed = TRUE,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $11
          RETURNING *
          `,
          [
            description || null,
            logo_url || null,
            classes_offered || null,
            requirements || null,
            phone || null,
            address || null,
            email || null,
            Number(form_price || 0),
            application_start || null,
            application_end || null,
            req.schoolAdmin.school_id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Shule haikupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Taarifa za shule zimehifadhiwa.",
        school:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Update school profile error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN GO LIVE
// ============================================================

app.put(
  "/api/school-admin/go-live",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          UPDATE schools
          SET
            status = 'active',
            profile_completed = TRUE,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $1
          RETURNING *
          `,
          [
            req.schoolAdmin.school_id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Shule haikupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Shule imewekwa LIVE.",
        school:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Go live error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN APPLICATIONS
// ============================================================

app.get(
  "/api/school-admin/applications",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            a.*,

            p.id AS payment_id,
            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_status_detail,
            p.paid_at

          FROM applications a

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments
            WHERE
              application_id = a.id
            ORDER BY
              created_at DESC,
              id DESC
            LIMIT 1
          ) p
            ON TRUE

          WHERE
            a.school_id = $1

          ORDER BY
            a.created_at DESC
          `,
          [
            req.schoolAdmin.school_id
          ]
        );

      res.json({
        success: true,
        applications:
          result.rows,
        count:
          result.rows.length
      });
    } catch (error) {
      console.error(
        "School admin applications error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN APPLICATION STATUS
// ============================================================

app.put(
  "/api/school-admin/applications/:id/status",
  requireSchoolAdmin,
  async (req, res) => {
    const { status } = req.body;

    const allowed = [
      "pending",
      "approved",
      "rejected"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        success: false,
        error:
          "Status si sahihi."
      });
    }

    try {
      const result =
        await pool.query(
          `
          UPDATE applications
          SET
            status = $1,
            updated_at = CURRENT_TIMESTAMP
          WHERE
            id = $2
            AND school_id = $3
          RETURNING *
          `,
          [
            status,
            req.params.id,
            req.schoolAdmin.school_id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Application haikupatikana."
        });
      }

      res.json({
        success: true,
        application:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "School admin update application error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN DASHBOARD STATS
// ============================================================

app.get(
  "/api/school-admin/dashboard-stats",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            COUNT(*)::INTEGER AS total,
            COUNT(*) FILTER (
              WHERE status = 'pending'
            )::INTEGER AS pending,
            COUNT(*) FILTER (
              WHERE status = 'approved'
            )::INTEGER AS approved,
            COUNT(*) FILTER (
              WHERE status = 'rejected'
            )::INTEGER AS rejected,
            COUNT(*) FILTER (
              WHERE payment_status = 'paid'
            )::INTEGER AS paid,
            COUNT(*) FILTER (
              WHERE payment_status <> 'paid'
                OR payment_status IS NULL
            )::INTEGER AS unpaid
          FROM applications
          WHERE school_id = $1
          `,
          [
            req.schoolAdmin.school_id
          ]
        );

      res.json({
        success: true,
        stats:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "Dashboard stats error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN - GET APPLICATION
// ============================================================

app.get(
  "/api/school-admin/applications/:id",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            a.*,

            p.id AS payment_id,
            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_status_detail,
            p.provider,
            p.provider_reference,
            p.paid_at,

            s.name AS school_name,
            s.region AS school_region,
            s.district AS school_district,
            s.school_type,
            s.form_price

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments
            WHERE
              application_id = a.id
            ORDER BY
              created_at DESC,
              id DESC
            LIMIT 1
          ) p
            ON TRUE

          WHERE
            a.id = $1
            AND a.school_id = $2

          LIMIT 1
          `,
          [
            req.params.id,
            req.schoolAdmin.school_id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error:
            "Application haikupatikana."
        });
      }

      res.json({
        success: true,
        application:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "School admin get application error:",
        error
      );

      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// APPLICATION SCHEMA CHECK
// ============================================================

app.get(
  "/api/application-schema",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            column_name,
            data_type,
            is_nullable,
            column_default
          FROM information_schema.columns
          WHERE table_name = 'applications'
          ORDER BY ordinal_position
        `);

      res.json({
        success: true,
        columns:
          result.rows
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// PAYMENT SCHEMA CHECK
// ============================================================

app.get(
  "/api/payment-schema",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            column_name,
            data_type,
            is_nullable,
            column_default
          FROM information_schema.columns
          WHERE table_name = 'payments'
          ORDER BY ordinal_position
        `);

      res.json({
        success: true,
        columns:
          result.rows
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error:
          error.message
      });
    }
  }
);

// ============================================================
// 404 API
// ============================================================

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        "API endpoint haikupatikana.",
      error:
        "API endpoint haikupatikana."
    });
  }
);

// ============================================================
// GENERAL ERROR
// ============================================================

app.use(
  (error, req, res, next) => {
    console.error(
      "Unhandled error:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        error.message ||
        "Internal server error.",
      error:
        error.message ||
        "Internal server error."
    });
  }
);

// ============================================================
// START SERVER
// ============================================================

async function startServer() {
  try {
    await setupDatabase();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Shule Portal Tanzania running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "SERVER START FAILED:",
      error
    );

    process.exit(1);
  }
}

startServer();