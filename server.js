const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "shule-portal-tanzania-session-secret-2026-change-this";

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

pool.on("error", (err) => {
  console.error("POSTGRES ERROR:", err);
});

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname)));

// ============================================================
// HELPERS
// ============================================================

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function generateApplicationNumber() {
  const year = new Date().getFullYear();

  const timestamp = Date.now();

  const random = crypto
    .randomBytes(2)
    .toString("hex")
    .toUpperCase();

  return `SPT-${year}-${timestamp}-${random}`;
}

function generatePaymentReference() {
  const year = new Date().getFullYear();

  const timestamp = Date.now();

  const random = crypto
    .randomBytes(2)
    .toString("hex")
    .toUpperCase();

  return `PAY-${year}-${timestamp}-${random}`;
}

function getCookie(req, name) {
  const header = req.headers.cookie;

  if (!header) {
    return null;
  }

  const cookies = header.split(";");

  for (const item of cookies) {
    const parts = item.trim().split("=");

    const key = parts.shift();

    const value = parts.join("=");

    if (key === name) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
}

// ============================================================
// SCHOOL ADMIN SECURE TOKEN
// ============================================================

function createSchoolAdminToken(adminId) {
  const payload = `${adminId}.${Date.now()}`;

  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("hex");

  return `${payload}.${signature}`;
}

function verifySchoolAdminToken(token) {
  try {
    if (!token) {
      return null;
    }

    const parts = token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const adminId = Number(parts[0]);

    const timestamp = Number(parts[1]);

    const signature = parts[2];

    if (
      !adminId ||
      !timestamp ||
      !signature
    ) {
      return null;
    }

    const age =
      Date.now() - timestamp;

    // Token expires after 12 hours
    if (
      age > 12 * 60 * 60 * 1000
    ) {
      return null;
    }

    // Future timestamps are invalid
    if (age < 0) {
      return null;
    }

    const payload =
      `${adminId}.${timestamp}`;

    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          SESSION_SECRET
        )
        .update(payload)
        .digest("hex");

    if (
      signature.length !==
      expectedSignature.length
    ) {
      return null;
    }

    const valid =
      crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      );

    if (!valid) {
      return null;
    }

    return adminId;

  } catch (error) {

    console.error(
      "TOKEN VERIFY ERROR:",
      error
    );

    return null;
  }
}

function setSchoolAdminCookie(
  res,
  token
) {
  res.setHeader(
    "Set-Cookie",
    `school_admin_token=${encodeURIComponent(
      token
    )}; HttpOnly; Secure; SameSite=Lax; Max-Age=43200; Path=/`
  );
}

function clearSchoolAdminCookie(res) {
  res.setHeader(
    "Set-Cookie",
    "school_admin_token=; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Path=/"
  );
}

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function initializeDatabase() {

  try {

    console.log(
      "===================================="
    );

    console.log(
      "INITIALIZING DATABASE"
    );

    console.log(
      "===================================="
    );

    // --------------------------------------------------------
    // SCHOOLS
    // --------------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS schools (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        region VARCHAR(255),
        district VARCHAR(255),
        school_type VARCHAR(255),
        type VARCHAR(255),
        form_price NUMERIC(12,2) DEFAULT 0,
        phone VARCHAR(100),
        address TEXT,
        email VARCHAR(255),
        application_start TIMESTAMP,
        application_end TIMESTAMP,
        status VARCHAR(50) DEFAULT 'draft',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // --------------------------------------------------------
    // APPLICATIONS
    // --------------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        application_number VARCHAR(255) UNIQUE,
        school_id INTEGER REFERENCES schools(id) ON DELETE CASCADE,
        student_name VARCHAR(255),
        gender VARCHAR(50),
        date_of_birth DATE,
        class_applied VARCHAR(255),
        parent_name VARCHAR(255),
        parent_phone VARCHAR(100),
        parent_email VARCHAR(255),
        address TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // --------------------------------------------------------
    // PAYMENTS
    // --------------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        application_id INTEGER REFERENCES applications(id) ON DELETE CASCADE,
        application_number VARCHAR(255),
        payment_reference VARCHAR(255) UNIQUE,
        amount NUMERIC(12,2) DEFAULT 0,
        status VARCHAR(50) DEFAULT 'pending',
        payment_method VARCHAR(100),
        transaction_reference VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // --------------------------------------------------------
    // SCHOOL ADMINS
    // --------------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS school_admins (
        id SERIAL PRIMARY KEY,
        school_id INTEGER REFERENCES schools(id) ON DELETE CASCADE,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(100),
        password_hash TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'active',
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // --------------------------------------------------------
    // OLD SCHOOL ADMIN SESSIONS TABLE
    // --------------------------------------------------------
    // Table inaweza kubaki database.
    // Mfumo mpya wa login hauitegemei.

    await pool.query(`
      CREATE TABLE IF NOT EXISTS school_admin_sessions (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES school_admins(id) ON DELETE CASCADE,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // --------------------------------------------------------
    // MIGRATIONS
    // --------------------------------------------------------

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS school_type VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS type VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS form_price NUMERIC(12,2) DEFAULT 0
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS phone VARCHAR(100)
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS address TEXT
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS email VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS application_start TIMESTAMP
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS application_end TIMESTAMP
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'draft'
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending'
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS transaction_reference VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS payment_method VARCHAR(100)
    `);

    await pool.query(`
      ALTER TABLE school_admins
      ADD COLUMN IF NOT EXISTS phone VARCHAR(100)
    `);

    await pool.query(`
      ALTER TABLE school_admins
      ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'active'
    `);

    await pool.query(`
      ALTER TABLE school_admins
      ADD COLUMN IF NOT EXISTS last_login TIMESTAMP
    `);

    await pool.query(`
      ALTER TABLE school_admins
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
    `);

    await pool.query(`
      ALTER TABLE school_admins
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
    `);

    // --------------------------------------------------------
    // INDEXES
    // --------------------------------------------------------

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_school
      ON applications(school_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_number
      ON applications(application_number)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_payments_application
      ON payments(application_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_school_admins_school
      ON school_admins(school_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_school_admin_sessions_token
      ON school_admin_sessions(token)
    `);

    console.log(
      "DATABASE INITIALIZATION COMPLETE"
    );

    console.log(
      "===================================="
    );

  } catch (error) {

    console.error(
      "DATABASE INITIALIZATION ERROR:"
    );

    console.error(error);
  }
}

// ============================================================
// STATUS
// ============================================================

app.get(
  "/api/status",
  async (req, res) => {

    try {

      await pool.query(
        "SELECT NOW()"
      );

      res.json({
        success: true,
        message:
          "Shule Portal Tanzania iko online.",
        database: true
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          "Server ipo online lakini database ina tatizo.",
        database: false,
        error:
          error.message
      });
    }
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
        message:
          "Database imeunganishwa vizuri.",
        time:
          result.rows[0].now
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          "Database haijaunganishwa.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// APPLICATION SCHEMA
// ============================================================

app.get(
  "/api/application-schema",
  async (req, res) => {

    try {

      const result =
        await pool.query(`
          SELECT
            column_name,
            data_type
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
// PAYMENT SCHEMA
// ============================================================

app.get(
  "/api/payment-schema",
  async (req, res) => {

    try {

      const result =
        await pool.query(`
          SELECT
            column_name,
            data_type
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
            type,
            form_price,
            phone,
            address,
            email,
            application_start,
            application_end,
            status,
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
        "PUBLIC SCHOOLS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// PUBLIC SCHOOL
// ============================================================

app.get(
  "/api/schools/:id",
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT *
          FROM schools
          WHERE id = $1
          AND status = 'active'
          `,
          [req.params.id]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
        });
      }

      res.json({
        success: true,
        school:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// ADMIN SCHOOLS
// ============================================================

app.get(
  "/api/admin/schools",
  async (req, res) => {

    try {

      const result =
        await pool.query(`
          SELECT
            s.*,
            COUNT(a.id)::INTEGER AS applicants_count
          FROM schools s
          LEFT JOIN applications a
            ON a.school_id = s.id
          GROUP BY s.id
          ORDER BY s.id DESC
        `);

      res.json({
        success: true,
        schools:
          result.rows
      });

    } catch (error) {

      console.error(
        "ADMIN SCHOOLS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// CREATE SCHOOL
// ============================================================

app.post(
  "/api/admin/schools",
  async (req, res) => {

    try {

      const {
        name,
        region,
        district,
        school_type,
        type,
        form_price,
        phone,
        address,
        email,
        application_start,
        application_end,
        status
      } = req.body;

      if (!name) {

        return res.status(400).json({
          success: false,
          message:
            "Jina la shule linahitajika."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO schools
          (
            name,
            region,
            district,
            school_type,
            type,
            form_price,
            phone,
            address,
            email,
            application_start,
            application_end,
            status
          )
          VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
          RETURNING *
          `,
          [
            name,
            region || null,
            district || null,
            school_type ||
              type ||
              null,
            type ||
              school_type ||
              null,
            Number(
              form_price || 0
            ),
            phone || null,
            address || null,
            email || null,
            application_start ||
              null,
            application_end ||
              null,
            status ||
              "draft"
          ]
        );

      res.json({
        success: true,
        message:
          "Shule imesajiliwa.",
        school:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "CREATE SCHOOL ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// UPDATE SCHOOL
// ============================================================

app.put(
  "/api/admin/schools/:id",
  async (req, res) => {

    try {

      const {
        name,
        region,
        district,
        school_type,
        type,
        form_price,
        phone,
        address,
        email,
        application_start,
        application_end,
        status
      } = req.body;

      const result =
        await pool.query(
          `
          UPDATE schools
          SET
            name = COALESCE($1,name),
            region = COALESCE($2,region),
            district = COALESCE($3,district),
            school_type =
              COALESCE($4,school_type),
            type =
              COALESCE($5,type),
            form_price =
              COALESCE($6,form_price),
            phone =
              COALESCE($7,phone),
            address =
              COALESCE($8,address),
            email =
              COALESCE($9,email),
            application_start =
              COALESCE(
                $10,
                application_start
              ),
            application_end =
              COALESCE(
                $11,
                application_end
              ),
            status =
              COALESCE($12,status),
            updated_at = NOW()
          WHERE id = $13
          RETURNING *
          `,
          [
            name || null,
            region || null,
            district || null,
            school_type ||
              type ||
              null,
            type ||
              school_type ||
              null,
            form_price !== undefined
              ? Number(form_price)
              : null,
            phone || null,
            address || null,
            email || null,
            application_start ||
              null,
            application_end ||
              null,
            status || null,
            req.params.id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
        });
      }

      res.json({
        success: true,
        message:
          "Taarifa za shule zimebadilishwa.",
        school:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "UPDATE SCHOOL ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMINS - LIST
// ============================================================

app.get(
  "/api/admin/school-admins",
  async (req, res) => {

    try {

      const result =
        await pool.query(`
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
          ORDER BY sa.id DESC
        `);

      res.json({
        success: true,
        admins:
          result.rows
      });

    } catch (error) {

      console.error(
        "SCHOOL ADMINS LIST ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN - SINGLE
// ============================================================

app.get(
  "/api/admin/school-admins/:id",
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
          WHERE sa.id = $1
          `,
          [req.params.id]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hakupatikana."
        });
      }

      res.json({
        success: true,
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "SINGLE SCHOOL ADMIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// CREATE SCHOOL ADMIN
// ============================================================

app.post(
  "/api/admin/school-admins",
  async (req, res) => {

    try {

      const {
        school_id,
        full_name,
        email,
        phone,
        password,
        status
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
            "School, jina, email na password vinahitajika."
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      const existing =
        await pool.query(
          `
          SELECT id
          FROM school_admins
          WHERE LOWER(TRIM(email)) = $1
          `,
          [normalizedEmail]
        );

      if (
        existing.rows.length > 0
      ) {

        return res.status(409).json({
          success: false,
          message:
            "Email hiyo tayari ipo."
        });
      }

      const school =
        await pool.query(
          `
          SELECT id
          FROM schools
          WHERE id = $1
          `,
          [school_id]
        );

      if (
        school.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO school_admins
          (
            school_id,
            full_name,
            email,
            phone,
            password_hash,
            status
          )
          VALUES
          ($1,$2,$3,$4,$5,$6)
          RETURNING
            id,
            school_id,
            full_name,
            email,
            phone,
            status,
            created_at
          `,
          [
            school_id,
            full_name,
            normalizedEmail,
            phone || null,
            hashPassword(
              password
            ),
            status ||
              "active"
          ]
        );

      res.json({
        success: true,
        message:
          "School Admin ameundwa.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "CREATE SCHOOL ADMIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// UPDATE SCHOOL ADMIN
// ============================================================

app.put(
  "/api/admin/school-admins/:id",
  async (req, res) => {

    try {

      const {
        school_id,
        full_name,
        email,
        phone,
        status
      } = req.body;

      let normalizedEmail =
        null;

      if (email) {

        normalizedEmail =
          String(email)
            .trim()
            .toLowerCase();

        const duplicate =
          await pool.query(
            `
            SELECT id
            FROM school_admins
            WHERE LOWER(TRIM(email)) = $1
            AND id <> $2
            `,
            [
              normalizedEmail,
              req.params.id
            ]
          );

        if (
          duplicate.rows.length > 0
        ) {

          return res.status(409).json({
            success: false,
            message:
              "Email hiyo tayari inatumika."
          });
        }
      }

      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            school_id =
              COALESCE(
                $1,
                school_id
              ),
            full_name =
              COALESCE(
                $2,
                full_name
              ),
            email =
              COALESCE(
                $3,
                email
              ),
            phone =
              COALESCE(
                $4,
                phone
              ),
            status =
              COALESCE(
                $5,
                status
              ),
            updated_at = NOW()
          WHERE id = $6
          RETURNING
            id,
            school_id,
            full_name,
            email,
            phone,
            status,
            last_login,
            updated_at
          `,
          [
            school_id || null,
            full_name || null,
            normalizedEmail,
            phone || null,
            status || null,
            req.params.id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hakupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "School Admin amesasishwa.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "UPDATE SCHOOL ADMIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN STATUS
// ============================================================

app.put(
  "/api/admin/school-admins/:id/status",
  async (req, res) => {

    try {

      const {
        status
      } = req.body;

      const allowed = [
        "active",
        "inactive",
        "suspended"
      ];

      if (
        !allowed.includes(status)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Status si sahihi."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            status = $1,
            updated_at = NOW()
          WHERE id = $2
          RETURNING
            id,
            full_name,
            email,
            status
          `,
          [
            status,
            req.params.id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hakupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Status imebadilishwa.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "ADMIN STATUS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// RESET PASSWORD
// ============================================================

app.put(
  "/api/admin/school-admins/:id/reset-password",
  async (req, res) => {

    try {

      const {
        password
      } = req.body;

      if (
        !password ||
        String(password).length < 4
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Password lazima iwe na angalau herufi 4."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            password_hash = $1,
            updated_at = NOW()
          WHERE id = $2
          RETURNING
            id,
            full_name,
            email
          `,
          [
            hashPassword(
              password
            ),
            req.params.id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hakupatikana."
        });
      }

      // Hakuna tena DELETE FROM school_admin_sessions.
      // Login mpya haitumii sessions table.

      res.json({
        success: true,
        message:
          "Password imebadilishwa.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "RESET PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// OLD PASSWORD ROUTE
// ============================================================

app.put(
  "/api/admin/school-admins/:id/password",
  async (req, res) => {

    try {

      const {
        password
      } = req.body;

      if (
        !password ||
        String(password).length < 4
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Password si sahihi."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            password_hash = $1,
            updated_at = NOW()
          WHERE id = $2
          RETURNING
            id,
            full_name,
            email
          `,
          [
            hashPassword(
              password
            ),
            req.params.id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hakupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Password imebadilishwa."
      });

    } catch (error) {

      console.error(
        "PASSWORD UPDATE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// DELETE SCHOOL ADMIN
// ============================================================

app.delete(
  "/api/admin/school-admins/:id",
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          DELETE FROM school_admins
          WHERE id = $1
          RETURNING
            id,
            full_name,
            email
          `,
          [req.params.id]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hakupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "School Admin amefutwa."
      });

    } catch (error) {

      console.error(
        "DELETE SCHOOL ADMIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN LOGIN
// ============================================================

app.post(
  "/api/school-admin/login",
  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body;

      console.log(
        "===================================="
      );

      console.log(
        "SCHOOL ADMIN LOGIN"
      );

      console.log(
        "EMAIL:",
        email
      );

      console.log(
        "===================================="
      );

      if (
        !email ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Email na password vinahitajika."
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      // ------------------------------------------------------
      // SEARCH ADMIN
      // ------------------------------------------------------

      const adminResult =
        await pool.query(
          `
          SELECT
            id,
            school_id,
            full_name,
            email,
            phone,
            password_hash,
            status
          FROM school_admins
          WHERE LOWER(TRIM(email)) = $1
          LIMIT 1
          `,
          [normalizedEmail]
        );

      console.log(
        "ADMIN FOUND:",
        adminResult.rows.length
      );

      if (
        adminResult.rows.length === 0
      ) {

        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });
      }

      const admin =
        adminResult.rows[0];

      // ------------------------------------------------------
      // PASSWORD
      // ------------------------------------------------------

      const suppliedHash =
        hashPassword(password);

      if (
        !admin.password_hash ||
        suppliedHash !==
          admin.password_hash
      ) {

        console.log(
          "PASSWORD DOES NOT MATCH"
        );

        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });
      }

      console.log(
        "PASSWORD CORRECT"
      );

      // ------------------------------------------------------
      // ADMIN STATUS
      // ------------------------------------------------------

      if (
        admin.status !==
        "active"
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Akaunti yako ya School Admin haijawezeshwa."
        });
      }

      // ------------------------------------------------------
      // SCHOOL
      // ------------------------------------------------------

      const schoolResult =
        await pool.query(
          `
          SELECT
            id,
            name,
            region,
            district,
            school_type,
            type,
            form_price,
            phone,
            address,
            email,
            application_start,
            application_end,
            status
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [admin.school_id]
        );

      if (
        schoolResult.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule iliyounganishwa na akaunti hii haipatikani."
        });
      }

      const school =
        schoolResult.rows[0];

      // Draft inaruhusiwa kuingia.
      // Inactive/suspended haziruhusiwi.

      if (
        school.status ===
          "inactive" ||
        school.status ===
          "suspended"
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Shule hii haijawezeshwa kwa sasa."
        });
      }

      // ------------------------------------------------------
      // CREATE SIGNED TOKEN
      // ------------------------------------------------------

      const token =
        createSchoolAdminToken(
          admin.id
        );

      console.log(
        "TOKEN CREATED"
      );

      // ------------------------------------------------------
      // LAST LOGIN
      // ------------------------------------------------------

      await pool.query(
        `
        UPDATE school_admins
        SET
          last_login = NOW()
        WHERE id = $1
        `,
        [admin.id]
      );

      console.log(
        "LAST LOGIN UPDATED"
      );

      // ------------------------------------------------------
      // COOKIE
      // ------------------------------------------------------

      setSchoolAdminCookie(
        res,
        token
      );

      console.log(
        "COOKIE SET"
      );

      // ------------------------------------------------------
      // SUCCESS
      // ------------------------------------------------------

      return res.json({
        success: true,
        message:
          "Umefanikiwa kuingia.",
        admin: {
          id:
            admin.id,

          full_name:
            admin.full_name,

          email:
            admin.email,

          phone:
            admin.phone,

          school_id:
            admin.school_id,

          school_name:
            school.name,

          school_status:
            school.status
        }
      });

    } catch (error) {

      console.error(
        "===================================="
      );

      console.error(
        "SCHOOL ADMIN LOGIN ERROR"
      );

      console.error(
        error
      );

      console.error(
        "===================================="
      );

      return res.status(500).json({
        success: false,
        message:
          "Hitilafu ya server wakati wa kuingia.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN AUTH
// ============================================================

async function requireSchoolAdmin(
  req,
  res,
  next
) {

  try {

    const token =
      getCookie(
        req,
        "school_admin_token"
      );

    if (!token) {

      return res.status(401).json({
        success: false,
        message:
          "Hujaingia kama School Admin."
      });
    }

    // --------------------------------------------------------
    // VERIFY SIGNED TOKEN
    // --------------------------------------------------------

    const adminId =
      verifySchoolAdminToken(
        token
      );

    if (!adminId) {

      clearSchoolAdminCookie(
        res
      );

      return res.status(401).json({
        success: false,
        message:
          "Session imekwisha. Ingia tena."
      });
    }

    // --------------------------------------------------------
    // LOAD ADMIN + SCHOOL
    // --------------------------------------------------------

    const result =
      await pool.query(
        `
        SELECT
          sa.id,
          sa.full_name,
          sa.email,
          sa.phone,
          sa.school_id,
          sa.status AS admin_status,

          s.name AS school_name,
          s.region,
          s.district,
          s.school_type,
          s.type,
          s.form_price,
          s.phone AS school_phone,
          s.address AS school_address,
          s.email AS school_email,
          s.application_start,
          s.application_end,
          s.status AS school_status

        FROM school_admins sa

        LEFT JOIN schools s
          ON s.id = sa.school_id

        WHERE sa.id = $1

        LIMIT 1
        `,
        [adminId]
      );

    if (
      result.rows.length === 0
    ) {

      clearSchoolAdminCookie(
        res
      );

      return res.status(401).json({
        success: false,
        message:
          "Akaunti ya School Admin haipatikani."
      });
    }

    const admin =
      result.rows[0];

    // --------------------------------------------------------
    // ADMIN STATUS
    // --------------------------------------------------------

    if (
      admin.admin_status !==
      "active"
    ) {

      clearSchoolAdminCookie(
        res
      );

      return res.status(403).json({
        success: false,
        message:
          "Akaunti yako haijawezeshwa."
      });
    }

    // --------------------------------------------------------
    // SCHOOL STATUS
    // --------------------------------------------------------

    if (
      admin.school_status ===
        "inactive" ||
      admin.school_status ===
        "suspended"
    ) {

      return res.status(403).json({
        success: false,
        message:
          "Shule haijawezeshwa."
      });
    }

    // --------------------------------------------------------
    // ATTACH ADMIN TO REQUEST
    // --------------------------------------------------------

    req.schoolAdmin =
      admin;

    next();

  } catch (error) {

    console.error(
      "AUTH ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Hitilafu ya authentication.",
      error:
        error.message
    });
  }
}

// ============================================================
// SCHOOL ADMIN ME
// ============================================================

app.get(
  "/api/school-admin/me",
  requireSchoolAdmin,
  async (req, res) => {

    return res.json({
      success: true,
      admin:
        req.schoolAdmin
    });

  }
);

// ============================================================
// LOGOUT
// ============================================================

app.post(
  "/api/school-admin/logout",
  async (req, res) => {

    try {

      // Token mpya haitumii database.
      // Kwa logout tunafuta cookie ya browser.

      clearSchoolAdminCookie(
        res
      );

      return res.json({
        success: true,
        message:
          "Umetoka kwenye mfumo."
      });

    } catch (error) {

      console.error(
        "LOGOUT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// DASHBOARD STATS
// ============================================================

app.get(
  "/api/school-admin/dashboard-stats",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const schoolId =
        req.schoolAdmin.school_id;

      const total =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS total
          FROM applications
          WHERE school_id = $1
          `,
          [schoolId]
        );

      const pending =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS total
          FROM applications
          WHERE school_id = $1
          AND status = 'pending'
          `,
          [schoolId]
        );

      const approved =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS total
          FROM applications
          WHERE school_id = $1
          AND status = 'approved'
          `,
          [schoolId]
        );

      const rejected =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS total
          FROM applications
          WHERE school_id = $1
          AND status = 'rejected'
          `,
          [schoolId]
        );

      const paid =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS total
          FROM payments p
          JOIN applications a
            ON a.id = p.application_id
          WHERE a.school_id = $1
          AND p.status IN
          (
            'paid',
            'confirmed',
            'completed'
          )
          `,
          [schoolId]
        );

      res.json({
        success: true,
        stats: {
          total_applications:
            total.rows[0].total,

          pending:
            pending.rows[0].total,

          approved:
            approved.rows[0].total,

          rejected:
            rejected.rows[0].total,

          paid:
            paid.rows[0].total
        }
      });

    } catch (error) {

      console.error(
        "DASHBOARD ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
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

            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_status,
            p.payment_method,
            p.transaction_reference

          FROM applications a

          LEFT JOIN payments p
            ON p.application_id = a.id

          WHERE a.school_id = $1

          ORDER BY a.created_at DESC
          `,
          [
            req.schoolAdmin.school_id
          ]
        );

      res.json({
        success: true,
        applications:
          result.rows
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// SINGLE APPLICATION FOR SCHOOL ADMIN
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

            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_status,
            p.payment_method,
            p.transaction_reference

          FROM applications a

          LEFT JOIN payments p
            ON p.application_id = a.id

          WHERE a.id = $1
          AND a.school_id = $2

          LIMIT 1
          `,
          [
            req.params.id,
            req.schoolAdmin.school_id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Application haipatikani."
        });
      }

      res.json({
        success: true,
        application:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// UPDATE APPLICATION STATUS
// ============================================================

app.put(
  "/api/school-admin/applications/:id/status",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const allowed = [
        "pending",
        "approved",
        "rejected"
      ];

      if (
        !allowed.includes(
          req.body.status
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Status si sahihi."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE applications
          SET
            status = $1,
            updated_at = NOW()
          WHERE id = $2
          AND school_id = $3
          RETURNING *
          `,
          [
            req.body.status,
            req.params.id,
            req.schoolAdmin.school_id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Application haipatikani."
        });
      }

      res.json({
        success: true,
        message:
          "Status imebadilishwa.",
        application:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// UPDATE SCHOOL BY SCHOOL ADMIN
// ============================================================

app.put(
  "/api/school-admin/school",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          UPDATE schools
          SET
            name =
              COALESCE(
                $1,
                name
              ),

            region =
              COALESCE(
                $2,
                region
              ),

            district =
              COALESCE(
                $3,
                district
              ),

            school_type =
              COALESCE(
                $4,
                school_type
              ),

            type =
              COALESCE(
                $5,
                type
              ),

            form_price =
              COALESCE(
                $6,
                form_price
              ),

            phone =
              COALESCE(
                $7,
                phone
              ),

            address =
              COALESCE(
                $8,
                address
              ),

            email =
              COALESCE(
                $9,
                email
              ),

            application_start =
              COALESCE(
                $10,
                application_start
              ),

            application_end =
              COALESCE(
                $11,
                application_end
              ),

            updated_at = NOW()

          WHERE id = $12

          RETURNING *
          `,
          [
            req.body.name || null,

            req.body.region || null,

            req.body.district || null,

            req.body.school_type ||
              req.body.type ||
              null,

            req.body.type ||
              req.body.school_type ||
              null,

            req.body.form_price !==
            undefined
              ? Number(
                  req.body.form_price
                )
              : null,

            req.body.phone ||
              null,

            req.body.address ||
              null,

            req.body.email ||
              null,

            req.body.application_start ||
              null,

            req.body.application_end ||
              null,

            req.schoolAdmin.school_id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
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
        "SCHOOL UPDATE ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// PUBLISH SCHOOL
// ============================================================

app.put(
  "/api/school-admin/school/publish",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          UPDATE schools
          SET
            status = 'active',
            updated_at = NOW()
          WHERE id = $1
          RETURNING *
          `,
          [
            req.schoolAdmin.school_id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
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

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// UNPUBLISH SCHOOL
// ============================================================

app.put(
  "/api/school-admin/school/unpublish",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          UPDATE schools
          SET
            status = 'draft',
            updated_at = NOW()
          WHERE id = $1
          RETURNING *
          `,
          [
            req.schoolAdmin.school_id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
        });
      }

      res.json({
        success: true,
        message:
          "Shule imeondolewa LIVE.",
        school:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// CREATE APPLICATION
// ============================================================

app.post(
  "/api/applications",
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const {
        school_id,
        student_name,
        gender,
        date_of_birth,
        class_applied,
        parent_name,
        parent_phone,
        parent_email,
        address
      } = req.body;

      if (
        !school_id ||
        !student_name ||
        !parent_name ||
        !parent_phone
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Tafadhali jaza taarifa muhimu."
        });
      }

      await client.query(
        "BEGIN"
      );

      const schoolResult =
        await client.query(
          `
          SELECT *
          FROM schools
          WHERE id = $1
          AND status = 'active'
          LIMIT 1
          `,
          [school_id]
        );

      if (
        schoolResult.rows.length === 0
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani au haiko LIVE."
        });
      }

      const school =
        schoolResult.rows[0];

      const applicationNumber =
        generateApplicationNumber();

      const applicationResult =
        await client.query(
          `
          INSERT INTO applications
          (
            application_number,
            school_id,
            student_name,
            gender,
            date_of_birth,
            class_applied,
            parent_name,
            parent_phone,
            parent_email,
            address,
            status
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending'
          )
          RETURNING *
          `,
          [
            applicationNumber,
            school_id,
            student_name,
            gender || null,
            date_of_birth || null,
            class_applied || null,
            parent_name,
            parent_phone,
            parent_email || null,
            address || null
          ]
        );

      const application =
        applicationResult.rows[0];

      const paymentReference =
        generatePaymentReference();

      await client.query(
        `
        INSERT INTO payments
        (
          application_id,
          application_number,
          payment_reference,
          amount,
          status
        )
        VALUES
        ($1,$2,$3,$4,'pending')
        `,
        [
          application.id,
          applicationNumber,
          paymentReference,
          Number(
            school.form_price || 0
          )
        ]
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        success: true,
        message:
          "Application imepokelewa.",

        application: {
          ...application,

          payment_reference:
            paymentReference,

          amount:
            Number(
              school.form_price || 0
            ),

          school_name:
            school.name
        }
      });

    } catch (error) {

      await client.query(
        "ROLLBACK"
      );

      console.error(
        "CREATE APPLICATION ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          error.message
      });

    } finally {

      client.release();

    }
  }
);

// ============================================================
// APPLICATION BY NUMBER
// ============================================================

app.get(
  "/api/application-by-number/:applicationNumber",
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            a.*,

            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.type,
            s.form_price,

            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_status,
            p.payment_method,
            p.transaction_reference,
            p.created_at AS payment_created_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN payments p
            ON p.application_id = a.id

          WHERE a.application_number = $1

          LIMIT 1
          `,
          [
            req.params.applicationNumber
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Application haipatikani."
        });
      }

      res.json({
        success: true,
        application:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// CONFIRM PAYMENT
// ============================================================

app.put(
  "/api/payments/:paymentReference/confirm",
  async (req, res) => {

    try {

      const transactionReference =
        req.body.transaction_reference ||
        `TEST-${Date.now()}`;

      const result =
        await pool.query(
          `
          UPDATE payments
          SET
            status = 'confirmed',
            transaction_reference = $1,
            updated_at = NOW()
          WHERE payment_reference = $2
          RETURNING *
          `,
          [
            transactionReference,
            req.params.paymentReference
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Payment haipatikani."
        });
      }

      res.json({
        success: true,
        message:
          "Malipo yamethibitishwa.",
        payment:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// ADMIN PAYMENTS
// ============================================================

app.get(
  "/api/admin/payments",
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            p.*,

            a.student_name,
            a.parent_name,
            a.parent_phone,
            a.application_number,

            s.name AS school_name

          FROM payments p

          LEFT JOIN applications a
            ON a.id = p.application_id

          LEFT JOIN schools s
            ON s.id = a.school_id

          ORDER BY p.created_at DESC
          `
        );

      res.json({
        success: true,
        payments:
          result.rows
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// ADMIN CONFIRM PAYMENT
// ============================================================

app.put(
  "/api/admin/payments/:id/confirm",
  async (req, res) => {

    try {

      const transactionReference =
        req.body.transaction_reference ||
        `ADMIN-${Date.now()}`;

      const result =
        await pool.query(
          `
          UPDATE payments
          SET
            status = 'confirmed',
            transaction_reference = $1,
            updated_at = NOW()
          WHERE id = $2
          RETURNING *
          `,
          [
            transactionReference,
            req.params.id
          ]
        );

      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Payment haipatikani."
        });
      }

      res.json({
        success: true,
        message:
          "Payment imethibitishwa.",
        payment:
          result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          error.message
      });
    }
  }
);

// ============================================================
// API 404
// ============================================================

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({
      success: false,
      message:
        "API route haipatikani."
    });

  }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
  (error, req, res, next) => {

    console.error(
      "GLOBAL SERVER ERROR:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    res.status(500).json({
      success: false,
      message:
        "Internal server error.",
      error:
        error.message
    });
  }
);

// ============================================================
// START
// ============================================================

async function startServer() {

  await initializeDatabase();

  app.listen(
    PORT,
    "0.0.0.0",
    () => {

      console.log(
        "===================================="
      );

      console.log(
        "SHULE PORTAL TANZANIA"
      );

      console.log(
        `SERVER RUNNING ON PORT ${PORT}`
      );

      console.log(
        "SCHOOL ADMIN AUTH: SIGNED COOKIE"
      );

      console.log(
        "===================================="
      );

    }
  );
}

startServer();