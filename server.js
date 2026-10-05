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

pool.on("error", (err) => {
  console.error("Unexpected PostgreSQL error:", err);
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

function generateApplicationNumber(schoolId) {
  const timestamp = Date.now();
  const random = crypto.randomBytes(2).toString("hex").toUpperCase();

  return `SPT-${new Date().getFullYear()}-${timestamp}-${random}`;
}

function generatePaymentReference() {
  const timestamp = Date.now();
  const random = crypto.randomBytes(2).toString("hex").toUpperCase();

  return `PAY-${new Date().getFullYear()}-${timestamp}-${random}`;
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie;

  if (!cookieHeader) {
    return null;
  }

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...valueParts] = cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

function setSchoolAdminCookie(res, token) {
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
    console.log("Checking database...");

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
    // SCHOOL ADMIN SESSIONS
    // --------------------------------------------------------

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
    // SAFE MIGRATIONS
    // --------------------------------------------------------

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
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS transaction_reference VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE school_admins
      ADD COLUMN IF NOT EXISTS last_login TIMESTAMP
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

    console.log("Database ready.");

  } catch (error) {
    console.error("DATABASE INITIALIZATION ERROR:", error);
  }
}

// ============================================================
// BASIC ROUTES
// ============================================================

app.get("/api/status", async (req, res) => {
  res.json({
    success: true,
    message: "Shule Portal Tanzania server iko online.",
    database_url: !!process.env.DATABASE_URL,
    time: new Date().toISOString()
  });
});

// ============================================================
// DATABASE CHECK
// ============================================================

app.get("/api/database-check", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS now");

    res.json({
      success: true,
      message: "Database imeunganishwa vizuri.",
      time: result.rows[0].now
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Database haijaunganishwa.",
      error: error.message
    });
  }
});

// ============================================================
// PAYMENT SCHEMA
// ============================================================

app.get("/api/payment-schema", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'payments'
      ORDER BY ordinal_position
    `);

    res.json({
      success: true,
      table: "payments",
      columns: result.rows
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// APPLICATION SCHEMA
// ============================================================

app.get("/api/application-schema", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type
      FROM information_schema.columns
      WHERE table_name = 'applications'
      ORDER BY ordinal_position
    `);

    res.json({
      success: true,
      table: "applications",
      columns: result.rows
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// PUBLIC SCHOOLS
// ONLY ACTIVE SCHOOLS
// ============================================================

app.get("/api/schools", async (req, res) => {
  try {
    const result = await pool.query(`
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
      schools: result.rows,
      count: result.rows.length
    });

  } catch (error) {
    console.error("PUBLIC SCHOOLS ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// PUBLIC SINGLE SCHOOL
// ============================================================

app.get("/api/schools/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `
      SELECT *
      FROM schools
      WHERE id = $1
      AND status = 'active'
      `,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haipatikani."
      });
    }

    res.json({
      success: true,
      school: result.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// ADMIN SCHOOL LIST
// ============================================================

app.get("/api/admin/schools", async (req, res) => {
  try {
    const result = await pool.query(`
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
      schools: result.rows
    });

  } catch (error) {
    console.error("ADMIN SCHOOLS ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// ADMIN CREATE SCHOOL
// ============================================================

app.post("/api/admin/schools", async (req, res) => {
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
        message: "Jina la shule linahitajika."
      });
    }

    const result = await pool.query(
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
        school_type || type || null,
        type || school_type || null,
        Number(form_price || 0),
        phone || null,
        address || null,
        email || null,
        application_start || null,
        application_end || null,
        status || "draft"
      ]
    );

    res.json({
      success: true,
      message: "Shule imesajiliwa.",
      school: result.rows[0]
    });

  } catch (error) {
    console.error("CREATE SCHOOL ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// ADMIN UPDATE SCHOOL
// ============================================================

app.put("/api/admin/schools/:id", async (req, res) => {
  try {
    const { id } = req.params;

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

    const result = await pool.query(
      `
      UPDATE schools
      SET
        name = COALESCE($1, name),
        region = COALESCE($2, region),
        district = COALESCE($3, district),
        school_type = COALESCE($4, school_type),
        type = COALESCE($5, type),
        form_price = COALESCE($6, form_price),
        phone = COALESCE($7, phone),
        address = COALESCE($8, address),
        email = COALESCE($9, email),
        application_start = COALESCE($10, application_start),
        application_end = COALESCE($11, application_end),
        status = COALESCE($12, status),
        updated_at = NOW()
      WHERE id = $13
      RETURNING *
      `,
      [
        name,
        region,
        district,
        school_type || type,
        type || school_type,
        form_price !== undefined ? Number(form_price) : null,
        phone,
        address,
        email,
        application_start,
        application_end,
        status,
        id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haipatikani."
      });
    }

    res.json({
      success: true,
      message: "Taarifa za shule zimebadilishwa.",
      school: result.rows[0]
    });

  } catch (error) {
    console.error("UPDATE SCHOOL ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// SCHOOL ADMIN CRUD
// ============================================================

// GET ALL SCHOOL ADMINS

app.get("/api/admin/school-admins", async (req, res) => {
  try {
    const result = await pool.query(`
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
      admins: result.rows
    });

  } catch (error) {
    console.error("GET SCHOOL ADMINS ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// GET SINGLE SCHOOL ADMIN

app.get("/api/admin/school-admins/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
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
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hakupatikana."
      });
    }

    res.json({
      success: true,
      admin: result.rows[0]
    });

  } catch (error) {
    console.error("GET SINGLE SCHOOL ADMIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// CREATE SCHOOL ADMIN

app.post("/api/admin/school-admins", async (req, res) => {
  try {
    const {
      school_id,
      full_name,
      email,
      phone,
      password,
      status
    } = req.body;

    if (!school_id || !full_name || !email || !password) {
      return res.status(400).json({
        success: false,
        message:
          "School, jina, email na password vinahitajika."
      });
    }

    const normalizedEmail = String(email)
      .trim()
      .toLowerCase();

    const school = await pool.query(
      `
      SELECT id, name
      FROM schools
      WHERE id = $1
      `,
      [school_id]
    );

    if (school.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haipatikani."
      });
    }

    const existing = await pool.query(
      `
      SELECT id
      FROM school_admins
      WHERE LOWER(TRIM(email)) = $1
      `,
      [normalizedEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email hiyo tayari imetumika."
      });
    }

    const passwordHash = hashPassword(password);

    const result = await pool.query(
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
      VALUES ($1,$2,$3,$4,$5,$6)
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
        passwordHash,
        status || "active"
      ]
    );

    res.json({
      success: true,
      message: "School Admin ameundwa.",
      admin: result.rows[0]
    });

  } catch (error) {
    console.error("CREATE SCHOOL ADMIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// UPDATE SCHOOL ADMIN

app.put("/api/admin/school-admins/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const {
      school_id,
      full_name,
      email,
      phone,
      status
    } = req.body;

    const normalizedEmail = email
      ? String(email).trim().toLowerCase()
      : null;

    if (normalizedEmail) {
      const duplicate = await pool.query(
        `
        SELECT id
        FROM school_admins
        WHERE LOWER(TRIM(email)) = $1
        AND id <> $2
        `,
        [normalizedEmail, id]
      );

      if (duplicate.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: "Email hiyo tayari inatumika na Admin mwingine."
        });
      }
    }

    const result = await pool.query(
      `
      UPDATE school_admins
      SET
        school_id = COALESCE($1, school_id),
        full_name = COALESCE($2, full_name),
        email = COALESCE($3, email),
        phone = COALESCE($4, phone),
        status = COALESCE($5, status),
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
        id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hakupatikana."
      });
    }

    res.json({
      success: true,
      message: "School Admin amesasishwa.",
      admin: result.rows[0]
    });

  } catch (error) {
    console.error("UPDATE SCHOOL ADMIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// UPDATE SCHOOL ADMIN STATUS

app.put("/api/admin/school-admins/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const allowedStatuses = [
      "active",
      "inactive",
      "suspended"
    ];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status si sahihi."
      });
    }

    const result = await pool.query(
      `
      UPDATE school_admins
      SET
        status = $1,
        updated_at = NOW()
      WHERE id = $2
      RETURNING id, full_name, email, status
      `,
      [status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hakupatikana."
      });
    }

    res.json({
      success: true,
      message: "Status imebadilishwa.",
      admin: result.rows[0]
    });

  } catch (error) {
    console.error("STATUS SCHOOL ADMIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// RESET SCHOOL ADMIN PASSWORD

app.put("/api/admin/school-admins/:id/reset-password", async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;

    if (!password || String(password).length < 4) {
      return res.status(400).json({
        success: false,
        message: "Password lazima iwe na angalau herufi 4."
      });
    }

    const passwordHash = hashPassword(password);

    const result = await pool.query(
      `
      UPDATE school_admins
      SET
        password_hash = $1,
        updated_at = NOW()
      WHERE id = $2
      RETURNING id, full_name, email
      `,
      [passwordHash, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hakupatikana."
      });
    }

    // Ondoa sessions zote za zamani
    await pool.query(
      `
      DELETE FROM school_admin_sessions
      WHERE admin_id = $1
      `,
      [id]
    );

    res.json({
      success: true,
      message: "Password imebadilishwa.",
      admin: result.rows[0]
    });

  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// OLD PASSWORD ROUTE - COMPATIBILITY

app.put("/api/admin/school-admins/:id/password", async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;

    if (!password || String(password).length < 4) {
      return res.status(400).json({
        success: false,
        message: "Password si sahihi."
      });
    }

    const passwordHash = hashPassword(password);

    const result = await pool.query(
      `
      UPDATE school_admins
      SET
        password_hash = $1,
        updated_at = NOW()
      WHERE id = $2
      RETURNING id, full_name, email
      `,
      [passwordHash, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hakupatikana."
      });
    }

    await pool.query(
      `
      DELETE FROM school_admin_sessions
      WHERE admin_id = $1
      `,
      [id]
    );

    res.json({
      success: true,
      message: "Password imebadilishwa."
    });

  } catch (error) {
    console.error("PASSWORD ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// DELETE SCHOOL ADMIN

app.delete("/api/admin/school-admins/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `
      DELETE FROM school_admins
      WHERE id = $1
      RETURNING id, full_name, email
      `,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hakupatikana."
      });
    }

    res.json({
      success: true,
      message: "School Admin amefutwa."
    });

  } catch (error) {
    console.error("DELETE SCHOOL ADMIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// SCHOOL ADMIN LOGIN
// ============================================================

app.post("/api/school-admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email na password vinahitajika."
      });
    }

    const normalizedEmail = String(email)
      .trim()
      .toLowerCase();

    console.log(
      "School Admin login attempt:",
      normalizedEmail
    );

    const result = await pool.query(
      `
      SELECT
        sa.id,
        sa.full_name,
        sa.email,
        sa.phone,
        sa.school_id,
        sa.password_hash,
        sa.status,
        s.name AS school_name,
        s.status AS school_status
      FROM school_admins sa
      LEFT JOIN schools s
        ON s.id = sa.school_id
      WHERE LOWER(TRIM(sa.email)) = $1
      LIMIT 1
      `,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      console.log("School Admin email not found.");

      return res.status(401).json({
        success: false,
        message: "Email au password si sahihi."
      });
    }

    const admin = result.rows[0];

    const passwordHash = hashPassword(password);

    if (passwordHash !== admin.password_hash) {
      console.log("School Admin password mismatch.");

      return res.status(401).json({
        success: false,
        message: "Email au password si sahihi."
      });
    }

    if (admin.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Akaunti yako ya School Admin haijawezeshwa."
      });
    }

    if (
      admin.school_status === "inactive" ||
      admin.school_status === "suspended"
    ) {
      return res.status(403).json({
        success: false,
        message: "Shule hii haijawezeshwa kwa sasa."
      });
    }

    // Futa sessions zilizokwisha muda
    await pool.query(`
      DELETE FROM school_admin_sessions
      WHERE expires_at < NOW()
    `);

    const token = crypto
      .randomBytes(32)
      .toString("hex");

    await pool.query(
      `
      INSERT INTO school_admin_sessions
      (
        admin_id,
        token,
        expires_at
      )
      VALUES
      (
        $1,
        $2,
        NOW() + INTERVAL '12 hours'
      )
      `,
      [admin.id, token]
    );

    await pool.query(
      `
      UPDATE school_admins
      SET last_login = NOW()
      WHERE id = $1
      `,
      [admin.id]
    );

    setSchoolAdminCookie(res, token);

    return res.json({
      success: true,
      message: "Umefanikiwa kuingia.",
      admin: {
        id: admin.id,
        full_name: admin.full_name,
        email: admin.email,
        phone: admin.phone,
        school_id: admin.school_id,
        school_name: admin.school_name
      }
    });

  } catch (error) {
    console.error(
      "SCHOOL ADMIN LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Hitilafu ya server wakati wa kuingia.",
      error: error.message
    });
  }
});

// ============================================================
// SCHOOL ADMIN AUTH MIDDLEWARE
// ============================================================

async function requireSchoolAdmin(req, res, next) {
  try {
    const token = getCookie(
      req,
      "school_admin_token"
    );

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Hujaingia kama School Admin."
      });
    }

    const result = await pool.query(
      `
      SELECT
        sas.id AS session_id,
        sas.token,
        sas.expires_at,

        sa.id,
        sa.full_name,
        sa.email,
        sa.phone,
        sa.school_id,
        sa.status,

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

      FROM school_admin_sessions sas

      JOIN school_admins sa
        ON sa.id = sas.admin_id

      LEFT JOIN schools s
        ON s.id = sa.school_id

      WHERE sas.token = $1
      AND sas.expires_at > NOW()

      LIMIT 1
      `,
      [token]
    );

    if (result.rows.length === 0) {
      clearSchoolAdminCookie(res);

      return res.status(401).json({
        success: false,
        message: "Session imekwisha. Ingia tena."
      });
    }

    const admin = result.rows[0];

    if (admin.status !== "active") {
      clearSchoolAdminCookie(res);

      return res.status(403).json({
        success: false,
        message: "Akaunti yako haijawezeshwa."
      });
    }

    if (
      admin.school_status === "inactive" ||
      admin.school_status === "suspended"
    ) {
      return res.status(403).json({
        success: false,
        message: "Shule haijawezeshwa."
      });
    }

    req.schoolAdmin = admin;

    next();

  } catch (error) {
    console.error(
      "SCHOOL ADMIN AUTH ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Hitilafu ya authentication."
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
    res.json({
      success: true,
      admin: req.schoolAdmin
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
      const token = getCookie(
        req,
        "school_admin_token"
      );

      if (token) {
        await pool.query(
          `
          DELETE FROM school_admin_sessions
          WHERE token = $1
          `,
          [token]
        );
      }

      clearSchoolAdminCookie(res);

      res.json({
        success: true,
        message: "Umetoka kwenye mfumo."
      });

    } catch (error) {
      console.error("LOGOUT ERROR:", error);

      res.status(500).json({
        success: false,
        message: error.message
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
      const schoolId =
        req.schoolAdmin.school_id;

      const totalResult = await pool.query(
        `
        SELECT COUNT(*)::INTEGER AS total
        FROM applications
        WHERE school_id = $1
        `,
        [schoolId]
      );

      const pendingResult = await pool.query(
        `
        SELECT COUNT(*)::INTEGER AS total
        FROM applications
        WHERE school_id = $1
        AND status = 'pending'
        `,
        [schoolId]
      );

      const approvedResult = await pool.query(
        `
        SELECT COUNT(*)::INTEGER AS total
        FROM applications
        WHERE school_id = $1
        AND status = 'approved'
        `,
        [schoolId]
      );

      const rejectedResult = await pool.query(
        `
        SELECT COUNT(*)::INTEGER AS total
        FROM applications
        WHERE school_id = $1
        AND status = 'rejected'
        `,
        [schoolId]
      );

      const paidResult = await pool.query(
        `
        SELECT COUNT(*)::INTEGER AS total
        FROM payments p
        JOIN applications a
          ON a.id = p.application_id
        WHERE a.school_id = $1
        AND p.status IN ('paid','confirmed','completed')
        `,
        [schoolId]
      );

      res.json({
        success: true,
        stats: {
          total_applications:
            totalResult.rows[0].total,

          pending:
            pendingResult.rows[0].total,

          approved:
            approvedResult.rows[0].total,

          rejected:
            rejectedResult.rows[0].total,

          paid:
            paidResult.rows[0].total
        }
      });

    } catch (error) {
      console.error(
        "DASHBOARD STATS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
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
      const result = await pool.query(
        `
        SELECT
          a.*,
          p.payment_reference,
          p.amount AS payment_amount,
          p.status AS payment_status,
          p.transaction_reference

        FROM applications a

        LEFT JOIN payments p
          ON p.application_id = a.id

        WHERE a.school_id = $1

        ORDER BY a.created_at DESC
        `,
        [req.schoolAdmin.school_id]
      );

      res.json({
        success: true,
        applications: result.rows
      });

    } catch (error) {
      console.error(
        "SCHOOL APPLICATIONS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN SINGLE APPLICATION
// ============================================================

app.get(
  "/api/school-admin/applications/:id",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const result = await pool.query(
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
        [id, req.schoolAdmin.school_id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Application haipatikani."
        });
      }

      res.json({
        success: true,
        application: result.rows[0]
      });

    } catch (error) {
      console.error(
        "SINGLE APPLICATION ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN UPDATE APPLICATION STATUS
// ============================================================

app.put(
  "/api/school-admin/applications/:id/status",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      const allowed = [
        "pending",
        "approved",
        "rejected"
      ];

      if (!allowed.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Application status si sahihi."
        });
      }

      const result = await pool.query(
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
          status,
          id,
          req.schoolAdmin.school_id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Application haipatikani."
        });
      }

      res.json({
        success: true,
        message: "Status ya application imebadilishwa.",
        application: result.rows[0]
      });

    } catch (error) {
      console.error(
        "UPDATE APPLICATION STATUS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN UPDATE SCHOOL
// ============================================================

app.put(
  "/api/school-admin/school",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const schoolId =
        req.schoolAdmin.school_id;

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
        application_end
      } = req.body;

      const result = await pool.query(
        `
        UPDATE schools
        SET
          name = COALESCE($1, name),
          region = COALESCE($2, region),
          district = COALESCE($3, district),
          school_type = COALESCE($4, school_type),
          type = COALESCE($5, type),
          form_price = COALESCE($6, form_price),
          phone = COALESCE($7, phone),
          address = COALESCE($8, address),
          email = COALESCE($9, email),
          application_start = COALESCE($10, application_start),
          application_end = COALESCE($11, application_end),
          updated_at = NOW()
        WHERE id = $12
        RETURNING *
        `,
        [
          name || null,
          region || null,
          district || null,
          school_type || type || null,
          type || school_type || null,
          form_price !== undefined
            ? Number(form_price)
            : null,
          phone || null,
          address || null,
          email || null,
          application_start || null,
          application_end || null,
          schoolId
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Shule haipatikani."
        });
      }

      res.json({
        success: true,
        message: "Taarifa za shule zimehifadhiwa.",
        school: result.rows[0]
      });

    } catch (error) {
      console.error(
        "SCHOOL ADMIN UPDATE SCHOOL ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
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
      const schoolId =
        req.schoolAdmin.school_id;

      const result = await pool.query(
        `
        UPDATE schools
        SET
          status = 'active',
          updated_at = NOW()
        WHERE id = $1
        RETURNING *
        `,
        [schoolId]
      );

      res.json({
        success: true,
        message: "Shule imewekwa LIVE.",
        school: result.rows[0]
      });

    } catch (error) {
      console.error(
        "PUBLISH SCHOOL ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
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
      const schoolId =
        req.schoolAdmin.school_id;

      const result = await pool.query(
        `
        UPDATE schools
        SET
          status = 'draft',
          updated_at = NOW()
        WHERE id = $1
        RETURNING *
        `,
        [schoolId]
      );

      res.json({
        success: true,
        message: "Shule imeondolewa LIVE.",
        school: result.rows[0]
      });

    } catch (error) {
      console.error(
        "UNPUBLISH SCHOOL ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// CREATE APPLICATION
// ============================================================

app.post("/api/applications", async (req, res) => {
  const client = await pool.connect();

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
          "Tafadhali jaza taarifa zote muhimu."
      });
    }

    await client.query("BEGIN");

    const schoolResult = await client.query(
      `
      SELECT *
      FROM schools
      WHERE id = $1
      AND status = 'active'
      LIMIT 1
      `,
      [school_id]
    );

    if (schoolResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        message: "Shule haipatikani au haiko LIVE."
      });
    }

    const school = schoolResult.rows[0];

    const applicationNumber =
      generateApplicationNumber(school_id);

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
        Number(school.form_price || 0)
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Application imepokelewa.",
      application: {
        ...application,
        payment_reference: paymentReference,
        amount: Number(
          school.form_price || 0
        ),
        school_name: school.name
      }
    });

  } catch (error) {
    await client.query("ROLLBACK");

    console.error(
      "CREATE APPLICATION ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: error.message
    });

  } finally {
    client.release();
  }
});

// ============================================================
// APPLICATION BY NUMBER
// ============================================================

app.get(
  "/api/application-by-number/:applicationNumber",
  async (req, res) => {
    try {
      const {
        applicationNumber
      } = req.params;

      const result = await pool.query(
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
        [applicationNumber]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Application haipatikani."
        });
      }

      res.json({
        success: true,
        application: result.rows[0]
      });

    } catch (error) {
      console.error(
        "APPLICATION TRACK ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// CONFIRM TEST PAYMENT
// ============================================================

app.put(
  "/api/payments/:paymentReference/confirm",
  async (req, res) => {
    try {
      const {
        paymentReference
      } = req.params;

      const transactionReference =
        req.body.transaction_reference ||
        `TEST-${Date.now()}`;

      const result = await pool.query(
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
          paymentReference
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Payment haipatikani."
        });
      }

      res.json({
        success: true,
        message: "Malipo yamethibitishwa.",
        payment: result.rows[0]
      });

    } catch (error) {
      console.error(
        "CONFIRM PAYMENT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// ADMIN PAYMENTS
// ============================================================

app.get("/api/admin/payments", async (req, res) => {
  try {
    const result = await pool.query(`
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
    `);

    res.json({
      success: true,
      payments: result.rows
    });

  } catch (error) {
    console.error(
      "ADMIN PAYMENTS ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// ADMIN PAYMENT CONFIRM
// ============================================================

app.put(
  "/api/admin/payments/:id/confirm",
  async (req, res) => {
    try {
      const { id } = req.params;

      const transactionReference =
        req.body.transaction_reference ||
        `ADMIN-${Date.now()}`;

      const result = await pool.query(
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
          id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Payment haipatikani."
        });
      }

      res.json({
        success: true,
        message: "Payment imethibitishwa.",
        payment: result.rows[0]
      });

    } catch (error) {
      console.error(
        "ADMIN CONFIRM PAYMENT ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// CATCH ALL API 404
// ============================================================

app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API route haipatikani."
  });
});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    success: false,
    message: "Internal server error.",
    error: error.message
  });
});

// ============================================================
// START SERVER
// ============================================================

async function startServer() {
  await initializeDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `Shule Portal Tanzania running on port ${PORT}`
    );
  });
}

startServer();