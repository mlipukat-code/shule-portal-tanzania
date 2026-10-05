const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// ======================================================
// DATABASE
// ======================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// ======================================================
// HELPERS
// ======================================================

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");

    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);

      resolve(`${salt}:${derivedKey.toString("hex")}`);
    });
  });
}

function verifyPassword(password, storedHash) {
  return new Promise((resolve, reject) => {
    try {
      const [salt, key] = String(storedHash || "").split(":");

      if (!salt || !key) {
        return resolve(false);
      }

      crypto.scrypt(password, salt, 64, (err, derivedKey) => {
        if (err) return reject(err);

        const storedBuffer = Buffer.from(key, "hex");

        if (storedBuffer.length !== derivedKey.length) {
          return resolve(false);
        }

        resolve(
          crypto.timingSafeEqual(storedBuffer, derivedKey)
        );
      });
    } catch (error) {
      reject(error);
    }
  });
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  header.split(";").forEach(part => {
    const index = part.indexOf("=");

    if (index === -1) return;

    const key = part.substring(0, index).trim();
    const value = part.substring(index + 1).trim();

    if (key) {
      cookies[key] = decodeURIComponent(value);
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
    .update(token)
    .digest("hex");
}

function generateApplicationNumber() {
  return `SPT-${new Date().getFullYear()}-${Date.now()}-${Math.floor(
    10 + Math.random() * 90
  )}`;
}

function generatePaymentReference() {
  return `PAY-${new Date().getFullYear()}-${Date.now()}-${Math.floor(
    100 + Math.random() * 900
  )}`;
}

// ======================================================
// DATABASE SETUP
// ======================================================

async function setupDatabase() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // --------------------------------------------------
    // SCHOOLS
    // --------------------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS schools (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        region VARCHAR(100),
        district VARCHAR(100),
        school_type VARCHAR(100),
        form_price NUMERIC(12,2) DEFAULT 0,
        phone VARCHAR(50),
        address TEXT,
        email VARCHAR(255),
        application_start TIMESTAMP NULL,
        application_end TIMESTAMP NULL,
        status VARCHAR(30) DEFAULT 'draft',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // New school profile fields
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

    // --------------------------------------------------
    // APPLICATIONS
    // --------------------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        application_number VARCHAR(100),
        school_id INTEGER,
        form_id INTEGER,
        applicant_name VARCHAR(255),
        applicant_gender VARCHAR(50),
        applicant_date_of_birth DATE,
        parent_name VARCHAR(255),
        parent_phone VARCHAR(50),
        parent_email VARCHAR(255),
        address TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        payment_status VARCHAR(50) DEFAULT 'unpaid',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS student_name VARCHAR(255)
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
      ADD COLUMN IF NOT EXISTS phone VARCHAR(50)
    `);

    await client.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS email VARCHAR(255)
    `);

    // --------------------------------------------------
    // PAYMENTS
    // --------------------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        application_id INTEGER,
        payment_reference VARCHAR(100),
        amount NUMERIC(12,2),
        status VARCHAR(50) DEFAULT 'pending',
        provider VARCHAR(100),
        provider_reference VARCHAR(255),
        paid_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // --------------------------------------------------
    // SCHOOL ADMINS
    // --------------------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS school_admins (
        id SERIAL PRIMARY KEY,
        school_id INTEGER NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        phone VARCHAR(50),
        email VARCHAR(255),
        password_hash TEXT NOT NULL,
        status VARCHAR(30) DEFAULT 'active',
        last_login TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // --------------------------------------------------
    // SCHOOL ADMIN SESSIONS
    // --------------------------------------------------

    await client.query(`
      CREATE TABLE IF NOT EXISTS school_admin_sessions (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER NOT NULL,
        token_hash VARCHAR(128) NOT NULL UNIQUE,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // --------------------------------------------------
    // INDEXES
    // --------------------------------------------------

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_school_id
      ON applications(school_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_applications_application_number
      ON applications(application_number)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_school_admins_school_id
      ON school_admins(school_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_school_admin_sessions_token_hash
      ON school_admin_sessions(token_hash)
    `);

    // Existing ACTIVE schools should remain fully live.
    await client.query(`
      UPDATE schools
      SET profile_completed = TRUE
      WHERE status = 'active'
        AND (profile_completed IS NULL OR profile_completed = FALSE)
    `);

    await client.query("COMMIT");

    console.log("Database setup completed successfully.");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Database setup error:", error);
    throw error;
  } finally {
    client.release();
  }
}

// ======================================================
// SCHOOL ADMIN AUTH
// ======================================================

async function requireSchoolAdmin(req, res, next) {
  try {
    const token = getSchoolAdminToken(req);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Hujaingia kama School Admin."
      });
    }

    const tokenHash = hashToken(token);

    const result = await pool.query(
      `
      SELECT
        sa.id,
        sa.school_id,
        sa.full_name,
        sa.phone,
        sa.email,
        sa.status AS admin_status,
        sa.last_login,
        s.name AS school_name,
        s.region,
        s.district,
        s.school_type,
        s.form_price,
        s.phone AS school_phone,
        s.address AS school_address,
        s.email AS school_email,
        s.application_start,
        s.application_end,
        s.status AS school_status,
        s.description,
        s.logo_url,
        s.classes_offered,
        s.requirements,
        s.profile_completed
      FROM school_admin_sessions ses
      JOIN school_admins sa
        ON sa.id = ses.admin_id
      JOIN schools s
        ON s.id = sa.school_id
      WHERE ses.token_hash = $1
        AND ses.expires_at > CURRENT_TIMESTAMP
      LIMIT 1
      `,
      [tokenHash]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Session imekwisha. Ingia tena."
      });
    }

    const admin = result.rows[0];

    if (admin.admin_status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Akaunti ya School Admin haijawezeshwa."
      });
    }

    // IMPORTANT:
    // School Admin can work while school is draft.
    // Only inactive/suspended schools are blocked.
    if (
      admin.school_status === "inactive" ||
      admin.school_status === "suspended"
    ) {
      return res.status(403).json({
        success: false,
        message: "Shule hii imezimwa kwa sasa."
      });
    }

    req.schoolAdmin = admin;

    next();
  } catch (error) {
    console.error("School admin auth error:", error);

    res.status(500).json({
      success: false,
      message: "Tatizo la mfumo."
    });
  }
}

// ======================================================
// HOME
// ======================================================

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// ======================================================
// SYSTEM STATUS
// ======================================================

app.get("/api/status", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS current_time");

    res.json({
      success: true,
      message: "Shule Portal Tanzania API inafanya kazi.",
      database: "connected",
      time: result.rows[0].current_time
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Database haijaunganishwa.",
      error: error.message
    });
  }
});

// ======================================================
// PUBLIC SCHOOLS
// ONLY LIVE / ACTIVE SCHOOLS
// ======================================================

app.get("/api/schools", async (req, res) => {
  try {
    const result = await pool.query(`
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
        description,
        logo_url,
        classes_offered,
        requirements,
        status,
        profile_completed,
        created_at,
        updated_at
      FROM schools
      WHERE status = 'active'
      ORDER BY created_at DESC
    `);

    res.json({
      success: true,
      schools: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kupata shule.",
      error: error.message
    });
  }
});

// ======================================================
// DATABASE CHECK
// ======================================================

app.get("/api/database-check", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS now");

    res.json({
      success: true,
      message: "database imeunganishwa",
      time: result.rows[0].now
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "database haijaunganishwa bado",
      error: error.message
    });
  }
});

// ======================================================
// APPLICATION SCHEMA
// ======================================================

app.get("/api/application-schema", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        column_name,
        data_type
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

// ======================================================
// PAYMENT SCHEMA
// ======================================================

app.get("/api/payment-schema", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        column_name,
        data_type
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

// ======================================================
// MAIN ADMIN - SCHOOLS
// ======================================================

app.get("/api/admin/schools", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        s.*,
        COUNT(a.id)::INTEGER AS applicants
      FROM schools s
      LEFT JOIN applications a
        ON a.school_id = s.id
      GROUP BY s.id
      ORDER BY s.created_at DESC
    `);

    res.json({
      success: true,
      schools: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kupata shule.",
      error: error.message
    });
  }
});

// ======================================================
// MAIN ADMIN - SINGLE SCHOOL
// ======================================================

app.get("/api/admin/schools/:id", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT
        s.*,
        COUNT(a.id)::INTEGER AS applicants
      FROM schools s
      LEFT JOIN applications a
        ON a.school_id = s.id
      WHERE s.id = $1
      GROUP BY s.id
      `,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
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

// ======================================================
// MAIN ADMIN - REGISTER SCHOOL
// NEW SCHOOL = DRAFT
// ======================================================

app.post("/api/admin/schools", async (req, res) => {
  try {
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
      application_end,
      description,
      logo_url,
      classes_offered,
      requirements
    } = req.body;

    if (!name || !String(name).trim()) {
      return res.status(400).json({
        success: false,
        message: "Jina la shule linahitajika."
      });
    }

    const result = await pool.query(
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
        description,
        logo_url,
        classes_offered,
        requirements,
        status,
        profile_completed
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
        'draft',
        FALSE
      )
      RETURNING *
      `,
      [
        String(name).trim(),
        region || null,
        district || null,
        school_type || null,
        Number(form_price) || 0,
        phone || null,
        address || null,
        normalizeEmail(email) || null,
        application_start || null,
        application_end || null,
        description || null,
        logo_url || null,
        classes_offered || null,
        requirements || null
      ]
    );

    res.status(201).json({
      success: true,
      message:
        "Shule imesajiliwa kama DRAFT. School Admin sasa anaweza kukamilisha taarifa.",
      school: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kusajili shule.",
      error: error.message
    });
  }
});

// ======================================================
// MAIN ADMIN - UPDATE SCHOOL
// ======================================================

app.put("/api/admin/schools/:id", async (req, res) => {
  try {
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
      application_end,
      description,
      logo_url,
      classes_offered,
      requirements,
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
        form_price = COALESCE($5, form_price),
        phone = COALESCE($6, phone),
        address = COALESCE($7, address),
        email = COALESCE($8, email),
        application_start = COALESCE($9, application_start),
        application_end = COALESCE($10, application_end),
        description = COALESCE($11, description),
        logo_url = COALESCE($12, logo_url),
        classes_offered = COALESCE($13, classes_offered),
        requirements = COALESCE($14, requirements),
        status = COALESCE($15, status),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $16
      RETURNING *
      `,
      [
        name !== undefined ? name : null,
        region !== undefined ? region : null,
        district !== undefined ? district : null,
        school_type !== undefined ? school_type : null,
        form_price !== undefined ? Number(form_price) : null,
        phone !== undefined ? phone : null,
        address !== undefined ? address : null,
        email !== undefined ? normalizeEmail(email) : null,
        application_start !== undefined ? application_start : null,
        application_end !== undefined ? application_end : null,
        description !== undefined ? description : null,
        logo_url !== undefined ? logo_url : null,
        classes_offered !== undefined ? classes_offered : null,
        requirements !== undefined ? requirements : null,
        status !== undefined ? status : null,
        req.params.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
      });
    }

    res.json({
      success: true,
      message: "Taarifa za shule zimebadilishwa.",
      school: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kubadilisha shule.",
      error: error.message
    });
  }
});

// ======================================================
// MAIN ADMIN - SCHOOL STATUS
// ======================================================

app.put("/api/admin/schools/:id/status", async (req, res) => {
  try {
    const { status } = req.body;

    const allowedStatuses = [
      "draft",
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
      UPDATE schools
      SET
        status = $1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING *
      `,
      [status, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
      });
    }

    res.json({
      success: true,
      message: `Status ya shule imekuwa ${status}.`,
      school: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// MAIN ADMIN - DELETE SCHOOL
// ======================================================

app.delete("/api/admin/schools/:id", async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const schoolId = req.params.id;

    await client.query(
      `
      DELETE FROM school_admin_sessions
      WHERE admin_id IN (
        SELECT id FROM school_admins
        WHERE school_id = $1
      )
      `,
      [schoolId]
    );

    await client.query(
      `
      DELETE FROM school_admins
      WHERE school_id = $1
      `,
      [schoolId]
    );

    await client.query(
      `
      DELETE FROM schools
      WHERE id = $1
      `,
      [schoolId]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Shule imefutwa."
    });
  } catch (error) {
    await client.query("ROLLBACK");

    res.status(500).json({
      success: false,
      message: "Imeshindikana kufuta shule.",
      error: error.message
    });
  } finally {
    client.release();
  }
});

// ======================================================
// APPLICATION CREATION
// ======================================================

app.post("/api/applications", async (req, res) => {
  const client = await pool.connect();

  try {
    const {
      school_id,
      form_id,

      student_name,
      applicant_name,

      gender,
      applicant_gender,

      date_of_birth,
      applicant_date_of_birth,

      class_level,

      parent_name,

      phone,
      parent_phone,

      email,
      parent_email,

      address
    } = req.body;

    const studentName = student_name || applicant_name;
    const studentGender = gender || applicant_gender;
    const dob = date_of_birth || applicant_date_of_birth;
    const parentPhone = phone || parent_phone;
    const parentEmail = email || parent_email;

    if (!school_id) {
      return res.status(400).json({
        success: false,
        message: "school_id inahitajika."
      });
    }

    if (!studentName) {
      return res.status(400).json({
        success: false,
        message: "Jina la mwanafunzi linahitajika."
      });
    }

    const schoolResult = await client.query(
      `
      SELECT *
      FROM schools
      WHERE id = $1
        AND status = 'active'
      `,
      [school_id]
    );

    if (schoolResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haipatikani au bado haijawekwa LIVE."
      });
    }

    const school = schoolResult.rows[0];

    const applicationNumber = generateApplicationNumber();
    const paymentReference = generatePaymentReference();

    await client.query("BEGIN");

    const applicationResult = await client.query(
      `
      INSERT INTO applications (
        application_number,
        school_id,
        form_id,
        applicant_name,
        applicant_gender,
        applicant_date_of_birth,
        parent_name,
        parent_phone,
        parent_email,
        address,
        student_name,
        gender,
        date_of_birth,
        class_level,
        phone,
        email,
        status,
        payment_status
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
        $11,$12,$13,$14,$15,$16,
        'pending',
        'unpaid'
      )
      RETURNING *
      `,
      [
        applicationNumber,
        school_id,
        form_id || null,
        studentName,
        studentGender || null,
        dob || null,
        parent_name || null,
        parentPhone || null,
        parentEmail || null,
        address || null,
        studentName,
        studentGender || null,
        dob || null,
        class_level || null,
        parentPhone || null,
        parentEmail || null
      ]
    );

    const application = applicationResult.rows[0];

    const paymentResult = await client.query(
      `
      INSERT INTO payments (
        application_id,
        payment_reference,
        amount,
        status,
        provider
      )
      VALUES (
        $1,
        $2,
        $3,
        'pending',
        'manual'
      )
      RETURNING *
      `,
      [
        application.id,
        paymentReference,
        school.form_price
      ]
    );

    await client.query("COMMIT");

    res.status(201).json({
      success: true,
      message: "Maombi yamepokelewa.",
      application,
      payment: paymentResult.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kutuma maombi.",
      error: error.message
    });
  } finally {
    client.release();
  }
});

// ======================================================
// GET APPLICATION BY ID
// ======================================================

app.get("/api/applications/:id", async (req, res) => {
  try {
    const result = await pool.query(
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
        ORDER BY id DESC
        LIMIT 1
      ) p
        ON TRUE

      WHERE a.id = $1
      `,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Application haijapatikana."
      });
    }

    res.json({
      success: true,
      application: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// GET APPLICATION BY NUMBER
// ======================================================

app.get(
  "/api/application-by-number/:applicationNumber",
  async (req, res) => {
    try {
      const result = await pool.query(
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
          ORDER BY id DESC
          LIMIT 1
        ) p
          ON TRUE

        WHERE a.application_number = $1
        LIMIT 1
        `,
        [req.params.applicationNumber]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Application haijapatikana."
        });
      }

      res.json({
        success: true,
        application: result.rows[0]
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// MAIN ADMIN - APPLICATIONS
// ======================================================

app.get("/api/admin/applications", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        a.*,
        s.name AS school_name,
        s.region,
        s.district,
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
        ORDER BY id DESC
        LIMIT 1
      ) p
        ON TRUE

      ORDER BY a.created_at DESC
    `);

    res.json({
      success: true,
      applications: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// MAIN ADMIN - DASHBOARD STATS
// ======================================================

app.get("/api/admin/dashboard-stats", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*)::INTEGER AS total_applications,

        COUNT(*) FILTER (
          WHERE status = 'pending'
        )::INTEGER AS pending_applications,

        COUNT(*) FILTER (
          WHERE status = 'approved'
        )::INTEGER AS approved_applications,

        COUNT(*) FILTER (
          WHERE status = 'rejected'
        )::INTEGER AS rejected_applications,

        COUNT(*) FILTER (
          WHERE payment_status = 'paid'
        )::INTEGER AS paid_applications,

        COUNT(*) FILTER (
          WHERE payment_status != 'paid'
        )::INTEGER AS unpaid_applications

      FROM applications
    `);

    res.json({
      success: true,
      stats: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// MAIN ADMIN - APPLICATION STATUS
// ======================================================

app.put("/api/admin/applications/:id/status", async (req, res) => {
  try {
    const { status } = req.body;

    const allowedStatuses = [
      "pending",
      "approved",
      "rejected"
    ];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: "Status si sahihi."
      });
    }

    const result = await pool.query(
      `
      UPDATE applications
      SET
        status = $1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING *
      `,
      [status, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Application haijapatikana."
      });
    }

    res.json({
      success: true,
      message: "Status ya application imebadilishwa.",
      application: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// MAIN ADMIN - PAYMENT STATUS
// ======================================================

app.put("/api/admin/applications/:id/payment-status", async (req, res) => {
  const client = await pool.connect();

  try {
    const { payment_status, provider, provider_reference } = req.body;

    const allowedStatuses = [
      "paid",
      "unpaid",
      "pending"
    ];

    if (!allowedStatuses.includes(payment_status)) {
      return res.status(400).json({
        success: false,
        message: "Payment status si sahihi."
      });
    }

    await client.query("BEGIN");

    const applicationResult = await client.query(
      `
      UPDATE applications
      SET
        payment_status = $1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING *
      `,
      [payment_status, req.params.id]
    );

    if (applicationResult.rows.length === 0) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        message: "Application haijapatikana."
      });
    }

    const application = applicationResult.rows[0];

    const paymentResult = await client.query(
      `
      SELECT *
      FROM payments
      WHERE application_id = $1
      ORDER BY id DESC
      LIMIT 1
      `,
      [application.id]
    );

    if (paymentResult.rows.length > 0) {
      let paymentRow = paymentResult.rows[0];

      let finalProvider =
        provider !== undefined
          ? provider
          : paymentRow.provider;

      let finalProviderReference =
        provider_reference !== undefined
          ? provider_reference
          : paymentRow.provider_reference;

      if (payment_status === "paid") {
        await client.query(
          `
          UPDATE payments
          SET
            status = 'paid',
            provider = $1,
            provider_reference = $2,
            paid_at = COALESCE(paid_at, CURRENT_TIMESTAMP),
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $3
          `,
          [
            finalProvider,
            finalProviderReference,
            paymentRow.id
          ]
        );
      } else {
        await client.query(
          `
          UPDATE payments
          SET
            status = $1,
            provider = $2,
            provider_reference = $3,
            paid_at = NULL,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $4
          `,
          [
            payment_status,
            finalProvider,
            finalProviderReference,
            paymentRow.id
          ]
        );
      }
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Payment status imebadilishwa.",
      application
    });
  } catch (error) {
    await client.query("ROLLBACK");

    res.status(500).json({
      success: false,
      message: error.message
    });
  } finally {
    client.release();
  }
});

// ======================================================
// MAIN ADMIN - SCHOOL ADMINS
// ======================================================

app.get("/api/admin/school-admins", async (req, res) => {
  try {
    const result = await pool.query(`
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
        s.region,
        s.district,
        s.status AS school_status

      FROM school_admins sa

      JOIN schools s
        ON s.id = sa.school_id

      ORDER BY sa.created_at DESC
    `);

    res.json({
      success: true,
      admins: result.rows,
      count: result.rows.length
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// MAIN ADMIN - SINGLE SCHOOL ADMIN
// ======================================================

app.get("/api/admin/school-admins/:id", async (req, res) => {
  try {
    const result = await pool.query(
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
        s.region,
        s.district,
        s.status AS school_status

      FROM school_admins sa

      JOIN schools s
        ON s.id = sa.school_id

      WHERE sa.id = $1
      `,
      [req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hajapatikana."
      });
    }

    res.json({
      success: true,
      admin: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// CREATE SCHOOL ADMIN
// ======================================================

app.post("/api/admin/school-admins", async (req, res) => {
  try {
    const {
      school_id,
      full_name,
      phone,
      email,
      password
    } = req.body;

    if (!school_id || !full_name || !email || !password) {
      return res.status(400).json({
        success: false,
        message:
          "school_id, full_name, email na password vinahitajika."
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password iwe na angalau characters 6."
      });
    }

    const schoolResult = await pool.query(
      `
      SELECT id, name, status
      FROM schools
      WHERE id = $1
      `,
      [school_id]
    );

    if (schoolResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
      });
    }

    const normalizedEmail = normalizeEmail(email);

    const existing = await pool.query(
      `
      SELECT id
      FROM school_admins
      WHERE LOWER(email) = $1
      LIMIT 1
      `,
      [normalizedEmail]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email hii tayari inatumika."
      });
    }

    const passwordHash = await hashPassword(password);

    const result = await pool.query(
      `
      INSERT INTO school_admins (
        school_id,
        full_name,
        phone,
        email,
        password_hash,
        status
      )
      VALUES ($1,$2,$3,$4,$5,'active')
      RETURNING
        id,
        school_id,
        full_name,
        phone,
        email,
        status,
        created_at
      `,
      [
        school_id,
        full_name,
        phone || null,
        normalizedEmail,
        passwordHash
      ]
    );

    res.status(201).json({
      success: true,
      message: "School Admin ameundwa.",
      admin: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// UPDATE SCHOOL ADMIN
// ======================================================

app.put("/api/admin/school-admins/:id", async (req, res) => {
  try {
    const {
      school_id,
      full_name,
      phone,
      email
    } = req.body;

    const normalizedEmail =
      email !== undefined
        ? normalizeEmail(email)
        : null;

    if (normalizedEmail) {
      const duplicate = await pool.query(
        `
        SELECT id
        FROM school_admins
        WHERE LOWER(email) = $1
          AND id <> $2
        LIMIT 1
        `,
        [
          normalizedEmail,
          req.params.id
        ]
      );

      if (duplicate.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message: "Email hii tayari inatumika."
        });
      }
    }

    const result = await pool.query(
      `
      UPDATE school_admins
      SET
        school_id = COALESCE($1, school_id),
        full_name = COALESCE($2, full_name),
        phone = COALESCE($3, phone),
        email = COALESCE($4, email),
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $5
      RETURNING
        id,
        school_id,
        full_name,
        phone,
        email,
        status,
        last_login,
        updated_at
      `,
      [
        school_id !== undefined ? school_id : null,
        full_name !== undefined ? full_name : null,
        phone !== undefined ? phone : null,
        normalizedEmail,
        req.params.id
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hajapatikana."
      });
    }

    res.json({
      success: true,
      message: "School Admin amesasishwa.",
      admin: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// SCHOOL ADMIN STATUS
// ======================================================

app.put("/api/admin/school-admins/:id/status", async (req, res) => {
  try {
    const { status } = req.body;

    const allowedStatuses = [
      "active",
      "inactive"
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
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING
        id,
        school_id,
        full_name,
        phone,
        email,
        status
      `,
      [status, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hajapatikana."
      });
    }

    res.json({
      success: true,
      message: "Status imebadilishwa.",
      admin: result.rows[0]
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ======================================================
// RESET SCHOOL ADMIN PASSWORD
// ======================================================

app.put(
  "/api/admin/school-admins/:id/reset-password",
  async (req, res) => {
    try {
      const { password } = req.body;

      if (!password || String(password).length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password mpya iwe na angalau characters 6."
        });
      }

      const passwordHash =
        await hashPassword(password);

      const result = await pool.query(
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
          email
        `,
        [
          passwordHash,
          req.params.id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "School Admin hajapatikana."
        });
      }

      // Force old sessions to expire.
      await pool.query(
        `
        DELETE FROM school_admin_sessions
        WHERE admin_id = $1
        `,
        [req.params.id]
      );

      res.json({
        success: true,
        message: "Password imebadilishwa.",
        admin: result.rows[0]
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// DELETE SCHOOL ADMIN
// ======================================================

app.delete("/api/admin/school-admins/:id", async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      `
      DELETE FROM school_admin_sessions
      WHERE admin_id = $1
      `,
      [req.params.id]
    );

    const result = await client.query(
      `
      DELETE FROM school_admins
      WHERE id = $1
      `,
      [req.params.id]
    );

    await client.query("COMMIT");

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "School Admin hajapatikana."
      });
    }

    res.json({
      success: true,
      message: "School Admin amefutwa."
    });
  } catch (error) {
    await client.query("ROLLBACK");

    res.status(500).json({
      success: false,
      message: error.message
    });
  } finally {
    client.release();
  }
});

// ======================================================
// SCHOOL ADMIN LOGIN
// ======================================================

app.post("/api/school-admin/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email na password vinahitajika."
      });
    }

    const result = await pool.query(
      `
      SELECT
        sa.*,

        s.name AS school_name,
        s.region,
        s.district,
        s.school_type,
        s.form_price,
        s.phone AS school_phone,
        s.address AS school_address,
        s.email AS school_email,
        s.application_start,
        s.application_end,
        s.status AS school_status,
        s.description,
        s.logo_url,
        s.classes_offered,
        s.requirements,
        s.profile_completed

      FROM school_admins sa

      JOIN schools s
        ON s.id = sa.school_id

      WHERE LOWER(sa.email) = $1
      LIMIT 1
      `,
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Email au password si sahihi."
      });
    }

    const admin = result.rows[0];

    if (admin.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Akaunti hii imezimwa."
      });
    }

    if (
      admin.school_status === "inactive" ||
      admin.school_status === "suspended"
    ) {
      return res.status(403).json({
        success: false,
        message: "Shule hii imezimwa kwa sasa."
      });
    }

    const validPassword =
      await verifyPassword(
        password,
        admin.password_hash
      );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Email au password si sahihi."
      });
    }

    // Remove expired sessions.
    await pool.query(
      `
      DELETE FROM school_admin_sessions
      WHERE expires_at <= CURRENT_TIMESTAMP
      `
    );

    // Generate session token.
    const token = crypto.randomBytes(48).toString("hex");
    const tokenHash = hashToken(token);

    await pool.query(
      `
      INSERT INTO school_admin_sessions (
        admin_id,
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
        maxAge: 12 * 60 * 60 * 1000,
        path: "/"
      }
    );

    res.json({
      success: true,
      message: "Umeingia kikamilifu.",
      admin: {
        id: admin.id,
        full_name: admin.full_name,
        email: admin.email,
        phone: admin.phone
      },
      school: {
        id: admin.school_id,
        name: admin.school_name,
        region: admin.region,
        district: admin.district,
        school_type: admin.school_type,
        form_price: admin.form_price,
        phone: admin.school_phone,
        address: admin.school_address,
        email: admin.school_email,
        application_start: admin.application_start,
        application_end: admin.application_end,
        status: admin.school_status,
        description: admin.description,
        logo_url: admin.logo_url,
        classes_offered: admin.classes_offered,
        requirements: admin.requirements,
        profile_completed: admin.profile_completed
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      success: false,
      message: "Tatizo la mfumo.",
      error: error.message
    });
  }
});

// ======================================================
// SCHOOL ADMIN ME
// ======================================================

app.get(
  "/api/school-admin/me",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          sa.id,
          sa.full_name,
          sa.phone,
          sa.email,

          s.id AS school_id,
          s.name,
          s.region,
          s.district,
          s.school_type,
          s.form_price,
          s.phone AS school_phone,
          s.address,
          s.email AS school_email,
          s.application_start,
          s.application_end,
          s.status,
          s.description,
          s.logo_url,
          s.classes_offered,
          s.requirements,
          s.profile_completed

        FROM school_admins sa

        JOIN schools s
          ON s.id = sa.school_id

        WHERE sa.id = $1
        `,
        [req.schoolAdmin.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "School Admin hajapatikana."
        });
      }

      const row = result.rows[0];

      res.json({
        success: true,
        admin: {
          id: row.id,
          full_name: row.full_name,
          phone: row.phone,
          email: row.email
        },
        school: {
          id: row.school_id,
          name: row.name,
          region: row.region,
          district: row.district,
          school_type: row.school_type,
          form_price: row.form_price,
          phone: row.school_phone,
          address: row.address,
          email: row.school_email,
          application_start: row.application_start,
          application_end: row.application_end,
          status: row.status,
          description: row.description,
          logo_url: row.logo_url,
          classes_offered: row.classes_offered,
          requirements: row.requirements,
          profile_completed: row.profile_completed
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// SCHOOL ADMIN - GET OWN SCHOOL
// ======================================================

app.get(
  "/api/school-admin/school",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          *
        FROM schools
        WHERE id = $1
        `,
        [req.schoolAdmin.school_id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Shule haijapatikana."
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
  }
);

// ======================================================
// SCHOOL ADMIN - UPDATE OWN SCHOOL
// ======================================================

app.put(
  "/api/school-admin/school",
  requireSchoolAdmin,
  async (req, res) => {
    try {
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
        application_end,
        description,
        logo_url,
        classes_offered,
        requirements
      } = req.body;

      if (!name || !String(name).trim()) {
        return res.status(400).json({
          success: false,
          message: "Jina la shule linahitajika."
        });
      }

      const result = await pool.query(
        `
        UPDATE schools
        SET
          name = $1,
          region = $2,
          district = $3,
          school_type = $4,
          form_price = $5,
          phone = $6,
          address = $7,
          email = $8,
          application_start = $9,
          application_end = $10,
          description = $11,
          logo_url = $12,
          classes_offered = $13,
          requirements = $14,
          profile_completed = TRUE,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $15
        RETURNING *
        `,
        [
          String(name).trim(),
          region || null,
          district || null,
          school_type || null,
          Number(form_price) || 0,
          phone || null,
          address || null,
          normalizeEmail(email) || null,
          application_start || null,
          application_end || null,
          description || null,
          logo_url || null,
          classes_offered || null,
          requirements || null,
          req.schoolAdmin.school_id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Shule haijapatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Taarifa za shule zimehifadhiwa. Shule bado haijawekwa LIVE.",
        school: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: "Imeshindikana kuhifadhi taarifa za shule.",
        error: error.message
      });
    }
  }
);

// ======================================================
// SCHOOL ADMIN - PUBLISH / PUT SCHOOL LIVE
// ======================================================

app.put(
  "/api/school-admin/school/publish",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM schools
        WHERE id = $1
        `,
        [req.schoolAdmin.school_id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Shule haijapatikana."
        });
      }

      const school = result.rows[0];

      const missing = [];

      if (!school.name) missing.push("Jina la shule");
      if (!school.region) missing.push("Mkoa");
      if (!school.district) missing.push("Wilaya");
      if (!school.school_type) missing.push("Aina ya shule");
      if (!school.phone) missing.push("Namba ya simu");
      if (!school.address) missing.push("Anwani");
      if (!school.form_price || Number(school.form_price) <= 0) {
        missing.push("Bei ya fomu");
      }

      if (missing.length > 0) {
        return res.status(400).json({
          success: false,
          message:
            "Taarifa hizi lazima zikamilishwe kabla ya shule kuwekwa LIVE.",
          missing
        });
      }

      const updated = await pool.query(
        `
        UPDATE schools
        SET
          status = 'active',
          profile_completed = TRUE,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        `,
        [req.schoolAdmin.school_id]
      );

      res.json({
        success: true,
        message:
          "Hongera! Shule sasa iko LIVE na inaweza kuonekana na wazazi.",
        school: updated.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// SCHOOL ADMIN - UNPUBLISH / DRAFT
// ======================================================

app.put(
  "/api/school-admin/school/unpublish",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        UPDATE schools
        SET
          status = 'draft',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
        RETURNING *
        `,
        [req.schoolAdmin.school_id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Shule haijapatikana."
        });
      }

      res.json({
        success: true,
        message: "Shule imerudishwa kwenye DRAFT.",
        school: result.rows[0]
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// SCHOOL ADMIN - DASHBOARD STATS
// ======================================================

app.get(
  "/api/school-admin/dashboard-stats",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          COUNT(*)::INTEGER AS total_applications,

          COUNT(*) FILTER (
            WHERE status = 'pending'
          )::INTEGER AS pending_applications,

          COUNT(*) FILTER (
            WHERE status = 'approved'
          )::INTEGER AS approved_applications,

          COUNT(*) FILTER (
            WHERE status = 'rejected'
          )::INTEGER AS rejected_applications,

          COUNT(*) FILTER (
            WHERE payment_status = 'paid'
          )::INTEGER AS paid_applications,

          COUNT(*) FILTER (
            WHERE payment_status != 'paid'
          )::INTEGER AS unpaid_applications

        FROM applications
        WHERE school_id = $1
        `,
        [req.schoolAdmin.school_id]
      );

      res.json({
        success: true,
        stats: result.rows[0]
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// SCHOOL ADMIN - APPLICATIONS
// ======================================================

app.get(
  "/api/school-admin/applications",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          a.*,

          p.id AS payment_id,
          p.payment_reference,
          p.amount AS payment_amount,
          p.status AS payment_detail_status,
          p.provider,
          p.provider_reference,
          p.paid_at

        FROM applications a

        LEFT JOIN LATERAL (
          SELECT *
          FROM payments
          WHERE application_id = a.id
          ORDER BY id DESC
          LIMIT 1
        ) p
          ON TRUE

        WHERE a.school_id = $1

        ORDER BY a.created_at DESC
        `,
        [req.schoolAdmin.school_id]
      );

      res.json({
        success: true,
        applications: result.rows,
        count: result.rows.length
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// SCHOOL ADMIN - SINGLE APPLICATION
// ======================================================

app.get(
  "/api/school-admin/applications/:id",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result = await pool.query(
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

        JOIN schools s
          ON s.id = a.school_id

        LEFT JOIN LATERAL (
          SELECT *
          FROM payments
          WHERE application_id = a.id
          ORDER BY id DESC
          LIMIT 1
        ) p
          ON TRUE

        WHERE a.id = $1
          AND a.school_id = $2
        `,
        [
          req.params.id,
          req.schoolAdmin.school_id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Application haijapatikana."
        });
      }

      res.json({
        success: true,
        application: result.rows[0]
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// SCHOOL ADMIN - APPLICATION STATUS
// ======================================================

app.put(
  "/api/school-admin/applications/:id/status",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const { status } = req.body;

      const allowedStatuses = [
        "pending",
        "approved",
        "rejected"
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Status si sahihi."
        });
      }

      const result = await pool.query(
        `
        UPDATE applications
        SET
          status = $1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
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
          message:
            "Application haijapatikana au si ya shule yako."
        });
      }

      res.json({
        success: true,
        message:
          "Status ya application imebadilishwa.",
        application: result.rows[0]
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// SCHOOL ADMIN LOGOUT
// ======================================================

app.post(
  "/api/school-admin/logout",
  async (req, res) => {
    try {
      const token = getSchoolAdminToken(req);

      if (token) {
        const tokenHash = hashToken(token);

        await pool.query(
          `
          DELETE FROM school_admin_sessions
          WHERE token_hash = $1
          `,
          [tokenHash]
        );
      }

      res.clearCookie(
        "school_admin_token",
        {
          httpOnly: true,
          secure: true,
          sameSite: "lax",
          path: "/"
        }
      );

      res.json({
        success: true,
        message: "Umetoka kwenye mfumo."
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ======================================================
// API 404
// ======================================================

app.use("/api", (req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint haijapatikana."
  });
});

// ======================================================
// GENERAL ERROR HANDLER
// ======================================================

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);

  res.status(500).json({
    success: false,
    message: "Server error.",
    error: err.message
  });
});

// ======================================================
// START SERVER
// ======================================================

setupDatabase()
  .then(() => {
    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Shule Portal Tanzania running on port ${PORT}`
        );
      }
    );
  })
  .catch(error => {
    console.error(
      "Failed to start application:",
      error
    );

    process.exit(1);
  });