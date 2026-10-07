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

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

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

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function parseBoolean(value, defaultValue = false) {
  if (value === undefined || value === null) {
    return defaultValue;
  }

  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();

    if (
      normalized === "true" ||
      normalized === "1" ||
      normalized === "yes" ||
      normalized === "on"
    ) {
      return true;
    }

    if (
      normalized === "false" ||
      normalized === "0" ||
      normalized === "no" ||
      normalized === "off"
    ) {
      return false;
    }
  }

  return Boolean(value);
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

    if (!adminId || !timestamp || !signature) {
      return null;
    }

    const age = Date.now() - timestamp;

    if (age > 12 * 60 * 60 * 1000) {
      return null;
    }

    if (age < 0) {
      return null;
    }

    const payload = `${adminId}.${timestamp}`;

    const expectedSignature = crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(payload)
      .digest("hex");

    if (signature.length !== expectedSignature.length) {
      return null;
    }

    const valid = crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );

    if (!valid) {
      return null;
    }

    return adminId;
  } catch (error) {
    console.error("TOKEN VERIFY ERROR:", error);
    return null;
  }
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
// CUSTOM FIELD HELPERS
// ============================================================

const ALLOWED_CUSTOM_FIELD_TYPES = [
  "text",
  "textarea",
  "number",
  "email",
  "phone",
  "date",
  "dropdown",
  "radio",
  "checkbox",
  "file"
];

function normalizeFieldKey(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9_]/g, "")
    .replace(/^_+|_+$/g, "")
    .slice(0, 100);
}

function normalizeOptions(options) {
  if (Array.isArray(options)) {
    return options
      .map((option) => {
        if (
          typeof option === "string" ||
          typeof option === "number"
        ) {
          return String(option).trim();
        }

        if (
          option &&
          typeof option === "object"
        ) {
          return {
            label: String(
              option.label ||
                option.value ||
                ""
            ).trim(),

            value: String(
              option.value ||
                option.label ||
                ""
            ).trim()
          };
        }

        return null;
      })
      .filter((option) => {
        if (!option) {
          return false;
        }

        if (typeof option === "string") {
          return option.length > 0;
        }

        return option.label && option.value;
      });
  }

  if (typeof options === "string") {
    try {
      const parsed = JSON.parse(options);

      if (Array.isArray(parsed)) {
        return normalizeOptions(parsed);
      }
    } catch (error) {
      // Continue and treat as comma separated values
    }

    return options
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  return [];
}

function validateCustomFieldOptions(
  fieldType,
  options
) {
  const selectionTypes = [
    "dropdown",
    "radio"
  ];

  if (selectionTypes.includes(fieldType)) {
    if (!Array.isArray(options) || options.length === 0) {
      return false;
    }
  }

  return true;
}

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

async function initializeDatabase() {
  try {
    console.log("====================================");
    console.log("INITIALIZING DATABASE");
    console.log("====================================");

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
        custom_data JSONB NOT NULL DEFAULT '{}'::jsonb,
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
    // SCHOOL MIGRATIONS
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
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS description TEXT
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS logo_url TEXT
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS classes_offered TEXT
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS requirements TEXT
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS profile_completed BOOLEAN DEFAULT FALSE
    `);

    await pool.query(`
      ALTER TABLE schools
      ADD COLUMN IF NOT EXISTS custom_data JSONB NOT NULL DEFAULT '{}'::jsonb
    `);

    // --------------------------------------------------------
    // APPLICATION MIGRATIONS
    // --------------------------------------------------------

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(255)
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS custom_data JSONB NOT NULL DEFAULT '{}'::jsonb
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending'
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
    `);

    // --------------------------------------------------------
    // PAYMENT MIGRATIONS
    // --------------------------------------------------------

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
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
    `);

    // --------------------------------------------------------
    // SCHOOL ADMIN MIGRATIONS
    // --------------------------------------------------------

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
    // SCHOOL CUSTOM FIELDS
    // --------------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS school_custom_fields (
        id SERIAL PRIMARY KEY,

        school_id INTEGER NOT NULL
          REFERENCES schools(id)
          ON DELETE CASCADE,

        field_key VARCHAR(100) NOT NULL,

        field_label VARCHAR(255) NOT NULL,

        field_type VARCHAR(50) NOT NULL DEFAULT 'text',

        placeholder TEXT,

        options JSONB NOT NULL DEFAULT '[]'::jsonb,

        is_required BOOLEAN NOT NULL DEFAULT FALSE,

        is_visible BOOLEAN NOT NULL DEFAULT TRUE,

        show_on_public BOOLEAN NOT NULL DEFAULT TRUE,

        sort_order INTEGER NOT NULL DEFAULT 0,

        created_at TIMESTAMP NOT NULL DEFAULT NOW(),

        updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

        CONSTRAINT unique_school_custom_field_key
          UNIQUE (school_id, field_key)
      )
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
      CREATE INDEX IF NOT EXISTS idx_applications_custom_data
      ON applications USING GIN(custom_data)
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

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_school_custom_fields_school
      ON school_custom_fields(school_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_school_custom_fields_order
      ON school_custom_fields(school_id, sort_order)
    `);

    console.log("DATABASE INITIALIZATION COMPLETE");
    console.log("CUSTOM FIELDS: ENABLED");
    console.log("APPLICATION CUSTOM DATA: ENABLED");
  } catch (error) {
    console.error("DATABASE INITIALIZATION ERROR:");
    console.error(error);
  }
}

// ============================================================
// STATUS
// ============================================================

app.get("/api/status", async (req, res) => {
  try {
    await pool.query("SELECT NOW()");

    res.json({
      success: true,
      message: "Shule Portal Tanzania iko online.",
      database: true
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message:
        "Server ipo online lakini database ina tatizo.",
      database: false,
      error: error.message
    });
  }
});

// ============================================================
// DATABASE CHECK
// ============================================================

app.get("/api/database-check", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT NOW() AS now"
    );

    res.json({
      success: true,
      message: "Database imeunganishwa vizuri.",
      time: result.rows[0].now
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Database haijaunganishwa.",
      error: error.message
    });
  }
});

// ============================================================
// APPLICATION SCHEMA
// ============================================================

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
      columns: result.rows
    });
  } catch (error) {
    res.status(500).json({
      success: false,
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
      SELECT
        column_name,
        data_type
      FROM information_schema.columns
      WHERE table_name = 'payments'
      ORDER BY ordinal_position
    `);

    res.json({
      success: true,
      columns: result.rows
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// ============================================================
// PUBLIC SCHOOLS
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
        description,
        logo_url,
        classes_offered,
        requirements,
        profile_completed,
        custom_data,
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
    console.error(
      "PUBLIC SCHOOLS ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// PUBLIC SCHOOL
// ============================================================

app.get("/api/schools/:id", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM schools
      WHERE id = $1
      AND status = 'active'
      `,
      [req.params.id]
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
// PUBLIC SCHOOL CUSTOM FIELDS
// ============================================================

app.get(
  "/api/schools/:id/custom-fields",
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          school_id,
          field_key,
          field_label,
          field_type,
          placeholder,
          options,
          is_required,
          is_visible,
          show_on_public,
          sort_order
        FROM school_custom_fields
        WHERE school_id = $1
        AND is_visible = TRUE
        AND show_on_public = TRUE
        ORDER BY sort_order ASC, id ASC
        `,
        [req.params.id]
      );

      res.json({
        success: true,
        fields: result.rows
      });
    } catch (error) {
      console.error(
        "PUBLIC CUSTOM FIELDS ERROR:",
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
// ADMIN SCHOOLS
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
    console.error(
      "ADMIN SCHOOLS ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// CREATE SCHOOL
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
      status,
      description,
      logo_url,
      classes_offered,
      requirements,
      profile_completed,
      custom_data
    } = req.body;

    if (!name || !String(name).trim()) {
      return res.status(400).json({
        success: false,
        message: "Jina la shule linahitajika."
      });
    }

    const cleanCustomData =
      isPlainObject(custom_data)
        ? JSON.stringify(custom_data)
        : "{}";

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
        status,
        description,
        logo_url,
        classes_offered,
        requirements,
        profile_completed,
        custom_data
      )
      VALUES
      (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
        $13,$14,$15,$16,$17,$18::jsonb
      )
      RETURNING *
      `,
      [
        String(name).trim(),
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
        status || "draft",
        description || null,
        logo_url || null,
        classes_offered || null,
        requirements || null,
        parseBoolean(profile_completed, false),
        cleanCustomData
      ]
    );

    res.json({
      success: true,
      message: "Shule imesajiliwa.",
      school: result.rows[0]
    });
  } catch (error) {
    console.error(
      "CREATE SCHOOL ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

// ============================================================
// UPDATE SCHOOL - MAIN ADMIN
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
        status,
        description,
        logo_url,
        classes_offered,
        requirements,
        profile_completed,
        custom_data
      } = req.body;

      const cleanCustomData =
        isPlainObject(custom_data)
          ? JSON.stringify(custom_data)
          : null;

      const result = await pool.query(
        `
        UPDATE schools
        SET
          name = COALESCE($1,name),
          region = COALESCE($2,region),
          district = COALESCE($3,district),
          school_type = COALESCE($4,school_type),
          type = COALESCE($5,type),
          form_price = COALESCE($6,form_price),
          phone = COALESCE($7,phone),
          address = COALESCE($8,address),
          email = COALESCE($9,email),
          application_start = COALESCE($10,application_start),
          application_end = COALESCE($11,application_end),
          status = COALESCE($12,status),
          description = COALESCE($13,description),
          logo_url = COALESCE($14,logo_url),
          classes_offered = COALESCE($15,classes_offered),
          requirements = COALESCE($16,requirements),
          profile_completed = COALESCE($17,profile_completed),
          custom_data = COALESCE($18::jsonb,custom_data),
          updated_at = NOW()
        WHERE id = $19
        RETURNING *
        `,
        [
          name ? String(name).trim() : null,
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
          status || null,
          description || null,
          logo_url || null,
          classes_offered || null,
          requirements || null,
          profile_completed !== undefined
            ? parseBoolean(profile_completed)
            : null,
          cleanCustomData,
          req.params.id
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
        message:
          "Taarifa za shule zimebadilishwa.",
        school: result.rows[0]
      });
    } catch (error) {
      console.error(
        "UPDATE SCHOOL ERROR:",
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
// SCHOOL CUSTOM FIELDS - ADMIN LIST
// ============================================================

app.get(
  "/api/admin/schools/:schoolId/custom-fields",
  async (req, res) => {
    try {
      const schoolId =
        Number(req.params.schoolId);

      if (!Number.isInteger(schoolId)) {
        return res.status(400).json({
          success: false,
          message: "School ID si sahihi."
        });
      }

      const result = await pool.query(
        `
        SELECT
          id,
          school_id,
          field_key,
          field_label,
          field_type,
          placeholder,
          options,
          is_required,
          is_visible,
          show_on_public,
          sort_order,
          created_at,
          updated_at
        FROM school_custom_fields
        WHERE school_id = $1
        ORDER BY sort_order ASC, id ASC
        `,
        [schoolId]
      );

      res.json({
        success: true,
        fields: result.rows
      });
    } catch (error) {
      console.error(
        "CUSTOM FIELDS LIST ERROR:",
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
// CREATE CUSTOM FIELD
// ============================================================

app.post(
  "/api/admin/schools/:schoolId/custom-fields",
  async (req, res) => {
    try {
      const schoolId =
        Number(req.params.schoolId);

      const {
        field_key,
        field_label,
        field_type,
        placeholder,
        options,
        is_required,
        is_visible,
        show_on_public,
        sort_order
      } = req.body;

      if (!Number.isInteger(schoolId)) {
        return res.status(400).json({
          success: false,
          message: "School ID si sahihi."
        });
      }

      if (
        !field_key ||
        !String(field_label || "").trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Field key na field label vinahitajika."
        });
      }

      const normalizedKey =
        normalizeFieldKey(field_key);

      if (!normalizedKey) {
        return res.status(400).json({
          success: false,
          message:
            "Field key si sahihi."
        });
      }

      const finalType =
        String(field_type || "text")
          .trim()
          .toLowerCase();

      if (
        !ALLOWED_CUSTOM_FIELD_TYPES.includes(
          finalType
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Aina ya field si sahihi."
        });
      }

      const school =
        await pool.query(
          `
          SELECT id
          FROM schools
          WHERE id = $1
          `,
          [schoolId]
        );

      if (school.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id
          FROM school_custom_fields
          WHERE school_id = $1
          AND field_key = $2
          `,
          [
            schoolId,
            normalizedKey
          ]
        );

      if (existing.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message:
            "Field key hiyo tayari ipo kwenye shule hii."
        });
      }

      const cleanOptions =
        normalizeOptions(options);

      if (
        !validateCustomFieldOptions(
          finalType,
          cleanOptions
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Dropdown/Radio lazima ziwe na options."
        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO school_custom_fields
          (
            school_id,
            field_key,
            field_label,
            field_type,
            placeholder,
            options,
            is_required,
            is_visible,
            show_on_public,
            sort_order
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10
          )
          RETURNING *
          `,
          [
            schoolId,
            normalizedKey,
            String(field_label).trim(),
            finalType,
            placeholder
              ? String(placeholder).trim()
              : null,
            JSON.stringify(cleanOptions),
            parseBoolean(is_required, false),
            parseBoolean(is_visible, true),
            parseBoolean(show_on_public, true),
            Number(sort_order || 0)
          ]
        );

      res.json({
        success: true,
        message:
          "Kipengele kimeongezwa.",
        field: result.rows[0]
      });
    } catch (error) {
      console.error(
        "CREATE CUSTOM FIELD ERROR:",
        error
      );

      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          message:
            "Field key hiyo tayari ipo."
        });
      }

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// UPDATE CUSTOM FIELD
// ============================================================

app.put(
  "/api/admin/schools/:schoolId/custom-fields/:fieldId",
  async (req, res) => {
    try {
      const schoolId =
        Number(req.params.schoolId);

      const fieldId =
        Number(req.params.fieldId);

      const {
        field_key,
        field_label,
        field_type,
        placeholder,
        options,
        is_required,
        is_visible,
        show_on_public,
        sort_order
      } = req.body;

      if (
        !Number.isInteger(schoolId) ||
        !Number.isInteger(fieldId)
      ) {
        return res.status(400).json({
          success: false,
          message: "ID si sahihi."
        });
      }

      const normalizedKey =
        normalizeFieldKey(field_key);

      if (
        !normalizedKey ||
        !String(field_label || "").trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Field key na field label vinahitajika."
        });
      }

      const finalType =
        String(field_type || "text")
          .trim()
          .toLowerCase();

      if (
        !ALLOWED_CUSTOM_FIELD_TYPES.includes(
          finalType
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Aina ya field si sahihi."
        });
      }

      const duplicate =
        await pool.query(
          `
          SELECT id
          FROM school_custom_fields
          WHERE school_id = $1
          AND field_key = $2
          AND id <> $3
          `,
          [
            schoolId,
            normalizedKey,
            fieldId
          ]
        );

      if (duplicate.rows.length > 0) {
        return res.status(409).json({
          success: false,
          message:
            "Field key hiyo tayari ipo."
        });
      }

      const cleanOptions =
        normalizeOptions(options);

      if (
        !validateCustomFieldOptions(
          finalType,
          cleanOptions
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Dropdown/Radio lazima ziwe na options."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE school_custom_fields
          SET
            field_key = $1,
            field_label = $2,
            field_type = $3,
            placeholder = $4,
            options = $5::jsonb,
            is_required = $6,
            is_visible = $7,
            show_on_public = $8,
            sort_order = $9,
            updated_at = NOW()
          WHERE id = $10
          AND school_id = $11
          RETURNING *
          `,
          [
            normalizedKey,
            String(field_label).trim(),
            finalType,
            placeholder
              ? String(placeholder).trim()
              : null,
            JSON.stringify(cleanOptions),
            parseBoolean(is_required, false),
            parseBoolean(is_visible, true),
            parseBoolean(show_on_public, true),
            Number(sort_order || 0),
            fieldId,
            schoolId
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Kipengele hakipatikani."
        });
      }

      res.json({
        success: true,
        message:
          "Kipengele kimesasishwa.",
        field: result.rows[0]
      });
    } catch (error) {
      console.error(
        "UPDATE CUSTOM FIELD ERROR:",
        error
      );

      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          message:
            "Field key hiyo tayari ipo."
        });
      }

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

// ============================================================
// DELETE CUSTOM FIELD
// ============================================================

app.delete(
  "/api/admin/schools/:schoolId/custom-fields/:fieldId",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          DELETE FROM school_custom_fields
          WHERE id = $1
          AND school_id = $2
          RETURNING *
          `,
          [
            req.params.fieldId,
            req.params.schoolId
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Kipengele hakipatikani."
        });
      }

      res.json({
        success: true,
        message:
          "Kipengele kimefutwa."
      });
    } catch (error) {
      console.error(
        "DELETE CUSTOM FIELD ERROR:",
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
// SCHOOL ADMINS - LIST
// ============================================================

app.get(
  "/api/admin/school-admins",
  async (req, res) => {
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
      console.error(
        "SCHOOL ADMINS LIST ERROR:",
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
// SCHOOL ADMIN - SINGLE
// ============================================================

app.get(
  "/api/admin/school-admins/:id",
  async (req, res) => {
    try {
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
        [req.params.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "School Admin hakupatikana."
        });
      }

      res.json({
        success: true,
        admin: result.rows[0]
      });
    } catch (error) {
      console.error(
        "SINGLE SCHOOL ADMIN ERROR:",
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

      if (String(password).length < 4) {
        return res.status(400).json({
          success: false,
          message:
            "Password lazima iwe na angalau herufi 4."
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

      if (existing.rows.length > 0) {
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

      if (school.rows.length === 0) {
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
            String(full_name).trim(),
            normalizedEmail,
            phone || null,
            hashPassword(password),
            status || "active"
          ]
        );

      res.json({
        success: true,
        message:
          "School Admin ameundwa.",
        admin: result.rows[0]
      });
    } catch (error) {
      console.error(
        "CREATE SCHOOL ADMIN ERROR:",
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

      let normalizedEmail = null;

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

        if (duplicate.rows.length > 0) {
          return res.status(409).json({
            success: false,
            message:
              "Email hiyo tayari inatumika."
          });
        }
      }

      if (school_id) {
        const school =
          await pool.query(
            `
            SELECT id
            FROM schools
            WHERE id = $1
            `,
            [school_id]
          );

        if (school.rows.length === 0) {
          return res.status(404).json({
            success: false,
            message:
              "Shule haipatikani."
          });
        }
      }

      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            school_id = COALESCE($1,school_id),
            full_name = COALESCE($2,full_name),
            email = COALESCE($3,email),
            phone = COALESCE($4,phone),
            status = COALESCE($5,status),
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
            full_name
              ? String(full_name).trim()
              : null,
            normalizedEmail,
            phone || null,
            status || null,
            req.params.id
          ]
        );

      if (result.rows.length === 0) {
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
        admin: result.rows[0]
      });
    } catch (error) {
      console.error(
        "UPDATE SCHOOL ADMIN ERROR:",
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
// SCHOOL ADMIN STATUS
// ============================================================

app.put(
  "/api/admin/school-admins/:id/status",
  async (req, res) => {
    try {
      const { status } = req.body;

      const allowed = [
        "active",
        "inactive",
        "suspended"
      ];

      if (!allowed.includes(status)) {
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

      if (result.rows.length === 0) {
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
        admin: result.rows[0]
      });
    } catch (error) {
      console.error(
        "ADMIN STATUS ERROR:",
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
// RESET PASSWORD
// ============================================================

app.put(
  "/api/admin/school-admins/:id/reset-password",
  async (req, res) => {
    try {
      const { password } = req.body;

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
            hashPassword(password),
            req.params.id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "School Admin hakupatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Password imebadilishwa.",
        admin: result.rows[0]
      });
    } catch (error) {
      console.error(
        "RESET PASSWORD ERROR:",
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
// OLD PASSWORD ROUTE
// ============================================================

app.put(
  "/api/admin/school-admins/:id/password",
  async (req, res) => {
    try {
      const { password } = req.body;

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
            hashPassword(password),
            req.params.id
          ]
        );

      if (result.rows.length === 0) {
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
        message: error.message
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

      if (result.rows.length === 0) {
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
        message: error.message
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

      if (!email || !password) {
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

      if (adminResult.rows.length === 0) {
        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });
      }

      const admin =
        adminResult.rows[0];

      const suppliedHash =
        hashPassword(password);

      if (
        !admin.password_hash ||
        suppliedHash !== admin.password_hash
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });
      }

      if (admin.status !== "active") {
        return res.status(403).json({
          success: false,
          message:
            "Akaunti yako ya School Admin haijawezeshwa."
        });
      }

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
            status,
            custom_data
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [admin.school_id]
        );

      if (schoolResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Shule iliyounganishwa na akaunti hii haipatikani."
        });
      }

      const school =
        schoolResult.rows[0];

      if (
        school.status === "inactive" ||
        school.status === "suspended"
      ) {
        return res.status(403).json({
          success: false,
          message:
            "Shule hii haijawezeshwa kwa sasa."
        });
      }

      const token =
        createSchoolAdminToken(
          admin.id
        );

      await pool.query(
        `
        UPDATE school_admins
        SET
          last_login = NOW()
        WHERE id = $1
        `,
        [admin.id]
      );

      setSchoolAdminCookie(
        res,
        token
      );

      return res.json({
        success: true,
        message:
          "Umefanikiwa kuingia.",
        admin: {
          id: admin.id,
          full_name: admin.full_name,
          email: admin.email,
          phone: admin.phone,
          school_id: admin.school_id,
          school_name: school.name,
          school_status: school.status
        }
      });
    } catch (error) {
      console.error(
        "SCHOOL ADMIN LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Hitilafu ya server wakati wa kuingia.",
        error: error.message
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
          s.status AS school_status,
          s.custom_data

        FROM school_admins sa

        LEFT JOIN schools s
          ON s.id = sa.school_id

        WHERE sa.id = $1

        LIMIT 1
        `,
        [adminId]
      );

    if (result.rows.length === 0) {
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

    if (admin.admin_status !== "active") {
      clearSchoolAdminCookie(
        res
      );

      return res.status(403).json({
        success: false,
        message:
          "Akaunti yako haijawezeshwa."
      });
    }

    if (
      admin.school_status === "inactive" ||
      admin.school_status === "suspended"
    ) {
      return res.status(403).json({
        success: false,
        message:
          "Shule haijawezeshwa."
      });
    }

    req.schoolAdmin = admin;

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
      error: error.message
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
      admin: req.schoolAdmin
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
        message: error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN DASHBOARD STATS
// ============================================================

app.get(
  "/api/school-admin/dashboard/stats",
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
          INNER JOIN applications a
            ON a.id = p.application_id
          WHERE a.school_id = $1
          AND p.status IN (
            'paid',
            'confirmed',
            'completed'
          )
          `,
          [schoolId]
        );

      const unpaid =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS total
          FROM payments p
          INNER JOIN applications a
            ON a.id = p.application_id
          WHERE a.school_id = $1
          AND (
            p.status IS NULL
            OR p.status NOT IN (
              'paid',
              'confirmed',
              'completed'
            )
          )
          `,
          [schoolId]
        );

      const today =
        await pool.query(
          `
          SELECT COUNT(*)::INTEGER AS total
          FROM applications
          WHERE school_id = $1
          AND created_at::date = CURRENT_DATE
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
            paid.rows[0].total,

          unpaid:
            unpaid.rows[0].total,

          today:
            today.rows[0].total
        }
      });
    } catch (error) {
      console.error(
        "DASHBOARD STATS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata takwimu za dashboard.",
        error: error.message
      });
    }
  }
);

// ============================================================
// OLD DASHBOARD STATS ROUTE
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
          INNER JOIN applications a
            ON a.id = p.application_id
          WHERE a.school_id = $1
          AND p.status IN (
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
        "OLD DASHBOARD STATS ERROR:",
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
      console.error(
        "SCHOOL ADMIN APPLICATIONS ERROR:",
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

      if (result.rows.length === 0) {
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
      console.error(
        "SINGLE SCHOOL APPLICATION ERROR:",
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

      if (result.rows.length === 0) {
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
// GET SCHOOL BY SCHOOL ADMIN
// ============================================================

app.get(
  "/api/school-admin/school",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const schoolId =
        req.schoolAdmin.school_id;

      const result =
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
            status,
            description,
            logo_url,
            classes_offered,
            requirements,
            profile_completed,
            custom_data,
            created_at,
            updated_at
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [schoolId]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
        });
      }

      return res.json({
        success: true,
        school:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        "GET SCHOOL ADMIN SCHOOL ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata taarifa za shule.",
        error:
          error.message
      });
    }
  }
);

// ============================================================
// SCHOOL ADMIN CUSTOM FIELDS
// ============================================================

app.get(
  "/api/school-admin/custom-fields",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            school_id,
            field_key,
            field_label,
            field_type,
            placeholder,
            options,
            is_required,
            is_visible,
            show_on_public,
            sort_order
          FROM school_custom_fields
          WHERE school_id = $1
          AND is_visible = TRUE
          ORDER BY sort_order ASC, id ASC
          `,
          [
            req.schoolAdmin.school_id
          ]
        );

      return res.json({
        success: true,
        fields: result.rows
      });
    } catch (error) {
      console.error(
        "SCHOOL ADMIN CUSTOM FIELDS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message: error.message
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
        description,
        logo_url,
        classes_offered,
        requirements,
        profile_completed,
        custom_data
      } = req.body;

      if (!name || !String(name).trim()) {
        return res.status(400).json({
          success: false,
          message:
            "Jina la shule linahitajika."
        });
      }

      if (!region || !String(region).trim()) {
        return res.status(400).json({
          success: false,
          message:
            "Mkoa wa shule unahitajika."
        });
      }

      if (!district || !String(district).trim()) {
        return res.status(400).json({
          success: false,
          message:
            "Wilaya ya shule inahitajika."
        });
      }

      if (!school_type && !type) {
        return res.status(400).json({
          success: false,
          message:
            "Aina ya shule inahitajika."
        });
      }

      const numericPrice =
        Number(form_price);

      if (
        !Number.isFinite(numericPrice) ||
        numericPrice < 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Bei ya fomu si sahihi."
        });
      }

      if (
        application_start &&
        application_end &&
        new Date(application_start) >
          new Date(application_end)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Tarehe ya kuanza maombi haiwezi kuwa baada ya tarehe ya mwisho."
        });
      }

      const finalSchoolType =
        String(
          school_type || type
        ).trim();

      const cleanCustomData =
        isPlainObject(custom_data)
          ? JSON.stringify(custom_data)
          : "{}";

      const result =
        await pool.query(
          `
          UPDATE schools
          SET
            name = $1,
            region = $2,
            district = $3,
            school_type = $4,
            type = $5,
            form_price = $6,
            phone = $7,
            address = $8,
            email = $9,
            application_start = $10,
            application_end = $11,
            description = $12,
            logo_url = $13,
            classes_offered = $14,
            requirements = $15,
            profile_completed = $16,
            custom_data = $17::jsonb,
            updated_at = NOW()
          WHERE id = $18
          RETURNING *
          `,
          [
            String(name).trim(),
            String(region).trim(),
            String(district).trim(),
            finalSchoolType,
            finalSchoolType,
            numericPrice,
            phone
              ? String(phone).trim()
              : null,
            address
              ? String(address).trim()
              : null,
            email
              ? String(email).trim()
              : null,
            application_start || null,
            application_end || null,
            description || null,
            logo_url || null,
            classes_offered || null,
            requirements || null,
            parseBoolean(
              profile_completed,
              false
            ),
            cleanCustomData,
            req.schoolAdmin.school_id
          ]
        );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani."
        });
      }

      return res.json({
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

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuhifadhi taarifa za shule.",
        error:
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

      if (result.rows.length === 0) {
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

      if (result.rows.length === 0) {
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
        message: error.message
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
        address,
        custom_data
      } = req.body;

      // ------------------------------------------------------
      // BASIC VALIDATION
      // ------------------------------------------------------

      if (!school_id) {
        return res.status(400).json({
          success: false,
          message:
            "Shule haijachaguliwa."
        });
      }

      if (
        !student_name ||
        !String(student_name).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Jina la mwanafunzi linahitajika."
        });
      }

      if (
        !parent_name ||
        !String(parent_name).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Jina la mzazi/mlezi linahitajika."
        });
      }

      if (
        !parent_phone ||
        !String(parent_phone).trim()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Namba ya simu ya mzazi/mlezi inahitajika."
        });
      }

      // ------------------------------------------------------
      // NORMALIZE CUSTOM DATA
      // ------------------------------------------------------

      let cleanCustomData = {};

      if (isPlainObject(custom_data)) {
        cleanCustomData = custom_data;
      }

      await client.query("BEGIN");

      // ------------------------------------------------------
      // GET SCHOOL
      // ------------------------------------------------------

      const schoolResult =
        await client.query(
          `
          SELECT
            id,
            name,
            region,
            district,
            school_type,
            type,
            form_price,
            status
          FROM schools
          WHERE id = $1
          AND status = 'active'
          LIMIT 1
          `,
          [Number(school_id)]
        );

      if (schoolResult.rows.length === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani au haiko LIVE."
        });
      }

      const school =
        schoolResult.rows[0];

      // ------------------------------------------------------
      // GET PUBLIC CUSTOM FIELDS
      // ------------------------------------------------------

      const fieldsResult =
        await client.query(
          `
          SELECT
            id,
            field_key,
            field_label,
            field_type,
            options,
            is_required,
            is_visible,
            show_on_public,
            sort_order
          FROM school_custom_fields
          WHERE school_id = $1
          AND is_visible = TRUE
          AND show_on_public = TRUE
          ORDER BY sort_order ASC, id ASC
          `,
          [school.id]
        );

      const customFields =
        fieldsResult.rows;

      // ------------------------------------------------------
      // VALIDATE CUSTOM FIELD VALUES
      // ------------------------------------------------------

      for (const field of customFields) {
        const value =
          cleanCustomData[
            field.field_key
          ];

        // Required field
        if (field.is_required) {
          let missing = false;

          if (field.field_type === "checkbox") {
            if (
              value === undefined ||
              value === null ||
              value === false ||
              value === ""
            ) {
              missing = true;
            }
          } else if (
            value === undefined ||
            value === null ||
            String(value).trim() === ""
          ) {
            missing = true;
          }

          if (missing) {
            await client.query(
              "ROLLBACK"
            );

            return res.status(400).json({
              success: false,
              message:
                `Tafadhali jaza kipengele: ${field.field_label}.`,
              field_key:
                field.field_key,
              field_label:
                field.field_label
            });
          }
        }

        // Validate dropdown/radio
        if (
          value !== undefined &&
          value !== null &&
          value !== "" &&
          (
            field.field_type === "dropdown" ||
            field.field_type === "radio"
          )
        ) {
          const options =
            normalizeOptions(
              field.options
            );

          const allowedValues =
            options.map((option) => {
              if (
                typeof option === "string"
              ) {
                return option;
              }

              return option.value;
            });

          if (
            !allowedValues.includes(
              String(value)
            )
          ) {
            await client.query(
              "ROLLBACK"
            );

            return res.status(400).json({
              success: false,
              message:
                `Thamani ya ${field.field_label} si sahihi.`,
              field_key:
                field.field_key
            });
          }
        }
      }

      // ------------------------------------------------------
      // ONLY ACCEPT FIELDS BELONGING TO THIS SCHOOL
      // ------------------------------------------------------

      const allowedKeys =
        new Set(
          customFields.map(
            (field) =>
              field.field_key
          )
        );

      const filteredCustomData =
        {};

      for (
        const [
          key,
          value
        ] of Object.entries(
          cleanCustomData
        )
      ) {
        if (
          allowedKeys.has(key)
        ) {
          filteredCustomData[key] =
            value;
        }
      }

      // ------------------------------------------------------
      // GENERATE APPLICATION NUMBER
      // ------------------------------------------------------

      const applicationNumber =
        generateApplicationNumber();

      // ------------------------------------------------------
      // INSERT APPLICATION
      // ------------------------------------------------------

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
            custom_data,
            status
          )
          VALUES
          (
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
            $11::jsonb,
            'pending'
          )
          RETURNING *
          `,
          [
            applicationNumber,
            school.id,
            String(student_name).trim(),
            gender
              ? String(gender).trim()
              : null,
            date_of_birth || null,
            class_applied
              ? String(
                  class_applied
                ).trim()
              : null,
            String(
              parent_name
            ).trim(),
            String(
              parent_phone
            ).trim(),
            parent_email
              ? String(
                  parent_email
                ).trim()
              : null,
            address
              ? String(
                  address
                ).trim()
              : null,
            JSON.stringify(
              filteredCustomData
            )
          ]
        );

      const application =
        applicationResult.rows[0];

      // ------------------------------------------------------
      // CREATE PAYMENT REFERENCE
      // ------------------------------------------------------

      const paymentReference =
        generatePaymentReference();

      const formPrice =
        Number(
          school.form_price || 0
        );

      // ------------------------------------------------------
      // CREATE PAYMENT RECORD
      // ------------------------------------------------------

      await client.query(
        `
        INSERT INTO payments
        (
          application_id,
          application_number,
          payment_reference,
          amount,
          status,
          payment_method
        )
        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          'pending',
          'pending'
        )
        `,
        [
          application.id,
          applicationNumber,
          paymentReference,
          formPrice
        ]
      );

      // ------------------------------------------------------
      // COMMIT
      // ------------------------------------------------------

      await client.query(
        "COMMIT"
      );

      // ------------------------------------------------------
      // RESPONSE
      // ------------------------------------------------------

      return res.status(201).json({
        success: true,

        message:
          "Application imepokelewa.",

        application: {
          ...application,

          payment_reference:
            paymentReference,

          amount:
            formPrice,

          school_name:
            school.name,

          custom_data:
            filteredCustomData
        }
      });

    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch (
        rollbackError
      ) {
        console.error(
          "ROLLBACK ERROR:",
          rollbackError
        );
      }

      console.error(
        "CREATE APPLICATION ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kutengeneza application.",
        error:
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
            s.custom_data AS school_custom_data,

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

      if (result.rows.length === 0) {
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
      console.error(
        "APPLICATION LOOKUP ERROR:",
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

      if (result.rows.length === 0) {
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

            s.name AS school_name,
            s.id AS school_id

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
      console.error(
        "ADMIN PAYMENTS ERROR:",
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

      if (result.rows.length === 0) {
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

    if (res.headersSent) {
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
// START SERVER
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
        "DASHBOARD STATS: ENABLED"
      );

      console.log(
        "SCHOOL EDIT ROUTES: ENABLED"
      );

      console.log(
        "CUSTOM FIELD BUILDER: ENABLED"
      );

      console.log(
        "APPLICATION CUSTOM DATA: ENABLED"
      );

      console.log(
        "PAYMENT SYSTEM: ENABLED"
      );

      console.log(
        "===================================="
      );
    }
  );
}

startServer();