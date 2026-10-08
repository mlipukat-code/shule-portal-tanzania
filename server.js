const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);

const SESSION_SECRET =
  process.env.SESSION_SECRET || "change-this-secret-in-production";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));

app.use(express.static(path.join(__dirname, "public")));

app.get("/:file.html", (req, res, next) => {
  const fileName = String(req.params.file || "").trim();

  if (!/^[a-zA-Z0-9_-]+$/.test(fileName)) {
    return next();
  }

  const publicFile = path.join(__dirname, "public", `${fileName}.html`);
  const rootFile = path.join(__dirname, `${fileName}.html`);

  res.sendFile(publicFile, err => {
    if (!err) return;

    res.sendFile(rootFile, err2 => {
      if (err2) return next();
    });
  });
});

/* =========================================================
   DATABASE
========================================================= */

const sessions = new Map();

async function q(text, params = []) {
  return pool.query(text, params).then(r => r.rows);
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

function randomHex(bytes = 8) {
  return crypto.randomBytes(bytes).toString("hex").toUpperCase();
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function generateApplicationNumber() {
  const year = new Date().getFullYear();
  return `SPT-${year}-${Date.now()}-${randomHex(2)}`;
}

function generatePaymentReference() {
  return `SPT-PAY-${Date.now()}-${randomHex(3)}`;
}

function getBearerToken(req) {
  const header = String(req.headers.authorization || "");

  if (!header.toLowerCase().startsWith("bearer ")) {
    return "";
  }

  return header.substring(7).trim();
}

function toBoolean(value, defaultValue = false) {
  if (value === undefined || value === null) {
    return defaultValue;
  }

  if (typeof value === "boolean") return value;

  const v = String(value).toLowerCase().trim();

  if (["true", "1", "yes", "active", "published"].includes(v)) {
    return true;
  }

  if (["false", "0", "no", "inactive", "unpublished"].includes(v)) {
    return false;
  }

  return defaultValue;
}

function normalizeOptions(options) {
  if (!Array.isArray(options)) return [];

  return options
    .map(option => {
      if (typeof option === "object" && option !== null) {
        const value = String(option.value ?? option.label ?? "").trim();
        const label = String(option.label ?? option.value ?? "").trim();

        if (!value) return null;

        return {
          value,
          label: label || value
        };
      }

      const value = String(option).trim();

      if (!value) return null;

      return {
        value,
        label: value
      };
    })
    .filter(Boolean);
}

function cleanFieldInput(body = {}) {
  const fieldType = String(
    body.field_type || body.type || "text"
  ).trim().toLowerCase();

  const fieldLabel = String(
    body.field_label || body.label || ""
  ).trim();

  const fieldName = String(
    body.field_name || body.name || ""
  ).trim();

  const required = toBoolean(body.required, false);

  const options = normalizeOptions(body.options);

  return {
    field_type: fieldType,
    field_label: fieldLabel,
    field_name: fieldName,
    required,
    options
  };
}

/* =========================================================
   AUTHENTICATION
========================================================= */

function mainAdmin(req, res, next) {
  const token = getBearerToken(req);
  const session = sessions.get(token);

  if (!session || session.role !== "main_admin") {
    return res.status(401).json({
      success: false,
      message: "Login ya Admin Mkuu inahitajika"
    });
  }

  req.auth = session;
  next();
}

function schoolAdmin(req, res, next) {
  const token = getBearerToken(req);
  const session = sessions.get(token);

  if (!session || session.role !== "school_admin") {
    return res.status(401).json({
      success: false,
      message: "Login ya Admin wa Shule inahitajika"
    });
  }

  req.auth = session;
  next();
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDatabase() {
  await q(`
    CREATE TABLE IF NOT EXISTS schools (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      region TEXT,
      district TEXT,
      level TEXT,
      form_price NUMERIC(12,2) DEFAULT 0,
      phone TEXT,
      address TEXT,
      email TEXT,
      description TEXT,
      logo_url TEXT,
      website TEXT,
      status TEXT DEFAULT 'active',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS applications (
      id SERIAL PRIMARY KEY,
      application_number VARCHAR(100) UNIQUE NOT NULL,
      school_id INT REFERENCES schools(id) ON DELETE CASCADE,
      form_id INT,
      applicant_name VARCHAR(255),
      applicant_gender VARCHAR(50),
      applicant_date_of_birth DATE,
      parent_name VARCHAR(255),
      parent_phone VARCHAR(100),
      parent_email VARCHAR(255),
      address TEXT,
      status VARCHAR(50) DEFAULT 'submitted',
      payment_status VARCHAR(50) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW(),
      student_name VARCHAR(255),
      gender VARCHAR(50),
      date_of_birth DATE,
      class_level VARCHAR(255),
      phone VARCHAR(100),
      email VARCHAR(255),
      custom_data JSONB DEFAULT '{}'::jsonb
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      application_id INT REFERENCES applications(id) ON DELETE CASCADE,
      payment_reference VARCHAR(150) UNIQUE NOT NULL,
      amount NUMERIC(12,2) DEFAULT 0,
      currency VARCHAR(10) DEFAULT 'TZS',
      status VARCHAR(50) DEFAULT 'pending',
      method VARCHAR(100),
      transaction_id VARCHAR(255),
      phone VARCHAR(100),
      paid_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS school_admins (
      id SERIAL PRIMARY KEY,
      school_id INT REFERENCES schools(id) ON DELETE CASCADE,
      full_name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS school_admin_sessions (
      id SERIAL PRIMARY KEY,
      school_admin_id INT REFERENCES school_admins(id) ON DELETE CASCADE,
      token TEXT UNIQUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS school_custom_fields (
      id SERIAL PRIMARY KEY,
      school_id INT REFERENCES schools(id) ON DELETE CASCADE,
      field_name TEXT,
      field_label TEXT,
      field_type TEXT DEFAULT 'text',
      required BOOLEAN DEFAULT FALSE,
      options JSONB DEFAULT '[]'::jsonb,
      sort_order INT DEFAULT 0,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS school_forms (
      id SERIAL PRIMARY KEY,
      school_id INT REFERENCES schools(id) ON DELETE CASCADE,
      file_name TEXT NOT NULL,
      mime_type TEXT DEFAULT 'application/pdf',
      file_data TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      uploaded_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  /* ---------------------------------------------------------
     SAFE MIGRATIONS
  --------------------------------------------------------- */

  const migrations = [
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS description TEXT`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS logo_url TEXT`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS website TEXT`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS email TEXT`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS phone TEXT`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS address TEXT`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS form_price NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS applicant_name VARCHAR(255)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS applicant_gender VARCHAR(50)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS applicant_date_of_birth DATE`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS parent_name VARCHAR(255)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS parent_phone VARCHAR(100)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS parent_email VARCHAR(255)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS address TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'submitted'`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS payment_status VARCHAR(50) DEFAULT 'pending'`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS student_name VARCHAR(255)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS gender VARCHAR(50)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS date_of_birth DATE`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS class_level VARCHAR(255)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS phone VARCHAR(100)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS email VARCHAR(255)`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS custom_data JSONB DEFAULT '{}'::jsonb`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS method VARCHAR(100)`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS transaction_id VARCHAR(255)`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS phone VARCHAR(100)`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ`,
    `ALTER TABLE school_admins ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE`,
    `ALTER TABLE school_admins ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`,
    `ALTER TABLE school_admins ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`
  ];

  for (const migration of migrations) {
    try {
      await q(migration);
    } catch (error) {
      console.error("Migration warning:", error.message);
    }
  }

  /* ---------------------------------------------------------
     DEMO SCHOOLS
  --------------------------------------------------------- */

  const schoolCount = await q(`
    SELECT COUNT(*)::int AS count
    FROM schools
  `);

  if (Number(schoolCount[0]?.count || 0) === 0) {
    await q(`
      INSERT INTO schools
      (name, region, district, level, form_price, phone, address, email, description, status)
      VALUES
      ('Mlipuka Academy','Dar es Salaam','Ubungo','Primary & Secondary',20000,'0765447073','Msumi','thomsonchristom@gmail.com','Shule inayopokea maombi kupitia Shule Portal Tanzania.','active'),
      ('Brothers','Arusha','Ngarenaro','Primary & Secondary',30000,'0616084704','','','','active'),
      ('Bright Future School','Dar es Salaam','Kinondoni','Primary',20000,'0742505055','','','','active')
    `);
  }

  /* ---------------------------------------------------------
     DEMO SCHOOL ADMIN
  --------------------------------------------------------- */

  const adminCount = await q(`
    SELECT COUNT(*)::int AS count
    FROM school_admins
  `);

  if (Number(adminCount[0]?.count || 0) === 0) {
    const firstSchool = await q(`
      SELECT id
      FROM schools
      ORDER BY id ASC
      LIMIT 1
    `);

    if (firstSchool[0]) {
      await q(`
        INSERT INTO school_admins
        (school_id, full_name, email, password_hash, active)
        VALUES ($1,$2,$3,$4,true)
      `, [
        firstSchool[0].id,
        "Imanuel",
        "ima@john.com",
        hashPassword("123456")
      ]);
    }
  }

  console.log("Database initialized successfully.");
}

/* =========================================================
   CUSTOM FIELD HELPERS
========================================================= */

async function getSchoolCustomFields(schoolId) {
  return q(`
    SELECT
      id,
      school_id,
      field_name,
      field_label,
      field_type,
      required,
      options,
      sort_order,
      active,
      created_at,
      updated_at
    FROM school_custom_fields
    WHERE school_id=$1
      AND active=true
    ORDER BY sort_order ASC, id ASC
  `, [schoolId]);
}

async function validateCustomData(schoolId, customData) {
  const fields = await getSchoolCustomFields(schoolId);
  const errors = [];

  const data =
    customData &&
    typeof customData === "object" &&
    !Array.isArray(customData)
      ? customData
      : {};

  for (const field of fields) {
    const value = data[field.field_name];

    const empty =
      value === undefined ||
      value === null ||
      String(value).trim() === "";

    if (field.required && empty) {
      errors.push(`Jaza taarifa: ${field.field_label}`);
      continue;
    }

    if (empty) continue;

    const type = String(field.field_type || "").toLowerCase();

    if (type === "dropdown" || type === "select" || type === "radio") {
      const allowed = new Set(
        normalizeOptions(field.options).map(o => String(o.value))
      );

      if (!allowed.has(String(value))) {
        errors.push(`Chaguo si sahihi kwa: ${field.field_label}`);
      }
    }
  }

  return errors;
}

/* =========================================================
   BASIC ROUTES
========================================================= */

app.get("/api/status", async (req, res) => {
  res.json({
    success: true,
    status: "online",
    service: "Shule Portal Tanzania",
    time: new Date().toISOString()
  });
});

app.get("/api/database-check", async (req, res) => {
  try {
    await q("SELECT NOW() AS now");

    res.json({
      success: true,
      database: "connected"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      database: "not_connected",
      message: error.message
    });
  }
});

app.get("/api/application-schema", async (req, res) => {
  try {
    const columns = await q(`
      SELECT
        column_name,
        data_type
      FROM information_schema.columns
      WHERE table_name='applications'
      ORDER BY ordinal_position
    `);

    res.json({
      success: true,
      columns
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.get("/api/payment-schema", async (req, res) => {
  try {
    const columns = await q(`
      SELECT
        column_name,
        data_type
      FROM information_schema.columns
      WHERE table_name='payments'
      ORDER BY ordinal_position
    `);

    res.json({
      success: true,
      columns
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* =========================================================
   PUBLIC SCHOOLS
========================================================= */

app.get("/api/schools", async (req, res) => {
  try {
    const search = String(req.query.search || "").trim();
    const region = String(req.query.region || "").trim();
    const district = String(req.query.district || "").trim();

    const params = [];
    const conditions = [`LOWER(COALESCE(status,'active'))='active'`];

    if (search) {
      params.push(`%${search.toLowerCase()}%`);

      conditions.push(`
        (
          LOWER(name) LIKE $${params.length}
          OR LOWER(COALESCE(region,'')) LIKE $${params.length}
          OR LOWER(COALESCE(district,'')) LIKE $${params.length}
        )
      `);
    }

    if (region) {
      params.push(region.toLowerCase());

      conditions.push(
        `LOWER(COALESCE(region,''))=$${params.length}`
      );
    }

    if (district) {
      params.push(district.toLowerCase());

      conditions.push(
        `LOWER(COALESCE(district,''))=$${params.length}`
      );
    }

    const schools = await q(`
      SELECT *
      FROM schools
      WHERE ${conditions.join(" AND ")}
      ORDER BY name ASC
    `, params);

    res.json({
      success: true,
      schools
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.get("/api/schools/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "School ID si sahihi."
      });
    }

    const school = (await q(`
      SELECT *
      FROM schools
      WHERE id=$1
        AND LOWER(COALESCE(status,'active'))='active'
    `, [id]))[0];

    if (!school) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
      });
    }

    const customFields = await getSchoolCustomFields(id);

    const form = (await q(`
      SELECT
        id,
        school_id,
        file_name,
        mime_type,
        active,
        uploaded_at,
        updated_at
      FROM school_forms
      WHERE school_id=$1
        AND active=true
      ORDER BY id DESC
      LIMIT 1
    `, [id]))[0] || null;

    res.json({
      success: true,
      school,
      custom_fields: customFields,
      form
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.get("/api/schools/:id/custom-fields", async (req, res) => {
  try {
    const schoolId = Number(req.params.id);

    const fields = await getSchoolCustomFields(schoolId);

    res.json({
      success: true,
      fields
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* =========================================================
   SCHOOL FORM PDF - PUBLIC
========================================================= */

app.get("/api/schools/:id/form-pdf", async (req, res) => {
  try {
    const schoolId = Number(req.params.id);

    const form = (await q(`
      SELECT *
      FROM school_forms
      WHERE school_id=$1
        AND active=true
      ORDER BY id DESC
      LIMIT 1
    `, [schoolId]))[0];

    if (!form) {
      return res.status(404).json({
        success: false,
        message: "Shule hii bado haijaweka PDF ya fomu."
      });
    }

    const buffer = Buffer.from(form.file_data, "base64");

    res.setHeader(
      "Content-Type",
      form.mime_type || "application/pdf"
    );

    res.setHeader(
      "Content-Disposition",
      `inline; filename="${String(form.file_name).replace(/"/g, "")}"`
    );

    res.send(buffer);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* =========================================================
   APPLICATIONS
========================================================= */

app.post("/api/applications", async (req, res) => {
  const client = await pool.connect();

  try {
    const b = req.body || {};

    const schoolId = Number(b.school_id || b.schoolId);

    const studentName = String(
      b.student_name ||
      b.studentName ||
      b.applicant_name ||
      ""
    ).trim();

    const parentName = String(
      b.parent_name ||
      b.parentName ||
      ""
    ).trim();

    const parentPhone = String(
      b.parent_phone ||
      b.parentPhone ||
      b.phone ||
      ""
    ).trim();

    const parentEmail = String(
      b.parent_email ||
      b.parentEmail ||
      b.email ||
      ""
    ).trim();

    const gender = String(
      b.gender ||
      b.applicant_gender ||
      ""
    ).trim();

    const dateOfBirth =
      b.date_of_birth ||
      b.dateOfBirth ||
      b.applicant_date_of_birth ||
      null;

    const classLevel = String(
      b.class_level ||
      b.classLevel ||
      ""
    ).trim();

    const address = String(
      b.address ||
      ""
    ).trim();

    const customData =
      b.custom_data ||
      b.customData ||
      {};

    if (!schoolId || !studentName || !parentName || !parentPhone) {
      return res.status(400).json({
        success: false,
        message:
          "Jaza taarifa muhimu za mwanafunzi na mzazi."
      });
    }

    await client.query("BEGIN");

    const schoolResult = await client.query(`
      SELECT *
      FROM schools
      WHERE id=$1
        AND LOWER(COALESCE(status,'active'))='active'
      FOR UPDATE
    `, [schoolId]);

    const school = schoolResult.rows[0];

    if (!school) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        message: "Shule haipatikani au haipokei maombi."
      });
    }

    const customErrors = await validateCustomData(
      schoolId,
      customData
    );

    if (customErrors.length) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        success: false,
        message: customErrors.join(" ")
      });
    }

    let applicationNumber = generateApplicationNumber();

    while (
      (
        await client.query(
          `
          SELECT id
          FROM applications
          WHERE application_number=$1
          LIMIT 1
          `,
          [applicationNumber]
        )
      ).rows.length
    ) {
      applicationNumber = generateApplicationNumber();
    }

    const paymentReference = generatePaymentReference();

    const amount = Number(school.form_price || 0);

    const commissionRate = 0;
    const commissionAmount = amount * commissionRate;
    const schoolAmount = amount - commissionAmount;

    const applicationResult = await client.query(`
      INSERT INTO applications
      (
        application_number,
        school_id,
        applicant_name,
        applicant_gender,
        applicant_date_of_birth,
        parent_name,
        parent_phone,
        parent_email,
        address,
        status,
        payment_status,
        student_name,
        gender,
        date_of_birth,
        class_level,
        phone,
        email,
        custom_data
      )
      VALUES
      (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,
        'submitted',
        'pending',
        $3,$4,$5,$10,$7,$8,$11
      )
      RETURNING *
    `, [
      applicationNumber,
      schoolId,
      studentName,
      gender || null,
      dateOfBirth,
      parentName,
      parentPhone,
      parentEmail || null,
      address || null,
      classLevel || null,
      JSON.stringify(customData || {})
    ]);

    const application = applicationResult.rows[0];

    const paymentResult = await client.query(`
      INSERT INTO payments
      (
        application_id,
        payment_reference,
        amount,
        currency,
        status
      )
      VALUES
      ($1,$2,$3,'TZS','pending')
      RETURNING *
    `, [
      application.id,
      paymentReference,
      amount
    ]);

    await client.query("COMMIT");

    res.status(201).json({
      success: true,
      application,
      application_number: applicationNumber,
      payment_reference: paymentReference,
      amount,
      commission_amount: commissionAmount,
      school_amount: schoolAmount,
      payment: paymentResult.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  } finally {
    client.release();
  }
});

/* =========================================================
   APPLICATION LOOKUP
========================================================= */

app.get(
  "/api/application-by-number/:applicationNumber",
  async (req, res) => {
    try {
      const applicationNumber = String(
        req.params.applicationNumber || ""
      ).trim();

      const application = (await q(`
        SELECT
          a.*,
          s.name AS school_name,
          s.region AS school_region,
          s.district AS school_district,
          s.phone AS school_phone,
          s.email AS school_email,
          s.address AS school_address
        FROM applications a
        LEFT JOIN schools s ON s.id=a.school_id
        WHERE a.application_number=$1
      `, [applicationNumber]))[0];

      if (!application) {
        return res.status(404).json({
          success: false,
          message: "Namba ya maombi haijapatikana."
        });
      }

      const payments = await q(`
        SELECT *
        FROM payments
        WHERE application_id=$1
        ORDER BY id DESC
      `, [application.id]);

      res.json({
        success: true,
        application,
        payments
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   PAYMENT
========================================================= */

app.get("/api/payments/:reference", async (req, res) => {
  try {
    const reference = String(req.params.reference || "").trim();

    const payment = (await q(`
      SELECT
        p.*,
        a.application_number,
        a.school_id,
        a.student_name,
        a.parent_name,
        s.name AS school_name
      FROM payments p
      LEFT JOIN applications a ON a.id=p.application_id
      LEFT JOIN schools s ON s.id=a.school_id
      WHERE p.payment_reference=$1
    `, [reference]))[0];

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: "Malipo hayajapatikana."
      });
    }

    res.json({
      success: true,
      payment
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/*
  TEST / MANUAL CONFIRMATION
  Itabaki kwa testing mpaka gateway halisi iunganishwe.
*/

app.put("/api/payments/:reference/confirm", async (req, res) => {
  const client = await pool.connect();

  try {
    const reference = String(req.params.reference || "").trim();

    await client.query("BEGIN");

    const paymentResult = await client.query(`
      UPDATE payments
      SET
        status='paid',
        method=COALESCE($2,method),
        transaction_id=COALESCE($3,transaction_id),
        phone=COALESCE($4,phone),
        paid_at=NOW(),
        updated_at=NOW()
      WHERE payment_reference=$1
      RETURNING *
    `, [
      reference,
      req.body?.method || "manual",
      req.body?.transaction_id || null,
      req.body?.phone || null
    ]);

    const payment = paymentResult.rows[0];

    if (!payment) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        message: "Payment reference haijapatikana."
      });
    }

    await client.query(`
      UPDATE applications
      SET
        payment_status='paid',
        status=CASE
          WHEN status='submitted' THEN 'paid'
          ELSE status
        END,
        updated_at=NOW()
      WHERE id=$1
    `, [payment.application_id]);

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Malipo yamethibitishwa.",
      payment
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

/* =========================================================
   PAYMENT WEBHOOK
========================================================= */

app.post("/api/payments/webhook", async (req, res) => {
  const client = await pool.connect();

  try {
    const body = req.body || {};

    const reference = String(
      body.payment_reference ||
      body.reference ||
      body.order_id ||
      ""
    ).trim();

    const status = String(
      body.status ||
      body.payment_status ||
      ""
    ).trim().toLowerCase();

    if (!reference) {
      return res.status(400).json({
        success: false,
        message: "Payment reference haipo."
      });
    }

    const successfulStatuses = [
      "paid",
      "success",
      "successful",
      "completed",
      "complete"
    ];

    const isPaid = successfulStatuses.includes(status);

    await client.query("BEGIN");

    const payment = (
      await client.query(`
        UPDATE payments
        SET
          status=$2,
          transaction_id=COALESCE($3,transaction_id),
          phone=COALESCE($4,phone),
          method=COALESCE($5,method),
          paid_at=CASE
            WHEN $2='paid' THEN NOW()
            ELSE paid_at
          END,
          updated_at=NOW()
        WHERE payment_reference=$1
        RETURNING *
      `, [
        reference,
        isPaid ? "paid" : (status || "pending"),
        body.transaction_id || body.transactionId || null,
        body.phone || null,
        body.method || null
      ])
    ).rows[0];

    if (!payment) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        message: "Payment haijapatikana."
      });
    }

    if (isPaid) {
      await client.query(`
        UPDATE applications
        SET
          payment_status='paid',
          status=CASE
            WHEN status='submitted' THEN 'paid'
            ELSE status
          END,
          updated_at=NOW()
        WHERE id=$1
      `, [payment.application_id]);
    }

    await client.query("COMMIT");

    res.json({
      success: true,
      received: true
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

/* =========================================================
   SCHOOL ADMIN LOGIN
========================================================= */

app.post("/api/school-admin/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Weka email na password."
      });
    }

    const admin = (
      await q(`
        SELECT *
        FROM school_admins
        WHERE LOWER(email)=LOWER($1)
          AND active=true
      `, [email])
    )[0];

    if (!admin || admin.password_hash !== hashPassword(password)) {
      return res.status(401).json({
        success: false,
        message: "Email au password si sahihi."
      });
    }

    const token = generateToken();

    sessions.set(token, {
      role: "school_admin",
      adminId: admin.id,
      schoolId: admin.school_id,
      email: admin.email,
      createdAt: Date.now()
    });

    res.json({
      success: true,
      token,
      admin: {
        id: admin.id,
        full_name: admin.full_name,
        email: admin.email,
        school_id: admin.school_id
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.get("/api/school-admin/me", schoolAdmin, async (req, res) => {
  try {
    const admin = (
      await q(`
        SELECT
          sa.id,
          sa.full_name,
          sa.email,
          sa.active,
          sa.school_id,
          s.name AS school_name
        FROM school_admins sa
        LEFT JOIN schools s ON s.id=sa.school_id
        WHERE sa.id=$1
      `, [req.auth.adminId])
    )[0];

    if (!admin) {
      return res.status(404).json({
        success: false,
        message: "Admin wa shule hajapatikana."
      });
    }

    res.json({
      success: true,
      admin
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.post("/api/school-admin/logout", schoolAdmin, async (req, res) => {
  const token = getBearerToken(req);

  sessions.delete(token);

  res.json({
    success: true,
    message: "Umetoka kwenye mfumo."
  });
});

/* =========================================================
   SCHOOL ADMIN - SCHOOL
========================================================= */

app.get("/api/school-admin/school", schoolAdmin, async (req, res) => {
  try {
    const school = (
      await q(`
        SELECT *
        FROM schools
        WHERE id=$1
      `, [req.auth.schoolId])
    )[0];

    if (!school) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
      });
    }

    res.json({
      success: true,
      school
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.put("/api/school-admin/school", schoolAdmin, async (req, res) => {
  try {
    const b = req.body || {};

    const school = (
      await q(`
        UPDATE schools
        SET
          name=COALESCE(NULLIF($2,''),name),
          region=$3,
          district=$4,
          level=$5,
          form_price=$6,
          phone=$7,
          address=$8,
          email=$9,
          description=$10,
          logo_url=$11,
          website=$12,
          updated_at=NOW()
        WHERE id=$1
        RETURNING *
      `, [
        req.auth.schoolId,
        String(b.name || "").trim(),
        String(b.region || "").trim(),
        String(b.district || "").trim(),
        String(b.level || "").trim(),
        Number(b.form_price || b.formPrice || 0),
        String(b.phone || "").trim(),
        String(b.address || "").trim(),
        String(b.email || "").trim(),
        String(b.description || "").trim(),
        String(b.logo_url || b.logoUrl || "").trim(),
        String(b.website || "").trim()
      ])
    )[0];

    if (!school) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
      });
    }

    res.json({
      success: true,
      school
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.post(
  "/api/school-admin/school/publish",
  schoolAdmin,
  async (req, res) => {
    try {
      const school = (
        await q(`
          UPDATE schools
          SET status='active', updated_at=NOW()
          WHERE id=$1
          RETURNING *
        `, [req.auth.schoolId])
      )[0];

      res.json({
        success: true,
        message: "Shule imewekwa Live.",
        school
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.post(
  "/api/school-admin/school/unpublish",
  schoolAdmin,
  async (req, res) => {
    try {
      const school = (
        await q(`
          UPDATE schools
          SET status='inactive', updated_at=NOW()
          WHERE id=$1
          RETURNING *
        `, [req.auth.schoolId])
      )[0];

      res.json({
        success: true,
        message: "Shule imeondolewa Live.",
        school
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN - CUSTOM FIELDS
========================================================= */

app.get(
  "/api/school-admin/custom-fields",
  schoolAdmin,
  async (req, res) => {
    try {
      const fields = await q(`
        SELECT *
        FROM school_custom_fields
        WHERE school_id=$1
        ORDER BY sort_order ASC, id ASC
      `, [req.auth.schoolId]);

      res.json({
        success: true,
        fields
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.post(
  "/api/school-admin/custom-fields",
  schoolAdmin,
  async (req, res) => {
    try {
      const data = cleanFieldInput(req.body);

      if (!data.field_label) {
        return res.status(400).json({
          success: false,
          message: "Field label inahitajika."
        });
      }

      if (!data.field_name) {
        return res.status(400).json({
          success: false,
          message: "Field name inahitajika."
        });
      }

      const field = (
        await q(`
          INSERT INTO school_custom_fields
          (
            school_id,
            field_name,
            field_label,
            field_type,
            required,
            options,
            sort_order,
            active
          )
          VALUES
          ($1,$2,$3,$4,$5,$6::jsonb,
           COALESCE(
             (SELECT MAX(sort_order)+1
              FROM school_custom_fields
              WHERE school_id=$1),
             0
           ),
           true)
          RETURNING *
        `, [
          req.auth.schoolId,
          data.field_name,
          data.field_label,
          data.field_type,
          data.required,
          JSON.stringify(data.options)
        ])
      )[0];

      res.status(201).json({
        success: true,
        field
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN - APPLICATIONS
========================================================= */

app.get(
  "/api/school-admin/applications",
  schoolAdmin,
  async (req, res) => {
    try {
      const applications = await q(`
        SELECT
          a.*,
          s.name AS school_name
        FROM applications a
        LEFT JOIN schools s ON s.id=a.school_id
        WHERE a.school_id=$1
        ORDER BY a.id DESC
      `, [req.auth.schoolId]);

      res.json({
        success: true,
        applications
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.put(
  "/api/school-admin/applications/:id/status",
  schoolAdmin,
  async (req, res) => {
    try {
      const status = String(
        req.body.status || ""
      ).trim().toLowerCase();

      const allowed = [
        "submitted",
        "paid",
        "received",
        "under_review",
        "approved",
        "rejected",
        "completed"
      ];

      if (!allowed.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Status ya maombi si sahihi."
        });
      }

      const application = (
        await q(`
          UPDATE applications
          SET
            status=$1,
            updated_at=NOW()
          WHERE id=$2
            AND school_id=$3
          RETURNING *
        `, [
          status,
          Number(req.params.id),
          req.auth.schoolId
        ])
      )[0];

      if (!application) {
        return res.status(404).json({
          success: false,
          message: "Application haijapatikana."
        });
      }

      res.json({
        success: true,
        application
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN - PAYMENTS
========================================================= */

app.get(
  "/api/school-admin/payments",
  schoolAdmin,
  async (req, res) => {
    try {
      const payments = await q(`
        SELECT
          p.*,
          a.application_number,
          a.student_name,
          a.parent_name
        FROM payments p
        JOIN applications a
          ON a.id=p.application_id
        WHERE a.school_id=$1
        ORDER BY p.id DESC
      `, [req.auth.schoolId]);

      res.json({
        success: true,
        payments
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN - PDF FORM
========================================================= */

app.get(
  "/api/school-admin/form-pdf",
  schoolAdmin,
  async (req, res) => {
    try {
      const form = (
        await q(`
          SELECT
            id,
            school_id,
            file_name,
            mime_type,
            active,
            uploaded_at,
            updated_at
          FROM school_forms
          WHERE school_id=$1
            AND active=true
          ORDER BY id DESC
          LIMIT 1
        `, [req.auth.schoolId])
      )[0] || null;

      res.json({
        success: true,
        form
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.post(
  "/api/school-admin/form-pdf",
  schoolAdmin,
  async (req, res) => {
    try {
      const fileName = String(
        req.body.file_name ||
        req.body.fileName ||
        "school-form.pdf"
      ).trim();

      const mimeType = String(
        req.body.mime_type ||
        req.body.mimeType ||
        "application/pdf"
      ).trim();

      let fileData = String(
        req.body.file_data ||
        req.body.fileData ||
        ""
      ).trim();

      if (!fileData) {
        return res.status(400).json({
          success: false,
          message: "PDF haijatumwa."
        });
      }

      if (fileData.includes(",")) {
        fileData = fileData.split(",").pop();
      }

      const buffer = Buffer.from(fileData, "base64");

      if (buffer.length === 0) {
        return res.status(400).json({
          success: false,
          message: "PDF si sahihi."
        });
      }

      if (buffer.length > 10 * 1024 * 1024) {
        return res.status(400).json({
          success: false,
          message: "PDF imezidi 10MB."
        });
      }

      const isPdf =
        mimeType === "application/pdf" ||
        fileName.toLowerCase().endsWith(".pdf");

      if (!isPdf) {
        return res.status(400).json({
          success: false,
          message: "Mfumo unaruhusu PDF pekee."
        });
      }

      await q(`
        UPDATE school_forms
        SET
          active=false,
          updated_at=NOW()
        WHERE school_id=$1
      `, [req.auth.schoolId]);

      const form = (
        await q(`
          INSERT INTO school_forms
          (
            school_id,
            file_name,
            mime_type,
            file_data,
            active
          )
          VALUES
          ($1,$2,'application/pdf',$3,true)
          RETURNING
            id,
            school_id,
            file_name,
            mime_type,
            active,
            uploaded_at,
            updated_at
        `, [
          req.auth.schoolId,
          fileName,
          buffer.toString("base64")
        ])
      )[0];

      res.status(201).json({
        success: true,
        message: "PDF ya fomu imepakiwa.",
        form
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

app.delete(
  "/api/school-admin/form-pdf",
  schoolAdmin,
  async (req, res) => {
    try {
      await q(`
        UPDATE school_forms
        SET
          active=false,
          updated_at=NOW()
        WHERE school_id=$1
      `, [req.auth.schoolId]);

      res.json({
        success: true,
        message: "PDF imeondolewa."
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN LOGIN
========================================================= */

app.post("/api/admin/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const adminEmail =
      process.env.ADMIN_EMAIL ||
      "admin@shuleportal.co.tz";

    const adminPassword =
      process.env.ADMIN_PASSWORD ||
      "Admin@123";

    if (
      email !== adminEmail.toLowerCase() ||
      password !== adminPassword
    ) {
      return res.status(401).json({
        success: false,
        message: "Email au password si sahihi."
      });
    }

    const token = generateToken();

    sessions.set(token, {
      role: "main_admin",
      email,
      createdAt: Date.now()
    });

    res.json({
      success: true,
      token,
      admin: {
        email
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.get("/api/admin/me", mainAdmin, async (req, res) => {
  res.json({
    success: true,
    admin: {
      email: req.auth.email
    }
  });
});

app.post("/api/admin/logout", mainAdmin, async (req, res) => {
  const token = getBearerToken(req);

  sessions.delete(token);

  res.json({
    success: true,
    message: "Umetoka kwenye Admin Mkuu."
  });
});

/* =========================================================
   MAIN ADMIN - SCHOOLS
========================================================= */

app.get("/api/admin/schools", mainAdmin, async (req, res) => {
  try {
    const schools = await q(`
      SELECT *
      FROM schools
      ORDER BY id DESC
    `);

    res.json({
      success: true,
      schools
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.post("/api/admin/schools", mainAdmin, async (req, res) => {
  try {
    const b = req.body || {};

    const name = String(b.name || "").trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Jina la shule linahitajika."
      });
    }

    const school = (
      await q(`
        INSERT INTO schools
        (
          name,
          region,
          district,
          level,
          form_price,
          phone,
          address,
          email,
          description,
          logo_url,
          website,
          status
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        RETURNING *
      `, [
        name,
        String(b.region || "").trim(),
        String(b.district || "").trim(),
        String(b.level || "").trim(),
        Number(b.form_price || b.formPrice || 0),
        String(b.phone || "").trim(),
        String(b.address || "").trim(),
        String(b.email || "").trim(),
        String(b.description || "").trim(),
        String(b.logo_url || b.logoUrl || "").trim(),
        String(b.website || "").trim(),
        String(b.status || "active").trim()
      ])
    )[0];

    res.status(201).json({
      success: true,
      school
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.put("/api/admin/schools/:id", mainAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const b = req.body || {};

    const school = (
      await q(`
        UPDATE schools
        SET
          name=$2,
          region=$3,
          district=$4,
          level=$5,
          form_price=$6,
          phone=$7,
          address=$8,
          email=$9,
          description=$10,
          logo_url=$11,
          website=$12,
          status=$13,
          updated_at=NOW()
        WHERE id=$1
        RETURNING *
      `, [
        id,
        String(b.name || "").trim(),
        String(b.region || "").trim(),
        String(b.district || "").trim(),
        String(b.level || "").trim(),
        Number(b.form_price || b.formPrice || 0),
        String(b.phone || "").trim(),
        String(b.address || "").trim(),
        String(b.email || "").trim(),
        String(b.description || "").trim(),
        String(b.logo_url || b.logoUrl || "").trim(),
        String(b.website || "").trim(),
        String(b.status || "active").trim()
      ])
    )[0];

    if (!school) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
      });
    }

    res.json({
      success: true,
      school
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.delete("/api/admin/schools/:id", mainAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    const school = (
      await q(`
        UPDATE schools
        SET
          status='inactive',
          updated_at=NOW()
        WHERE id=$1
        RETURNING *
      `, [id])
    )[0];

    if (!school) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana."
      });
    }

    res.json({
      success: true,
      message: "Shule imeondolewa kwenye Live.",
      school
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/* =========================================================
   MAIN ADMIN - CUSTOM FIELDS
========================================================= */

app.get(
  "/api/admin/schools/:schoolId/custom-fields",
  mainAdmin,
  async (req, res) => {
    try {
      const schoolId = Number(req.params.schoolId);

      const fields = await q(`
        SELECT *
        FROM school_custom_fields
        WHERE school_id=$1
        ORDER BY sort_order ASC, id ASC
      `, [schoolId]);

      res.json({
        success: true,
        fields
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.post(
  "/api/admin/schools/:schoolId/custom-fields",
  mainAdmin,
  async (req, res) => {
    try {
      const schoolId = Number(req.params.schoolId);

      const school = (
        await q(
          "SELECT id FROM schools WHERE id=$1",
          [schoolId]
        )
      )[0];

      if (!school) {
        return res.status(404).json({
          success: false,
          message: "Shule haijapatikana."
        });
      }

      const data = cleanFieldInput(req.body);

      if (!data.field_label || !data.field_name) {
        return res.status(400).json({
          success: false,
          message: "Field name na label vinahitajika."
        });
      }

      const field = (
        await q(`
          INSERT INTO school_custom_fields
          (
            school_id,
            field_name,
            field_label,
            field_type,
            required,
            options,
            sort_order,
            active
          )
          VALUES
          ($1,$2,$3,$4,$5,$6::jsonb,
           COALESCE(
             (SELECT MAX(sort_order)+1
              FROM school_custom_fields
              WHERE school_id=$1),
             0
           ),
           true)
          RETURNING *
        `, [
          schoolId,
          data.field_name,
          data.field_label,
          data.field_type,
          data.required,
          JSON.stringify(data.options)
        ])
      )[0];

      res.status(201).json({
        success: true,
        field
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.put(
  "/api/admin/schools/:schoolId/custom-fields/:fieldId",
  mainAdmin,
  async (req, res) => {
    try {
      const schoolId = Number(req.params.schoolId);
      const fieldId = Number(req.params.fieldId);

      const data = cleanFieldInput(req.body);

      const field = (
        await q(`
          UPDATE school_custom_fields
          SET
            field_name=$1,
            field_label=$2,
            field_type=$3,
            required=$4,
            options=$5::jsonb,
            updated_at=NOW()
          WHERE id=$6
            AND school_id=$7
          RETURNING *
        `, [
          data.field_name,
          data.field_label,
          data.field_type,
          data.required,
          JSON.stringify(data.options),
          fieldId,
          schoolId
        ])
      )[0];

      if (!field) {
        return res.status(404).json({
          success: false,
          message: "Field haijapatikana."
        });
      }

      res.json({
        success: true,
        field
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.delete(
  "/api/admin/schools/:schoolId/custom-fields/:fieldId",
  mainAdmin,
  async (req, res) => {
    try {
      const schoolId = Number(req.params.schoolId);
      const fieldId = Number(req.params.fieldId);

      const field = (
        await q(`
          UPDATE school_custom_fields
          SET
            active=false,
            updated_at=NOW()
          WHERE id=$1
            AND school_id=$2
          RETURNING *
        `, [fieldId, schoolId])
      )[0];

      if (!field) {
        return res.status(404).json({
          success: false,
          message: "Field haijapatikana."
        });
      }

      res.json({
        success: true,
        message: "Field imeondolewa.",
        field
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN - DASHBOARD STATS
========================================================= */

app.get(
  "/api/admin/dashboard-stats",
  mainAdmin,
  async (req, res) => {
    try {
      const stats = (
        await q(`
          SELECT
            (SELECT COUNT(*) FROM schools) AS total_schools,
            (SELECT COUNT(*) FROM schools
             WHERE LOWER(COALESCE(status,'active'))='active')
              AS active_schools,
            (SELECT COUNT(*) FROM applications) AS total_applications,
            (SELECT COUNT(*) FROM applications
             WHERE LOWER(COALESCE(payment_status,''))='paid')
              AS paid_applications,
            (SELECT COUNT(*) FROM payments
             WHERE LOWER(COALESCE(status,''))='paid')
              AS paid_payments,
            (SELECT COALESCE(SUM(amount),0)
             FROM payments
             WHERE LOWER(COALESCE(status,''))='paid')
              AS total_revenue,
            (SELECT COUNT(*) FROM school_admins) AS total_admins,
            (SELECT COUNT(*) FROM school_admins
             WHERE active=true)
              AS active_admins
        `)
      )[0];

      res.json({
        success: true,
        stats
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN - SCHOOL ADMINS
   COMPLETE CRUD
========================================================= */

/*
  GET LIST
  Supports:
  ?search=
  ?school_id=
  ?status=active|inactive
*/

app.get(
  "/api/admin/school-admins",
  mainAdmin,
  async (req, res) => {
    try {
      const search = String(
        req.query.search || ""
      ).trim();

      const schoolId = Number(
        req.query.school_id || 0
      );

      const status = String(
        req.query.status || ""
      ).trim().toLowerCase();

      const params = [];
      const conditions = [];

      if (search) {
        params.push(`%${search.toLowerCase()}%`);

        conditions.push(`
          (
            LOWER(COALESCE(sa.full_name,'')) LIKE $${params.length}
            OR LOWER(COALESCE(sa.email,'')) LIKE $${params.length}
            OR LOWER(COALESCE(s.name,'')) LIKE $${params.length}
          )
        `);
      }

      if (schoolId) {
        params.push(schoolId);

        conditions.push(
          `sa.school_id=$${params.length}`
        );
      }

      if (status === "active") {
        conditions.push("sa.active=true");
      }

      if (status === "inactive") {
        conditions.push("sa.active=false");
      }

      const where =
        conditions.length
          ? `WHERE ${conditions.join(" AND ")}`
          : "";

      const admins = await q(`
        SELECT
          sa.id,
          sa.school_id,
          sa.full_name,
          sa.email,
          sa.active,
          sa.created_at,
          sa.updated_at,
          s.name AS school_name,
          s.region AS school_region,
          s.district AS school_district
        FROM school_admins sa
        LEFT JOIN schools s
          ON s.id=sa.school_id
        ${where}
        ORDER BY sa.id DESC
      `, params);

      const totalAdmins = admins.length;

      const activeAdmins = admins.filter(
        a => a.active === true
      ).length;

      const inactiveAdmins = admins.filter(
        a => a.active === false
      ).length;

      res.json({
        success: true,
        admins,
        total_admins: totalAdmins,
        active_admins: activeAdmins,
        inactive_admins: inactiveAdmins
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

/* ---------------------------------------------------------
   GET SINGLE ADMIN
--------------------------------------------------------- */

app.get(
  "/api/admin/school-admins/:id",
  mainAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!id) {
        return res.status(400).json({
          success: false,
          message: "Admin ID si sahihi."
        });
      }

      const admin = (
        await q(`
          SELECT
            sa.id,
            sa.school_id,
            sa.full_name,
            sa.email,
            sa.active,
            sa.created_at,
            sa.updated_at,
            s.name AS school_name,
            s.region AS school_region,
            s.district AS school_district
          FROM school_admins sa
          LEFT JOIN schools s
            ON s.id=sa.school_id
          WHERE sa.id=$1
        `, [id])
      )[0];

      if (!admin) {
        return res.status(404).json({
          success: false,
          message: "Admin wa shule hajapatikana."
        });
      }

      res.json({
        success: true,
        admin
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* ---------------------------------------------------------
   CREATE ADMIN
--------------------------------------------------------- */

app.post(
  "/api/admin/school-admins",
  mainAdmin,
  async (req, res) => {
    try {
      const b = req.body || {};

      const fullName = String(
        b.full_name || ""
      ).trim();

      const email = String(
        b.email || ""
      ).trim().toLowerCase();

      const password = String(
        b.password || ""
      );

      const schoolId = Number(
        b.school_id
      );

      const status = String(
        b.status || "active"
      ).trim().toLowerCase();

      if (
        !fullName ||
        !email ||
        !password ||
        !schoolId
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Jaza taarifa zote za Admin wa Shule."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password lazima iwe na angalau characters 6."
        });
      }

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
      ) {
        return res.status(400).json({
          success: false,
          message: "Email si sahihi."
        });
      }

      const school = (
        await q(`
          SELECT id,name
          FROM schools
          WHERE id=$1
        `, [schoolId])
      )[0];

      if (!school) {
        return res.status(404).json({
          success: false,
          message: "Shule uliyochagua haipo."
        });
      }

      const existing = (
        await q(`
          SELECT id
          FROM school_admins
          WHERE LOWER(email)=LOWER($1)
          LIMIT 1
        `, [email])
      )[0];

      if (existing) {
        return res.status(409).json({
          success: false,
          message:
            "Email hiyo tayari imetumika na Admin mwingine."
        });
      }

      const active = status !== "inactive";

      const admin = (
        await q(`
          INSERT INTO school_admins
          (
            school_id,
            full_name,
            email,
            password_hash,
            active,
            created_at,
            updated_at
          )
          VALUES
          ($1,$2,$3,$4,$5,NOW(),NOW())
          RETURNING
            id,
            school_id,
            full_name,
            email,
            active,
            created_at,
            updated_at
        `, [
          schoolId,
          fullName,
          email,
          hashPassword(password),
          active
        ])
      )[0];

      res.status(201).json({
        success: true,
        message:
          "Admin wa Shule ameongezwa kikamilifu.",
        admin
      });
    } catch (error) {
      console.error(error);

      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          message:
            "Email hiyo tayari imetumika."
        });
      }

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* ---------------------------------------------------------
   UPDATE ADMIN
--------------------------------------------------------- */

app.put(
  "/api/admin/school-admins/:id",
  mainAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);
      const b = req.body || {};

      if (!id) {
        return res.status(400).json({
          success: false,
          message: "Admin ID si sahihi."
        });
      }

      const fullName = String(
        b.full_name || ""
      ).trim();

      const email = String(
        b.email || ""
      ).trim().toLowerCase();

      const schoolId = Number(
        b.school_id
      );

      const status = String(
        b.status || "active"
      ).trim().toLowerCase();

      const password =
        b.password === undefined ||
        b.password === null
          ? ""
          : String(b.password);

      if (!fullName || !email || !schoolId) {
        return res.status(400).json({
          success: false,
          message:
            "Jaza jina, email na shule."
        });
      }

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
      ) {
        return res.status(400).json({
          success: false,
          message: "Email si sahihi."
        });
      }

      if (
        password &&
        password.length < 6
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Password mpya lazima iwe na angalau characters 6."
        });
      }

      const school = (
        await q(`
          SELECT id
          FROM schools
          WHERE id=$1
        `, [schoolId])
      )[0];

      if (!school) {
        return res.status(404).json({
          success: false,
          message: "Shule haijapatikana."
        });
      }

      const duplicate = (
        await q(`
          SELECT id
          FROM school_admins
          WHERE LOWER(email)=LOWER($1)
            AND id<>$2
          LIMIT 1
        `, [email, id])
      )[0];

      if (duplicate) {
        return res.status(409).json({
          success: false,
          message:
            "Email hiyo tayari imetumika na Admin mwingine."
        });
      }

      const active =
        status !== "inactive";

      let admin;

      if (password) {
        admin = (
          await q(`
            UPDATE school_admins
            SET
              school_id=$1,
              full_name=$2,
              email=$3,
              password_hash=$4,
              active=$5,
              updated_at=NOW()
            WHERE id=$6
            RETURNING
              id,
              school_id,
              full_name,
              email,
              active,
              created_at,
              updated_at
          `, [
            schoolId,
            fullName,
            email,
            hashPassword(password),
            active,
            id
          ])
        )[0];
      } else {
        admin = (
          await q(`
            UPDATE school_admins
            SET
              school_id=$1,
              full_name=$2,
              email=$3,
              active=$4,
              updated_at=NOW()
            WHERE id=$5
            RETURNING
              id,
              school_id,
              full_name,
              email,
              active,
              created_at,
              updated_at
          `, [
            schoolId,
            fullName,
            email,
            active,
            id
          ])
        )[0];
      }

      if (!admin) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hajapatikana."
        });
      }

      /*
        Ikiwa admin amehamishwa shule au amefanywa inactive,
        tunafuta session zake za sasa.
      */

      for (const [token, session] of sessions.entries()) {
        if (
          session.role === "school_admin" &&
          Number(session.adminId) === id
        ) {
          sessions.delete(token);
        }
      }

      res.json({
        success: true,
        message:
          "Taarifa za Admin wa Shule zimebadilishwa.",
        admin
      });
    } catch (error) {
      console.error(error);

      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          message:
            "Email hiyo tayari imetumika."
        });
      }

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* ---------------------------------------------------------
   ACTIVATE / DEACTIVATE
--------------------------------------------------------- */

app.put(
  "/api/admin/school-admins/:id/status",
  mainAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const requestedStatus = String(
        req.body.status || ""
      ).trim().toLowerCase();

      if (
        !["active", "inactive"].includes(
          requestedStatus
        )
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Status lazima iwe active au inactive."
        });
      }

      const active =
        requestedStatus === "active";

      const admin = (
        await q(`
          UPDATE school_admins
          SET
            active=$1,
            updated_at=NOW()
          WHERE id=$2
          RETURNING
            id,
            school_id,
            full_name,
            email,
            active,
            created_at,
            updated_at
        `, [active, id])
      )[0];

      if (!admin) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hajapatikana."
        });
      }

      if (!active) {
        for (const [token, session] of sessions.entries()) {
          if (
            session.role === "school_admin" &&
            Number(session.adminId) === id
          ) {
            sessions.delete(token);
          }
        }
      }

      res.json({
        success: true,
        message: active
          ? "Admin wa shule ame-activate."
          : "Admin wa shule ame-deactivate.",
        admin
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* ---------------------------------------------------------
   RESET PASSWORD
--------------------------------------------------------- */

app.put(
  "/api/admin/school-admins/:id/reset-password",
  mainAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const password = String(
        req.body.password || ""
      );

      if (!password) {
        return res.status(400).json({
          success: false,
          message:
            "Weka password mpya."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password lazima iwe na angalau characters 6."
        });
      }

      const admin = (
        await q(`
          UPDATE school_admins
          SET
            password_hash=$1,
            updated_at=NOW()
          WHERE id=$2
          RETURNING
            id,
            school_id,
            full_name,
            email,
            active,
            updated_at
        `, [
          hashPassword(password),
          id
        ])
      )[0];

      if (!admin) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hajapatikana."
        });
      }

      /*
        Force re-login after password reset.
      */

      for (const [token, session] of sessions.entries()) {
        if (
          session.role === "school_admin" &&
          Number(session.adminId) === id
        ) {
          sessions.delete(token);
        }
      }

      res.json({
        success: true,
        message:
          "Password imebadilishwa. Admin ataingia kwa password mpya.",
        admin
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* ---------------------------------------------------------
   DELETE ADMIN
--------------------------------------------------------- */

app.delete(
  "/api/admin/school-admins/:id",
  mainAdmin,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      const admin = (
        await q(`
          DELETE FROM school_admins
          WHERE id=$1
          RETURNING
            id,
            school_id,
            full_name,
            email
        `, [id])
      )[0];

      if (!admin) {
        return res.status(404).json({
          success: false,
          message:
            "Admin wa shule hajapatikana."
        });
      }

      for (const [token, session] of sessions.entries()) {
        if (
          session.role === "school_admin" &&
          Number(session.adminId) === id
        ) {
          sessions.delete(token);
        }
      }

      res.json({
        success: true,
        message:
          "Admin wa shule amefutwa kikamilifu.",
        admin
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      success: false,
      message: "API endpoint haijapatikana."
    });
  }

  res.status(404).send("Page haijapatikana.");
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    success: false,
    message: "Server error.",
    error:
      process.env.NODE_ENV === "production"
        ? undefined
        : err.message
  });
});

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await initDatabase();

    await pool.query("SELECT NOW()");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Shule Portal Tanzania running on port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Server failed to start:",
      error
    );

    process.exit(1);
  }
}

startServer();