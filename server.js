"use strict";

const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

// ======================================================
// 1. DATABASE
// ======================================================

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL haijawekwa kwenye mazingira ya server.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

async function query(sql, params = []) {
  return pool.query(sql, params);
}

function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}

function applicationNumber() {
  const date = new Date();
  const year = date.getFullYear();
  const random = crypto.randomBytes(6).toString("hex").toUpperCase();

  return `SPT-${year}-${random}`;
}

function paymentReference() {
  return `PAY-${Date.now()}-${crypto.randomBytes(4)
    .toString("hex")
    .toUpperCase()}`;
}

function asyncHandler(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

// ======================================================
// 2. DATABASE TABLES
// ======================================================

async function initializeDatabase() {
  await query(`
    CREATE TABLE IF NOT EXISTS schools (
      id SERIAL PRIMARY KEY,
      name VARCHAR(250) NOT NULL,
      region VARCHAR(150),
      district VARCHAR(150),
      address TEXT,
      phone VARCHAR(50),
      email VARCHAR(250),
      description TEXT,
      education_level VARCHAR(150),
      status VARCHAR(30) NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(200) NOT NULL,
      email VARCHAR(250) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role VARCHAR(30) NOT NULL DEFAULT 'school_admin',
      school_id INTEGER REFERENCES schools(id) ON DELETE SET NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS school_forms (
      id SERIAL PRIMARY KEY,
      school_id INTEGER NOT NULL
        REFERENCES schools(id) ON DELETE CASCADE,
      title VARCHAR(250) NOT NULL,
      description TEXT,
      price NUMERIC(12,2) NOT NULL DEFAULT 0,
      academic_year VARCHAR(20),
      pdf_data BYTEA,
      pdf_filename VARCHAR(250),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS applications (
      id SERIAL PRIMARY KEY,
      application_number VARCHAR(100) NOT NULL UNIQUE,
      school_id INTEGER NOT NULL
        REFERENCES schools(id) ON DELETE RESTRICT,
      form_id INTEGER NOT NULL
        REFERENCES school_forms(id) ON DELETE RESTRICT,
      applicant_name VARCHAR(250) NOT NULL,
      applicant_email VARCHAR(250),
      applicant_phone VARCHAR(60),
      applicant_details JSONB NOT NULL DEFAULT '{}'::jsonb,
      amount NUMERIC(12,2) NOT NULL,
      status VARCHAR(40) NOT NULL DEFAULT 'PENDING_PAYMENT',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      reference VARCHAR(120) NOT NULL UNIQUE,
      application_id INTEGER NOT NULL
        REFERENCES applications(id) ON DELETE RESTRICT,
      amount NUMERIC(12,2) NOT NULL,
      method VARCHAR(60) NOT NULL DEFAULT 'LIPA_NAMBA',
      transaction_id VARCHAR(200),
      status VARCHAR(30) NOT NULL DEFAULT 'PENDING',
      paid_at TIMESTAMPTZ,
      verified_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      verification_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      token_hash VARCHAR(128) PRIMARY KEY,
      user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS idx_schools_region
    ON schools(region)
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS idx_forms_school
    ON school_forms(school_id)
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS idx_applications_number
    ON applications(application_number)
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS idx_payments_application
    ON payments(application_id)
  `);

  await query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_expiry
    ON user_sessions(expires_at)
  `);

  // Create the main administrator only when credentials
  // have been supplied through environment variables.
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (adminEmail && adminPassword) {
    const existing = await query(
      "SELECT id FROM users WHERE LOWER(email) = LOWER($1)",
      [adminEmail]
    );

    if (existing.rowCount === 0) {
      const passwordHash = await bcrypt.hash(adminPassword, 12);

      await query(
        `INSERT INTO users (name, email, password_hash, role)
         VALUES ($1, $2, $3, 'super_admin')`,
        ["Main Administrator", adminEmail, passwordHash]
      );

      console.log("Akaunti ya admin mkuu imeundwa.");
    }
  }

  console.log("PostgreSQL database iko tayari.");
}

// ======================================================
// 3. AUTHENTICATION
// ======================================================

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function createSession(userId) {
  const token = randomToken();
  const tokenHash = hashToken(token);

  await query(
    `INSERT INTO user_sessions (token_hash, user_id, expires_at)
     VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
    [tokenHash, userId]
  );

  return token;
}

async function authenticate(req, res, next) {
  try {
    const authorization = req.headers.authorization || "";
    const bearerToken = authorization.startsWith("Bearer ")
      ? authorization.slice(7).trim()
      : "";

    const cookieToken = req.headers.cookie
      ? req.headers.cookie
          .split(";")
          .map((item) => item.trim())
          .find((item) => item.startsWith("spt_session="))
          ?.slice("spt_session=".length)
      : "";

    const token = bearerToken || cookieToken;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Tafadhali ingia kwanza.",
      });
    }

    const result = await query(
      `SELECT
          u.id,
          u.name,
          u.email,
          u.role,
          u.school_id,
          u.active
       FROM user_sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1
         AND s.expires_at > NOW()`,
      [hashToken(token)]
    );

    if (result.rowCount === 0 || !result.rows[0].active) {
      return res.status(401).json({
        success: false,
        message: "Session imeisha au akaunti haipo hai.",
      });
    }

    req.user = result.rows[0];
    req.sessionTokenHash = hashToken(token);

    next();
  } catch (error) {
    next(error);
  }
}

function requireSuperAdmin(req, res, next) {
  if (req.user.role !== "super_admin") {
    return res.status(403).json({
      success: false,
      message: "Unahitaji ruhusa ya admin mkuu.",
    });
  }

  next();
}

function requireSchoolAccess(req, res, next) {
  if (req.user.role === "super_admin") {
    return next();
  }

  const requestedSchoolId = Number(
    req.params.schoolId ||
      req.body.school_id ||
      req.query.school_id ||
      0
  );

  if (
    req.user.role !== "school_admin" ||
    !req.user.school_id ||
    (requestedSchoolId &&
      requestedSchoolId !== Number(req.user.school_id))
  ) {
    return res.status(403).json({
      success: false,
      message: "Huna ruhusa ya kusimamia shule hii.",
    });
  }

  next();
}

// ======================================================
// 4. LOGIN AND LOGOUT
// ======================================================

app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
    const email = String(req.body.email || "").trim();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Weka email na password.",
      });
    }

    const result = await query(
      `SELECT id, name, email, password_hash, role, school_id, active
       FROM users
       WHERE LOWER(email) = LOWER($1)
       LIMIT 1`,
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        success: false,
        message: "Email au password si sahihi.",
      });
    }

    const user = result.rows[0];

    if (!user.active) {
      return res.status(403).json({
        success: false,
        message: "Akaunti yako imesimamishwa.",
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Email au password si sahihi.",
      });
    }

    const token = await createSession(user.id);

    res.setHeader(
      "Set-Cookie",
      `spt_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
    );

    res.json({
      success: true,
      message: "Umeingia kikamilifu.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        school_id: user.school_id,
      },
      redirect:
        user.role === "super_admin"
          ? "/admin.html"
          : "/school-admin.html",
    });
  })
);

app.get(
  "/api/auth/me",
  authenticate,
  asyncHandler(async (req, res) => {
    res.json({
      success: true,
      user: req.user,
    });
  })
);

app.post(
  "/api/auth/logout",
  authenticate,
  asyncHandler(async (req, res) => {
    await query(
      "DELETE FROM user_sessions WHERE token_hash = $1",
      [req.sessionTokenHash]
    );

    res.setHeader(
      "Set-Cookie",
      "spt_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
    );

    res.json({
      success: true,
      message: "Umetoka kwenye mfumo.",
    });
  })
);

// ======================================================
// 5. PUBLIC SCHOOL LIST
// ======================================================

app.get(
  "/api/schools",
  asyncHandler(async (req, res) => {
    const search = String(req.query.search || "").trim();
    const region = String(req.query.region || "").trim();
    const district = String(req.query.district || "").trim();

    const result = await query(
      `SELECT
          s.id,
          s.name,
          s.region,
          s.district,
          s.address,
          s.phone,
          s.email,
          s.description,
          s.education_level,
          s.created_at,
          COUNT(f.id)::int AS forms_count
       FROM schools s
       LEFT JOIN school_forms f
         ON f.school_id = s.id AND f.active = TRUE
       WHERE s.status = 'active'
         AND (
           $1 = ''
           OR s.name ILIKE '%' || $1 || '%'
           OR s.description ILIKE '%' || $1 || '%'
         )
         AND ($2 = '' OR s.region ILIKE '%' || $2 || '%')
         AND ($3 = '' OR s.district ILIKE '%' || $3 || '%')
       GROUP BY s.id
       ORDER BY s.name ASC
       LIMIT 200`,
      [search, region, district]
    );

    res.json({
      success: true,
      schools: result.rows,
    });
  })
);

app.get(
  "/api/schools/:id",
  asyncHandler(async (req, res) => {
    const schoolId = Number(req.params.id);

    if (!Number.isInteger(schoolId) || schoolId < 1) {
      return res.status(400).json({
        success: false,
        message: "Namba ya shule si sahihi.",
      });
    }

    const result = await query(
      `SELECT id, name, region, district, address, phone, email,
              description, education_level, status, created_at
       FROM schools
       WHERE id = $1 AND status = 'active'`,
      [schoolId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana.",
      });
    }

    const forms = await query(
      `SELECT id, school_id, title, description, price, academic_year
       FROM school_forms
       WHERE school_id = $1 AND active = TRUE
       ORDER BY id DESC`,
      [schoolId]
    );

    res.json({
      success: true,
      school: result.rows[0],
      forms: forms.rows,
    });
  })
);

// ======================================================
// 6. SCHOOL FORMS
// ======================================================

// PDF files are held in PostgreSQL BYTEA storage.
// This avoids relying on temporary Railway local storage.

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 15 * 1024 * 1024,
  },
  fileFilter(req, file, cb) {
    const isPdf =
      file.mimetype === "application/pdf" ||
      file.originalname.toLowerCase().endsWith(".pdf");

    if (!isPdf) {
      return cb(new Error("Tafadhali pakia faili la PDF pekee."));
    }

    cb(null, true);
  },
});

app.get(
  "/api/forms/:id",
  asyncHandler(async (req, res) => {
    const result = await query(
      `SELECT f.id, f.school_id, f.title, f.description,
              f.price, f.academic_year, f.pdf_filename,
              s.name AS school_name
       FROM school_forms f
       JOIN schools s ON s.id = f.school_id
       WHERE f.id = $1 AND f.active = TRUE
         AND s.status = 'active'`,
      [Number(req.params.id)]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Fomu haijapatikana.",
      });
    }

    res.json({
      success: true,
      form: result.rows[0],
    });
  })
);

app.get(
  "/api/forms/:id/download",
  asyncHandler(async (req, res) => {
    const result = await query(
      `SELECT f.pdf_data, f.pdf_filename, f.title
       FROM school_forms f
       JOIN schools s ON s.id = f.school_id
       WHERE f.id = $1
         AND f.active = TRUE
         AND s.status = 'active'`,
      [Number(req.params.id)]
    );

    if (result.rowCount === 0 || !result.rows[0].pdf_data) {
      return res.status(404).json({
        success: false,
        message: "PDF ya fomu haijapakiwa.",
      });
    }

    const form = result.rows[0];
    const filename = (
      form.pdf_filename ||
      `${form.title || "fomu-ya-shule"}.pdf`
    ).replace(/[^a-zA-Z0-9._-]/g, "_");

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );

    res.send(form.pdf_data);
  })
);

// ======================================================
// 7. CREATE APPLICATION
// ======================================================

app.post(
  "/api/applications",
  asyncHandler(async (req, res) => {
    const formId = Number(req.body.form_id);
    const applicantName = String(
      req.body.applicant_name || req.body.name || ""
    ).trim();
    const applicantEmail = String(
      req.body.applicant_email || req.body.email || ""
    ).trim();
    const applicantPhone = String(
      req.body.applicant_phone || req.body.phone || ""
    ).trim();

    if (!Number.isInteger(formId) || formId < 1) {
      return res.status(400).json({
        success: false,
        message: "Chagua fomu sahihi.",
      });
    }

    if (applicantName.length < 2) {
      return res.status(400).json({
        success: false,
        message: "Weka jina la mwombaji.",
      });
    }

    const formResult = await query(
      `SELECT f.id, f.school_id, f.price, f.title,
              s.name AS school_name
       FROM school_forms f
       JOIN schools s ON s.id = f.school_id
       WHERE f.id = $1
         AND f.active = TRUE
         AND s.status = 'active'`,
      [formId]
    );

    if (formResult.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Fomu haipatikani kwa sasa.",
      });
    }

    const form = formResult.rows[0];
    const amount = Number(form.price);

    if (!Number.isFinite(amount) || amount < 0) {
      return res.status(400).json({
        success: false,
        message: "Bei ya fomu si sahihi.",
      });
    }

    const appNumber = applicationNumber();
    const payReference = paymentReference();

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const applicationResult = await client.query(
        `INSERT INTO applications (
            application_number,
            school_id,
            form_id,
            applicant_name,
            applicant_email,
            applicant_phone,
            applicant_details,
            amount,
            status
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
         RETURNING id, application_number, school_id, form_id,
                   applicant_name, applicant_email, applicant_phone,
                   amount, status, created_at`,
        [
          appNumber,
          form.school_id,
          form.id,
          applicantName,
          applicantEmail || null,
          applicantPhone || null,
          JSON.stringify(req.body.details || {}),
          amount,
          amount === 0 ? "PAID" : "PENDING_PAYMENT",
        ]
      );

      const application = applicationResult.rows[0];

      const paymentResult = await client.query(
        `INSERT INTO payments (
            reference,
            application_id,
            amount,
            method,
            status,
            paid_at
         )
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, reference, amount, method, status, created_at`,
        [
          payReference,
          application.id,
          amount,
          "LIPA_NAMBA",
          amount === 0 ? "PAID" : "PENDING",
          amount === 0 ? new Date() : null,
        ]
      );

      await client.query("COMMIT");

      res.status(201).json({
        success: true,
        message: "Ombi limeundwa.",
        application,
        payment: paymentResult.rows[0],
        school: {
          id: form.school_id,
          name: form.school_name,
        },
        payment_instructions:
          amount > 0
            ? "Lipa kwa kutumia maelekezo rasmi ya Lipa Namba ya kampuni. Hifadhi uthibitisho wa malipo na reference ya malipo."
            : "Fomu hii haina malipo.",
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  })
);

// ======================================================
// 8. CHECK APPLICATION STATUS
// ======================================================

app.get(
  "/api/applications/:applicationNumber",
  asyncHandler(async (req, res) => {
    const number = String(req.params.applicationNumber || "").trim();

    const result = await query(
      `SELECT
          a.id,
          a.application_number,
          a.applicant_name,
          a.applicant_email,
          a.applicant_phone,
          a.amount,
          a.status,
          a.created_at,
          s.name AS school_name,
          f.title AS form_title,
          p.reference AS payment_reference,
          p.transaction_id,
          p.method AS payment_method,
          p.status AS payment_status,
          p.paid_at
       FROM applications a
       JOIN schools s ON s.id = a.school_id
       JOIN school_forms f ON f.id = a.form_id
       LEFT JOIN payments p ON p.application_id = a.id
       WHERE a.application_number = $1
       LIMIT 1`,
      [number]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Namba ya maombi haijapatikana.",
      });
    }

    res.json({
      success: true,
      application: result.rows[0],
    });
  })
);

// ======================================================
// 9. PAYMENT STATUS
// ======================================================

app.get(
  "/api/payments/:reference",
  asyncHandler(async (req, res) => {
    const result = await query(
      `SELECT
          p.reference,
          p.amount,
          p.method,
          p.transaction_id,
          p.status,
          p.paid_at,
          a.application_number,
          a.applicant_name,
          s.name AS school_name
       FROM payments p
       JOIN applications a ON a.id = p.application_id
       JOIN schools s ON s.id = a.school_id
       WHERE p.reference = $1
       LIMIT 1`,
      [req.params.reference]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Malipo hayajapatikana.",
      });
    }

    res.json({
      success: true,
      payment: result.rows[0],
    });
  })
);

// ======================================================
// 10. ADMIN: CONFIRM PAYMENT
// ======================================================

// Muhimu: endpoint hii inalindwa.
// Ni admin mkuu pekee anayeweza kuthibitisha malipo.

app.post(
  "/api/admin/payments/:reference/confirm",
  authenticate,
  requireSuperAdmin,
  asyncHandler(async (req, res) => {
    const reference = String(req.params.reference || "").trim();
    const transactionId = String(
      req.body.transaction_id || ""
    ).trim();
    const note = String(req.body.note || "").trim();

    if (!transactionId) {
      return res.status(400).json({
        success: false,
        message:
          "Weka transaction ID au kumbukumbu ya malipo yaliyohakikiwa.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const result = await client.query(
        `SELECT id, application_id, amount, status
         FROM payments
         WHERE reference = $1
         FOR UPDATE`,
        [reference]
      );

      if (result.rowCount === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          success: false,
          message: "Rejea ya malipo haijapatikana.",
        });
      }

      const payment = result.rows[0];

      if (payment.status === "PAID") {
        await client.query("ROLLBACK");

        return res.status(409).json({
          success: false,
          message: "Malipo haya tayari yamehakikiwa.",
        });
      }

      await client.query(
        `UPDATE payments
         SET status = 'PAID',
             transaction_id = $1,
             paid_at = NOW(),
             verified_by = $2,
             verification_note = $3
         WHERE id = $4`,
        [transactionId, req.user.id, note || null, payment.id]
      );

      await client.query(
        `UPDATE applications
         SET status = 'PAID'
         WHERE id = $1`,
        [payment.application_id]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message: "Malipo yamethibitishwa.",
        reference,
        transaction_id: transactionId,
        status: "PAID",
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  })
);

// ======================================================
// 11. SCHOOL ADMIN: UPLOAD ORIGINAL PDF
// ======================================================

app.post(
  "/api/admin/schools/:schoolId/forms",
  authenticate,
  requireSchoolAccess,
  upload.single("pdf"),
  asyncHandler(async (req, res) => {
    const schoolId = Number(req.params.schoolId);
    const title = String(req.body.title || "").trim();
    const description = String(req.body.description || "").trim();
    const price = Number(req.body.price);
    const academicYear = String(
      req.body.academic_year || new Date().getFullYear()
    ).trim();

    if (!Number.isInteger(schoolId) || schoolId < 1) {
      return res.status(400).json({
        success: false,
        message: "Namba ya shule si sahihi.",
      });
    }

    if (!title) {
      return res.status(400).json({
        success: false,
        message: "Weka jina la fomu.",
      });
    }

    if (!Number.isFinite(price) || price < 0) {
      return res.status(400).json({
        success: false,
        message: "Bei ya fomu si sahihi.",
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Pakia PDF ya fomu halisi ya shule.",
      });
    }

    const school = await query(
      "SELECT id FROM schools WHERE id = $1",
      [schoolId]
    );

    if (school.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana.",
      });
    }

    const result = await query(
      `INSERT INTO school_forms (
          school_id,
          title,
          description,
          price,
          academic_year,
          pdf_data,
          pdf_filename,
          active
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE)
       RETURNING id, school_id, title, description,
                 price, academic_year, pdf_filename, active`,
      [
        schoolId,
        title,
        description || null,
        price,
        academicYear,
        req.file.buffer,
        path.basename(req.file.originalname),
      ]
    );

    res.status(201).json({
      success: true,
      message: "Fomu ya shule imepakiwa.",
      form: result.rows[0],
    });
  })
);

// ======================================================
// 12. ADMIN: LIST SCHOOL FORMS
// ======================================================

app.get(
  "/api/admin/schools/:schoolId/forms",
  authenticate,
  requireSchoolAccess,
  asyncHandler(async (req, res) => {
    const result = await query(
      `SELECT id, school_id, title, description, price,
              academic_year, pdf_filename, active, created_at
       FROM school_forms
       WHERE school_id = $1
       ORDER BY id DESC`,
      [Number(req.params.schoolId)]
    );

    res.json({
      success: true,
      forms: result.rows,
    });
  })
);

// ======================================================
// 13. ADMIN: LIST APPLICATIONS
// ======================================================

app.get(
  "/api/admin/applications",
  authenticate,
  asyncHandler(async (req, res) => {
    let schoolFilter = "";
    const params = [];

    if (req.user.role !== "super_admin") {
      if (!req.user.school_id) {
        return res.status(403).json({
          success: false,
          message: "Akaunti hii haina shule iliyounganishwa.",
        });
      }

      params.push(req.user.school_id);
      schoolFilter = "WHERE a.school_id = $1";
    }

    const result = await query(
      `SELECT
          a.id,
          a.application_number,
          a.applicant_name,
          a.applicant_email,
          a.applicant_phone,
          a.amount,
          a.status,
          a.created_at,
          s.name AS school_name,
          f.title AS form_title,
          p.reference AS payment_reference,
          p.transaction_id,
          p.status AS payment_status,
          p.paid_at
       FROM applications a
       JOIN schools s ON s.id = a.school_id
       JOIN school_forms f ON f.id = a.form_id
       LEFT JOIN payments p ON p.application_id = a.id
       ${schoolFilter}
       ORDER BY a.created_at DESC
       LIMIT 500`,
      params
    );

    res.json({
      success: true,
      applications: result.rows,
    });
  })
);

// ======================================================
// 14. ADMIN: DASHBOARD STATISTICS
// ======================================================

app.get(
  "/api/admin/dashboard",
  authenticate,
  requireSuperAdmin,
  asyncHandler(async (req, res) => {
    const result = await query(`
      SELECT
        (SELECT COUNT(*) FROM schools)::int AS schools,
        (SELECT COUNT(*) FROM users
          WHERE role = 'school_admin')::int AS school_admins,
        (SELECT COUNT(*) FROM school_forms
          WHERE active = TRUE)::int AS active_forms,
        (SELECT COUNT(*) FROM applications)::int AS applications,
        (SELECT COUNT(*) FROM applications
          WHERE status = 'PENDING_PAYMENT')::int
          AS pending_applications,
        (SELECT COUNT(*) FROM payments
          WHERE status = 'PAID')::int AS paid_payments,
        (SELECT COALESCE(SUM(amount), 0)
          FROM payments WHERE status = 'PAID') AS total_paid
    `);

    res.json({
      success: true,
      stats: result.rows[0],
    });
  })
);

// ======================================================
// 15. ADMIN: CREATE SCHOOL
// ======================================================

app.post(
  "/api/admin/schools",
  authenticate,
  requireSuperAdmin,
  asyncHandler(async (req, res) => {
    const name = String(req.body.name || "").trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Jina la shule linahitajika.",
      });
    }

    const result = await query(
      `INSERT INTO schools (
          name, region, district, address,
          phone, email, description, education_level, status
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active')
       RETURNING *`,
      [
        name,
        req.body.region || null,
        req.body.district || null,
        req.body.address || null,
        req.body.phone || null,
        req.body.email || null,
        req.body.description || null,
        req.body.education_level || null,
      ]
    );

    res.status(201).json({
      success: true,
      message: "Shule imeongezwa.",
      school: result.rows[0],
    });
  })
);

// ======================================================
// 16. ADMIN: CREATE SCHOOL ADMIN
// ======================================================

app.post(
  "/api/admin/school-admins",
  authenticate,
  requireSuperAdmin,
  asyncHandler(async (req, res) => {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim();
    const password = String(req.body.password || "");
    const schoolId = Number(req.body.school_id);

    if (!name || !email || password.length < 8) {
      return res.status(400).json({
        success: false,
        message:
          "Weka jina, email na password yenye angalau herufi 8.",
      });
    }

    if (!Number.isInteger(schoolId) || schoolId < 1) {
      return res.status(400).json({
        success: false,
        message: "Chagua shule sahihi.",
      });
    }

    const school = await query(
      "SELECT id FROM schools WHERE id = $1",
      [schoolId]
    );

    if (school.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Shule haijapatikana.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await query(
      `INSERT INTO users (
          name, email, password_hash, role, school_id
       )
       VALUES ($1, $2, $3, 'school_admin', $4)
       RETURNING id, name, email, role, school_id, active`,
      [name, email, passwordHash, schoolId]
    );

    res.status(201).json({
      success: true,
      message: "Akaunti ya admin wa shule imeundwa.",
      user: result.rows[0],
    });
  })
);

// ======================================================
// 17. ADMIN: LIST SCHOOLS
// ======================================================

app.get(
  "/api/admin/schools",
  authenticate,
  requireSuperAdmin,
  asyncHandler(async (req, res) => {
    const result = await query(
      `SELECT s.*,
          (SELECT COUNT(*)::int FROM school_forms f
           WHERE f.school_id = s.id) AS forms_count,
          (SELECT COUNT(*)::int FROM applications a
           WHERE a.school_id = s.id) AS applications_count
       FROM schools s
       ORDER BY s.created_at DESC`
    );

    res.json({
      success: true,
      schools: result.rows,
    });
  })
);

// ======================================================
// 18. VERIFY APPLICATION NUMBER
// ======================================================

app.get(
  "/api/verify/:applicationNumber",
  asyncHandler(async (req, res) => {
    const number = String(
      req.params.applicationNumber || ""
    ).trim();

    const result = await query(
      `SELECT
          a.application_number,
          a.status AS application_status,
          a.amount,
          a.created_at,
          s.name AS school_name,
          f.title AS form_title,
          p.status AS payment_status,
          p.reference AS payment_reference,
          p.transaction_id,
          p.paid_at
       FROM applications a
       JOIN schools s ON s.id = a.school_id
       JOIN school_forms f ON f.id = a.form_id
       LEFT JOIN payments p ON p.application_id = a.id
       WHERE a.application_number = $1
       LIMIT 1`,
      [number]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        verified: false,
        message: "Namba hii ya maombi haipo kwenye mfumo.",
      });
    }

    const application = result.rows[0];

    res.json({
      success: true,
      verified: application.payment_status === "PAID",
      message:
        application.payment_status === "PAID"
          ? "Malipo ya ombi hili yamethibitishwa."
          : "Ombi lipo lakini malipo hayajathibitishwa.",
      application,
    });
  })
);

// ======================================================
// 19. STATIC WEBSITE FILES
// ======================================================

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ======================================================
// 20. HEALTH CHECK
// ======================================================

app.get(
  "/api/health",
  asyncHandler(async (req, res) => {
    await query("SELECT 1");

    res.json({
      success: true,
      message: "Shule Portal Tanzania server inafanya kazi.",
      database: "connected",
      time: new Date().toISOString(),
    });
  })
);

// ======================================================
// 21. ERROR HANDLER
// ======================================================

app.use((err, req, res, next) => {
  console.error("Server error:", err);

  if (res.headersSent) {
    return next(err);
  }

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      message:
        err.code === "LIMIT_FILE_SIZE"
          ? "PDF imezidi ukubwa wa MB 15."
          : "Imeshindikana kupakia faili.",
    });
  }

  if (err.code === "23505") {
    return res.status(409).json({
      success: false,
      message: "Taarifa hii tayari ipo kwenye mfumo.",
    });
  }

  if (err.code === "23503") {
    return res.status(400).json({
      success: false,
      message: "Taarifa inayohitajika haijapatikana.",
    });
  }

  res.status(500).json({
    success: false,
    message:
      "Hitilafu imetokea kwenye server. Tafadhali jaribu tena.",
  });
});

// ======================================================
// 22. START SERVER
// ======================================================

async function startServer() {
  try {
    await initializeDatabase();

    // Safisha sessions zilizoisha muda wake.
    setInterval(async () => {
      try {
        await query(
          "DELETE FROM user_sessions WHERE expires_at < NOW()"
        );
      } catch (error) {
        console.error("Session cleanup error:", error.message);
      }
    }, 60 * 60 * 1000).unref();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Shule Portal Tanzania inaendesha port ${PORT}`
      );
    });
  } catch (error) {
    console.error("Server haijaanza:", error);
    process.exit(1);
  }
}

startServer();