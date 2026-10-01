const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================================
// DATABASE
// =====================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// =====================================================
// HELPERS
// =====================================================

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(":")) {
    return false;
  }

  const parts = storedHash.split(":");

  if (parts.length !== 2) {
    return false;
  }

  const salt = parts[0];
  const originalHash = parts[1];

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  const hashBuffer = Buffer.from(hash, "hex");
  const originalBuffer = Buffer.from(originalHash, "hex");

  if (hashBuffer.length !== originalBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    hashBuffer,
    originalBuffer
  );
}

function generateApplicationNumber() {
  const year = new Date().getFullYear();

  const random = crypto
    .randomBytes(4)
    .toString("hex")
    .toUpperCase();

  return `SPT-${year}-${random}`;
}

function generatePaymentReference() {
  const year = new Date().getFullYear();

  const random = crypto
    .randomBytes(4)
    .toString("hex")
    .toUpperCase();

  return `PAY-${year}-${random}`;
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

// =====================================================
// DATABASE INITIALIZATION
// =====================================================

async function initializeDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS schools (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      region VARCHAR(100) NOT NULL,
      district VARCHAR(100) NOT NULL,
      school_type VARCHAR(100) NOT NULL,
      form_price NUMERIC(12,2) NOT NULL DEFAULT 0,
      phone VARCHAR(30),
      address TEXT,
      email VARCHAR(255),
      application_start DATE,
      application_end DATE,
      status VARCHAR(30) NOT NULL DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS school_admins (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      phone VARCHAR(30),
      school_id INTEGER NOT NULL,
      password_hash TEXT NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      CONSTRAINT fk_school_admin_school
        FOREIGN KEY (school_id)
        REFERENCES schools(id)
        ON DELETE RESTRICT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS school_forms (
      id SERIAL PRIMARY KEY,
      school_id INTEGER NOT NULL,
      form_name VARCHAR(255) NOT NULL,
      price NUMERIC(12,2) NOT NULL DEFAULT 0,
      status VARCHAR(30) NOT NULL DEFAULT 'active',
      application_start DATE,
      application_end DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      CONSTRAINT fk_school_form_school
        FOREIGN KEY (school_id)
        REFERENCES schools(id)
        ON DELETE RESTRICT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS applications (
      id SERIAL PRIMARY KEY,

      application_number VARCHAR(50)
        NOT NULL UNIQUE,

      school_id INTEGER NOT NULL,

      form_id INTEGER NOT NULL,

      applicant_name VARCHAR(255) NOT NULL,

      applicant_gender VARCHAR(30),

      applicant_date_of_birth DATE,

      parent_name VARCHAR(255),

      parent_phone VARCHAR(30),

      parent_email VARCHAR(255),

      address TEXT,

      status VARCHAR(50)
        NOT NULL DEFAULT 'pending',

      payment_status VARCHAR(50)
        NOT NULL DEFAULT 'unpaid',

      created_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP,

      updated_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP,

      CONSTRAINT fk_application_school
        FOREIGN KEY (school_id)
        REFERENCES schools(id)
        ON DELETE RESTRICT,

      CONSTRAINT fk_application_form
        FOREIGN KEY (form_id)
        REFERENCES school_forms(id)
        ON DELETE RESTRICT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,

      payment_reference VARCHAR(100)
        NOT NULL UNIQUE,

      application_id INTEGER NOT NULL,

      application_number VARCHAR(50)
        NOT NULL,

      amount NUMERIC(12,2) NOT NULL,

      payment_method VARCHAR(50),

      transaction_id VARCHAR(100),

      payer_phone VARCHAR(30),

      status VARCHAR(30)
        NOT NULL DEFAULT 'pending',

      paid_at TIMESTAMP,

      created_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP,

      updated_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP,

      CONSTRAINT fk_payment_application
        FOREIGN KEY (application_id)
        REFERENCES applications(id)
        ON DELETE RESTRICT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id SERIAL PRIMARY KEY,

      full_name VARCHAR(255) NOT NULL,

      email VARCHAR(255)
        NOT NULL UNIQUE,

      password_hash TEXT NOT NULL,

      role VARCHAR(50)
        NOT NULL DEFAULT 'super_admin',

      status VARCHAR(30)
        NOT NULL DEFAULT 'active',

      created_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP,

      updated_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      id SERIAL PRIMARY KEY,

      admin_id INTEGER NOT NULL,

      session_token TEXT
        NOT NULL UNIQUE,

      expires_at TIMESTAMP NOT NULL,

      created_at TIMESTAMP
        DEFAULT CURRENT_TIMESTAMP,

      CONSTRAINT fk_admin_session_admin
        FOREIGN KEY (admin_id)
        REFERENCES admin_users(id)
        ON DELETE CASCADE
    );
  `);

  console.log("Database tables ready.");
}

// =====================================================
// SYNC ADMIN MKUU
// =====================================================

async function syncAdminUser() {

  const email = String(
    process.env.ADMIN_EMAIL || ""
  )
    .trim()
    .toLowerCase();

  const password = String(
    process.env.ADMIN_PASSWORD || ""
  );

  const name = String(
    process.env.ADMIN_NAME || "Admin Mkuu"
  ).trim();

  if (!email || !password) {
    console.log(
      "ADMIN_EMAIL au ADMIN_PASSWORD haijawekwa."
    );
    return;
  }

  const existing = await pool.query(
    `
    SELECT id
    FROM admin_users
    WHERE email = $1
    LIMIT 1
    `,
    [email]
  );

  const passwordHash = hashPassword(password);

  if (existing.rows.length === 0) {

    await pool.query(
      `
      INSERT INTO admin_users
      (
        full_name,
        email,
        password_hash,
        role,
        status
      )
      VALUES
      ($1, $2, $3, 'super_admin', 'active')
      `,
      [
        name,
        email,
        passwordHash
      ]
    );

    console.log(
      "Admin Mkuu ameundwa:",
      email
    );

  } else {

    await pool.query(
      `
      UPDATE admin_users
      SET
        full_name = $1,
        password_hash = $2,
        status = 'active',
        updated_at = CURRENT_TIMESTAMP
      WHERE email = $3
      `,
      [
        name,
        passwordHash,
        email
      ]
    );

    console.log(
      "Admin Mkuu amesync:",
      email
    );
  }
}

// =====================================================
// ADMIN AUTH MIDDLEWARE
// =====================================================

async function requireAdmin(req, res, next) {

  try {

    const authHeader =
      req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {

      return res.status(401).json({
        success: false,
        message: "Hujaingia kama Admin."
      });
    }

    const token =
      authHeader.substring(7).trim();

    if (!token) {

      return res.status(401).json({
        success: false,
        message: "Session token haipo."
      });
    }

    const result = await pool.query(
      `
      SELECT
        s.id AS session_id,
        s.admin_id,
        s.expires_at,
        a.full_name,
        a.email,
        a.role,
        a.status

      FROM admin_sessions s

      INNER JOIN admin_users a
        ON a.id = s.admin_id

      WHERE
        s.session_token = $1
        AND a.status = 'active'

      LIMIT 1
      `,
      [token]
    );

    if (result.rows.length === 0) {

      return res.status(401).json({
        success: false,
        message: "Session si sahihi."
      });
    }

    const session = result.rows[0];

    if (
      new Date(session.expires_at) <=
      new Date()
    ) {

      await pool.query(
        `
        DELETE FROM admin_sessions
        WHERE id = $1
        `,
        [session.session_id]
      );

      return res.status(401).json({
        success: false,
        message: "Session imekwisha muda."
      });
    }

    req.admin = session;

    next();

  } catch (error) {

    console.error(
      "Admin middleware error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Tatizo la authentication."
    });
  }
}

// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// =====================================================
// SYSTEM STATUS
// =====================================================

app.get("/api/status", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    return res.json({
      success: true,
      message:
        "Shule Portal Tanzania backend na PostgreSQL vimeunganishwa",
      database: "connected",
      time: new Date().toISOString()
    });

  } catch (error) {

    console.error(
      "Status error:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Database haijaunganishwa."
    });
  }
});

// =====================================================
// ADMIN LOGIN
// =====================================================

app.post(
  "/api/admin/login",
  async (req, res) => {

    try {

      const email = String(
        req.body.email || ""
      )
        .trim()
        .toLowerCase();

      const password = String(
        req.body.password || ""
      );

      if (!email || !password) {

        return res.status(400).json({
          success: false,
          message:
            "Email na password vinahitajika."
        });
      }

      const result = await pool.query(
        `
        SELECT
          id,
          full_name,
          email,
          password_hash,
          role,
          status
        FROM admin_users
        WHERE email = $1
        LIMIT 1
        `,
        [email]
      );

      if (result.rows.length === 0) {

        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });
      }

      const admin = result.rows[0];

      if (admin.status !== "active") {

        return res.status(403).json({
          success: false,
          message:
            "Admin account haijawezeshwa."
        });
      }

      const valid = verifyPassword(
        password,
        admin.password_hash
      );

      if (!valid) {

        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });
      }

      const sessionToken =
        generateSessionToken();

      await pool.query(
        `
        INSERT INTO admin_sessions
        (
          admin_id,
          session_token,
          expires_at
        )
        VALUES
        (
          $1,
          $2,
          CURRENT_TIMESTAMP + INTERVAL '12 hours'
        )
        `,
        [
          admin.id,
          sessionToken
        ]
      );

      return res.json({
        success: true,
        message:
          "Umeingia kwa mafanikio.",
        token: sessionToken,
        admin: {
          id: admin.id,
          full_name: admin.full_name,
          email: admin.email,
          role: admin.role
        }
      });

    } catch (error) {

      console.error(
        "Admin login error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuingia."
      });
    }
  }
);

// =====================================================
// ADMIN ME
// =====================================================

app.get(
  "/api/admin/me",
  requireAdmin,
  async (req, res) => {

    return res.json({
      success: true,
      admin: {
        id: req.admin.admin_id,
        full_name: req.admin.full_name,
        email: req.admin.email,
        role: req.admin.role
      }
    });
  }
);

// =====================================================
// ADMIN LOGOUT
// =====================================================

app.post(
  "/api/admin/logout",
  requireAdmin,
  async (req, res) => {

    try {

      const authHeader =
        req.headers.authorization || "";

      const token =
        authHeader.substring(7).trim();

      await pool.query(
        `
        DELETE FROM admin_sessions
        WHERE session_token = $1
        `,
        [token]
      );

      return res.json({
        success: true,
        message:
          "Umetoka kwenye mfumo."
      });

    } catch (error) {

      console.error(
        "Admin logout error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Logout imeshindikana."
      });
    }
  }
);

// =====================================================
// ADMIN DASHBOARD
// =====================================================

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  async (req, res) => {

    try {

      const totalSchoolsResult =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM schools
          `
        );

      const totalFormsResult =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM school_forms
          `
        );

      const totalApplicationsResult =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM applications
          `
        );

      const totalPaymentsResult =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM payments
          `
        );

      const paidPaymentsResult =
        await pool.query(
          `
          SELECT
            COUNT(*)::int AS count,
            COALESCE(SUM(amount), 0)::numeric AS total
          FROM payments
          WHERE status = 'paid'
          `
        );

      const pendingPaymentsResult =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM payments
          WHERE status = 'pending'
          `
        );

      const pendingApplicationsResult =
        await pool.query(
          `
          SELECT COUNT(*)::int AS count
          FROM applications
          WHERE status = 'pending'
          `
        );

      const recentApplicationsResult =
        await pool.query(
          `
          SELECT
            a.id,
            a.application_number,
            a.applicant_name,
            a.status,
            a.payment_status,
            a.created_at,
            s.name AS school_name,
            f.form_name
          FROM applications a
          LEFT JOIN schools s
            ON s.id = a.school_id
          LEFT JOIN school_forms f
            ON f.id = a.form_id
          ORDER BY a.id DESC
          LIMIT 10
          `
        );

      const recentPaymentsResult =
        await pool.query(
          `
          SELECT
            p.id,
            p.payment_reference,
            p.application_number,
            p.amount,
            p.payment_method,
            p.status,
            p.created_at
          FROM payments p
          ORDER BY p.id DESC
          LIMIT 10
          `
        );

      const totalSchools =
        totalSchoolsResult.rows[0].count;

      const totalForms =
        totalFormsResult.rows[0].count;

      const totalApplications =
        totalApplicationsResult.rows[0].count;

      const totalPayments =
        totalPaymentsResult.rows[0].count;

      const paidPayments =
        paidPaymentsResult.rows[0].count;

      const pendingPayments =
        pendingPaymentsResult.rows[0].count;

      const totalPaid =
        paidPaymentsResult.rows[0].total;

      const pendingApplications =
        pendingApplicationsResult.rows[0].count;

      return res.json({
        success: true,

        stats: {
          schools: totalSchools,
          forms: totalForms,
          applications: totalApplications,
          payments: totalPayments,
          paidPayments: paidPayments,
          soldForms: paidPayments,
          pendingPayments: pendingPayments,
          totalPaidAmount: totalPaid,
          totalSchools: totalSchools,
          totalForms: totalForms,
          totalApplications: totalApplications,
          totalPayments: totalPayments,
          totalPaid: totalPaid,
          pendingApplications:
            pendingApplications
        },

        statistics: {
          totalSchools: totalSchools,
          totalForms: totalForms,
          totalApplications:
            totalApplications,
          totalPayments: totalPayments,
          totalPaid: totalPaid,
          pendingPayments:
            pendingPayments,
          pendingApplications:
            pendingApplications
        },

        recentApplications:
          recentApplicationsResult.rows,

        recentPayments:
          recentPaymentsResult.rows
      });

    } catch (error) {

      console.error(
        "Admin dashboard error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata dashboard."
      });
    }
  }
);

// =====================================================
// ADMIN SCHOOLS
// =====================================================

app.get(
  "/api/admin/schools",
  requireAdmin,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT *
        FROM schools
        ORDER BY id DESC
        `
      );

      return res.json({
        success: true,
        schools: result.rows
      });

    } catch (error) {

      console.error(
        "Get admin schools error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata shule."
      });
    }
  }
);

app.post(
  "/api/admin/schools",
  requireAdmin,
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
        application_end
      } = req.body;

      if (
        !name ||
        !region ||
        !district ||
        !school_type
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Jina, mkoa, wilaya na aina ya shule vinahitajika."
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
          form_price,
          phone,
          address,
          email,
          application_start,
          application_end
        )
        VALUES
        (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
        )
        RETURNING *
        `,
        [
          name,
          region,
          district,
          school_type,
          Number(form_price || 0),
          phone || null,
          address || null,
          email || null,
          application_start || null,
          application_end || null
        ]
      );

      return res.json({
        success: true,
        message:
          "Shule imeongezwa.",
        school:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Create school error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuongeza shule."
      });
    }
  }
);

// =====================================================
// PUBLIC SCHOOLS
// =====================================================

app.get(
  "/api/schools",
  async (req, res) => {

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
          status,
          created_at,
          updated_at
        FROM schools
        WHERE status = 'active'
        ORDER BY id DESC
      `);

      return res.json({
        success: true,
        schools: result.rows,
        count: result.rows.length
      });

    } catch (error) {

      console.error(
        "Get schools error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata taarifa za shule.",
        schools: []
      });
    }
  }
);

// =====================================================
// SCHOOL ADMINS
// =====================================================

app.get(
  "/api/admin/school-admins",
  requireAdmin,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT
          sa.id,
          sa.full_name,
          sa.email,
          sa.phone,
          sa.school_id,
          sa.status,
          sa.created_at,
          s.name AS school_name
        FROM school_admins sa
        LEFT JOIN schools s
          ON s.id = sa.school_id
        ORDER BY sa.id DESC
        `
      );

      return res.json({
        success: true,
        schoolAdmins:
          result.rows
      });

    } catch (error) {

      console.error(
        "Get school admins error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata School Admins."
      });
    }
  }
);

app.post(
  "/api/admin/school-admins",
  requireAdmin,
  async (req, res) => {

    try {

      const {
        full_name,
        email,
        phone,
        school_id,
        password
      } = req.body;

      if (
        !full_name ||
        !email ||
        !school_id ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Jina, email, school, na password vinahitajika."
        });
      }

      const passwordHash =
        hashPassword(password);

      const result = await pool.query(
        `
        INSERT INTO school_admins
        (
          full_name,
          email,
          phone,
          school_id,
          password_hash
        )
        VALUES
        ($1,$2,$3,$4,$5)
        RETURNING
          id,
          full_name,
          email,
          phone,
          school_id,
          status,
          created_at
        `,
        [
          full_name,
          email.toLowerCase(),
          phone || null,
          Number(school_id),
          passwordHash
        ]
      );

      return res.json({
        success: true,
        message:
          "School Admin ameongezwa.",
        schoolAdmin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Create school admin error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuongeza School Admin."
      });
    }
  }
);

// =====================================================
// SCHOOL FORMS
// =====================================================

app.get(
  "/api/admin/school-forms",
  requireAdmin,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT
          sf.id,
          sf.school_id,
          sf.form_name,
          sf.price,
          sf.status,
          sf.application_start,
          sf.application_end,
          sf.created_at,
          s.name AS school_name
        FROM school_forms sf
        LEFT JOIN schools s
          ON s.id = sf.school_id
        ORDER BY sf.id DESC
        `
      );

      return res.json({
        success: true,
        forms: result.rows
      });

    } catch (error) {

      console.error(
        "Get school forms error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata fomu."
      });
    }
  }
);

app.post(
  "/api/admin/school-forms",
  requireAdmin,
  async (req, res) => {

    try {

      const {
        school_id,
        form_name,
        price,
        status,
        application_start,
        application_end
      } = req.body;

      if (!school_id || !form_name) {

        return res.status(400).json({
          success: false,
          message:
            "School na jina la fomu vinahitajika."
        });
      }

      const result = await pool.query(
        `
        INSERT INTO school_forms
        (
          school_id,
          form_name,
          price,
          status,
          application_start,
          application_end
        )
        VALUES
        ($1,$2,$3,$4,$5,$6)
        RETURNING *
        `,
        [
          Number(school_id),
          form_name,
          Number(price || 0),
          status || "active",
          application_start || null,
          application_end || null
        ]
      );

      return res.json({
        success: true,
        message:
          "Fomu imeongezwa.",
        form:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Create school form error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuongeza fomu."
      });
    }
  }
);

// =====================================================
// PUBLIC SCHOOL FORMS
// =====================================================

app.get(
  "/api/school-forms",
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT
          sf.id,
          sf.school_id,
          sf.form_name,
          sf.price,
          sf.status,
          sf.application_start,
          sf.application_end,
          s.name AS school_name
        FROM school_forms sf
        LEFT JOIN schools s
          ON s.id = sf.school_id
        WHERE sf.status = 'active'
        ORDER BY sf.id DESC
        `
      );

      return res.json({
        success: true,
        forms: result.rows,
        count: result.rows.length
      });

    } catch (error) {

      console.error(
        "Get public forms error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata fomu.",
        forms: []
      });
    }
  }
);

// =====================================================
// APPLICATIONS - ADMIN
// =====================================================

app.get(
  "/api/admin/applications",
  requireAdmin,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT
          a.*,
          s.name AS school_name,
          f.form_name
        FROM applications a
        LEFT JOIN schools s
          ON s.id = a.school_id
        LEFT JOIN school_forms f
          ON f.id = a.form_id
        ORDER BY a.id DESC
        `
      );

      return res.json({
        success: true,
        applications:
          result.rows
      });

    } catch (error) {

      console.error(
        "Get applications error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata applications."
      });
    }
  }
);

// =====================================================
// CREATE APPLICATION
// =====================================================

app.post(
  "/api/applications",
  async (req, res) => {

    try {

      const {
        school_id,
        form_id,
        applicant_name,
        applicant_gender,
        applicant_date_of_birth,
        parent_name,
        parent_phone,
        parent_email,
        address
      } = req.body;

      if (
        !school_id ||
        !form_id ||
        !applicant_name
      ) {

        return res.status(400).json({
          success: false,
          message:
            "School, form na jina la mwombaji vinahitajika."
        });
      }

      const schoolResult =
        await pool.query(
          `
          SELECT
            id,
            name
          FROM schools
          WHERE
            id = $1
            AND status = 'active'
          LIMIT 1
          `,
          [Number(school_id)]
        );

      if (schoolResult.rows.length === 0) {

        return