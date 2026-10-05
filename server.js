const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function cleanText(value) {
  return String(value || "").trim();
}

function generateApplicationNumber() {
  return `SPT-2026-${Date.now()}-${crypto
    .randomInt(10, 99)}`;
}

function generatePaymentReference() {
  return `PAY-2026-${Date.now()}-${crypto
    .randomInt(100, 999)}`;
}

/* =========================================================
   PASSWORD HASH
========================================================= */

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString("hex");

    crypto.scrypt(
      String(password),
      salt,
      64,
      (err, derivedKey) => {
        if (err) return reject(err);

        resolve(
          `scrypt:${salt}:${derivedKey.toString("hex")}`
        );
      }
    );
  });
}

function verifyPassword(password, storedHash) {
  return new Promise((resolve) => {
    try {
      const parts = String(storedHash || "").split(":");

      if (parts.length !== 3) {
        return resolve(false);
      }

      const algorithm = parts[0];
      const salt = parts[1];
      const storedKey = parts[2];

      if (algorithm !== "scrypt") {
        return resolve(false);
      }

      crypto.scrypt(
        String(password),
        salt,
        64,
        (err, derivedKey) => {
          if (err) return resolve(false);

          const storedBuffer =
            Buffer.from(storedKey, "hex");

          const derivedBuffer =
            Buffer.from(derivedKey);

          if (
            storedBuffer.length !==
            derivedBuffer.length
          ) {
            return resolve(false);
          }

          resolve(
            crypto.timingSafeEqual(
              storedBuffer,
              derivedBuffer
            )
          );
        }
      );
    } catch (error) {
      resolve(false);
    }
  });
}

/* =========================================================
   SESSION
========================================================= */

function generateSessionToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashSessionToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";

  const cookies = header
    .split(";")
    .map((item) => item.trim());

  for (const cookie of cookies) {
    const index = cookie.indexOf("=");

    if (index === -1) continue;

    const key = cookie.substring(0, index);
    const value = cookie.substring(index + 1);

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function setSchoolAdminCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    [
      `school_admin_token=${encodeURIComponent(token)}`,
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Path=/",
      "Max-Age=43200"
    ].join("; ")
  );
}

function clearSchoolAdminCookie(res) {
  res.setHeader(
    "Set-Cookie",
    [
      "school_admin_token=",
      "HttpOnly",
      "Secure",
      "SameSite=Lax",
      "Path=/",
      "Max-Age=0"
    ].join("; ")
  );
}

/* =========================================================
   DATABASE SETUP
========================================================= */

async function setupDatabase() {
  await pool.query(`
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
      status VARCHAR(30) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
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

  const applicationColumns = [
    ["student_name", "VARCHAR(255)"],
    ["gender", "VARCHAR(50)"],
    ["date_of_birth", "DATE"],
    ["class_level", "VARCHAR(100)"],
    ["phone", "VARCHAR(50)"],
    ["email", "VARCHAR(255)"]
  ];

  for (const [column, type] of applicationColumns) {
    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS ${column} ${type}
    `);
  }

  await pool.query(`
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

  await pool.query(`
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS school_admin_sessions (
      id SERIAL PRIMARY KEY,
      admin_id INTEGER NOT NULL,
      token_hash VARCHAR(128) NOT NULL UNIQUE,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_applications_school_id
    ON applications(school_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_applications_number
    ON applications(application_number)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_school_admins_email
    ON school_admins(email)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_token
    ON school_admin_sessions(token_hash)
  `);

  console.log("Database setup completed.");
}

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(
    require("path").join(__dirname, "index.html")
  );
});

/* =========================================================
   STATUS
========================================================= */

app.get("/api/status", async (req, res) => {
  res.json({
    success: true,
    message: "Shule Portal Tanzania server iko online.",
    time: new Date().toISOString()
  });
});

/* =========================================================
   DATABASE CHECK
========================================================= */

app.get("/api/database-check", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT NOW() AS current_time"
    );

    res.json({
      success: true,
      message: "database imeunganishwa",
      time: result.rows[0].current_time
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "database haijaunganishwa bado",
      error: error.message
    });
  }
});

/* =========================================================
   SCHOOLS PUBLIC
========================================================= */

app.get("/api/schools", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        s.*,
        (
          SELECT COUNT(*)
          FROM applications a
          WHERE a.school_id = s.id
        ) AS applicant_count
      FROM schools s
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

/* =========================================================
   ADMIN SCHOOLS
========================================================= */

app.get("/api/admin/schools", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        s.*,
        (
          SELECT COUNT(*)
          FROM applications a
          WHERE a.school_id = s.id
        ) AS applicant_count
      FROM schools s
      ORDER BY s.created_at DESC
    `);

    res.json({
      success: true,
      schools: result.rows
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.get("/api/admin/schools/:id", async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM schools
      WHERE id = $1
      `,
      [req.params.id]
    );

    if (!result.rows.length) {
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
        form_price,
        phone,
        address,
        email,
        application_start,
        application_end,
        status
      )
      VALUES
      ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      RETURNING *
      `,
      [
        cleanText(name),
        cleanText(region),
        cleanText(district),
        cleanText(school_type),
        Number(form_price || 0),
        cleanText(phone),
        cleanText(address),
        normalizeEmail(email),
        application_start || null,
        application_end || null,
        status || "active"
      ]
    );

    res.json({
      success: true,
      message: "Shule imeongezwa.",
      school: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

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
      status
    } = req.body;

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
        status = $11,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $12
      RETURNING *
      `,
      [
        cleanText(name),
        cleanText(region),
        cleanText(district),
        cleanText(school_type),
        Number(form_price || 0),
        cleanText(phone),
        cleanText(address),
        normalizeEmail(email),
        application_start || null,
        application_end || null,
        status || "active",
        req.params.id
      ]
    );

    if (!result.rows.length) {
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
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.put(
  "/api/admin/schools/:id/status",
  async (req, res) => {
    try {
      const status =
        req.body.status || "active";

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

app.delete(
  "/api/admin/schools/:id",
  async (req, res) => {
    try {
      await pool.query(
        `
        DELETE FROM schools
        WHERE id = $1
        `,
        [req.params.id]
      );

      res.json({
        success: true,
        message: "Shule imefutwa."
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
   APPLICATIONS
========================================================= */

app.post("/api/applications", async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const {
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
      email
    } = req.body;

    const schoolResult = await client.query(
      `
      SELECT *
      FROM schools
      WHERE id = $1
      AND status = 'active'
      `,
      [school_id]
    );

    if (!schoolResult.rows.length) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        success: false,
        message: "Shule haipatikani au haipo active."
      });
    }

    const school = schoolResult.rows[0];

    const applicationNumber =
      generateApplicationNumber();

    const studentName =
      student_name ||
      applicant_name ||
      "";

    const studentGender =
      gender ||
      applicant_gender ||
      "";

    const studentDob =
      date_of_birth ||
      applicant_date_of_birth ||
      null;

    const parentName =
      parent_name || "";

    const parentPhone =
      phone ||
      parent_phone ||
      "";

    const parentEmail =
      email ||
      parent_email ||
      "";

    const result = await client.query(
      `
      INSERT INTO applications
      (
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
      VALUES
      (
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
        studentGender,
        studentDob,
        parentName,
        parentPhone,
        parentEmail,
        address || "",
        studentName,
        studentGender,
        studentDob,
        class_level || "",
        parentPhone,
        parentEmail
      ]
    );

    const application =
      result.rows[0];

    const paymentReference =
      generatePaymentReference();

    await client.query(
      `
      INSERT INTO payments
      (
        application_id,
        payment_reference,
        amount,
        status,
        provider
      )
      VALUES
      ($1,$2,$3,'pending','manual')
      `,
      [
        application.id,
        paymentReference,
        school.form_price || 0
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Maombi yamehifadhiwa.",
      application: {
        ...application,
        form_price: school.form_price,
        school_name: school.name,
        school_region: school.region,
        school_district: school.district
      },
      payment_reference: paymentReference
    });
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kuhifadhi maombi.",
      error: error.message
    });
  } finally {
    client.release();
  }
});

app.get(
  "/api/applications/:id",
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          a.*,
          s.name AS school_name,
          s.region,
          s.district,
          s.school_type,
          s.form_price,
          p.payment_reference,
          p.status AS payment_record_status,
          p.provider_reference,
          p.paid_at
        FROM applications a
        LEFT JOIN schools s
          ON s.id = a.school_id
        LEFT JOIN payments p
          ON p.application_id = a.id
        WHERE a.id = $1
        ORDER BY p.id DESC
        LIMIT 1
        `,
        [req.params.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Maombi hayajapatikana."
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

app.get(
  "/api/application-by-number/:applicationNumber",
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          a.*,
          s.name AS school_name,
          s.region,
          s.district,
          s.school_type,
          s.form_price,
          p.payment_reference,
          p.status AS payment_record_status,
          p.provider_reference,
          p.paid_at
        FROM applications a
        LEFT JOIN schools s
          ON s.id = a.school_id
        LEFT JOIN payments p
          ON p.application_id = a.id
        WHERE a.application_number = $1
        ORDER BY p.id DESC
        LIMIT 1
        `,
        [req.params.applicationNumber]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Namba ya maombi haijapatikana."
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

/* =========================================================
   ADMIN APPLICATIONS
========================================================= */

app.get(
  "/api/admin/applications",
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          a.*,
          s.name AS school_name,
          s.region,
          s.district,
          s.school_type,
          s.form_price,
          p.payment_reference,
          p.status AS payment_record_status,
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
        ) p ON TRUE
        ORDER BY a.created_at DESC
      `);

      res.json({
        success: true,
        applications: result.rows
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.get(
  "/api/admin/dashboard-stats",
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (
            WHERE status = 'pending'
          )::int AS pending,
          COUNT(*) FILTER (
            WHERE status = 'approved'
          )::int AS approved,
          COUNT(*) FILTER (
            WHERE status = 'rejected'
          )::int AS rejected,
          COUNT(*) FILTER (
            WHERE payment_status = 'paid'
          )::int AS paid,
          COUNT(*) FILTER (
            WHERE payment_status <> 'paid'
               OR payment_status IS NULL
          )::int AS unpaid
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
  }
);

app.put(
  "/api/admin/applications/:id/status",
  async (req, res) => {
    try {
      const status =
        req.body.status || "pending";

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

app.put(
  "/api/admin/applications/:id/payment-status",
  async (req, res) => {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const status =
        req.body.status || "unpaid";

      await client.query(
        `
        UPDATE applications
        SET
          payment_status = $1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
        `,
        [status, req.params.id]
      );

      await client.query(
        `
        UPDATE payments
        SET
          status = $1,
          paid_at =
            CASE
              WHEN $1 = 'paid'
              THEN CURRENT_TIMESTAMP
              ELSE paid_at
            END,
          updated_at = CURRENT_TIMESTAMP
        WHERE application_id = $2
        `,
        [status, req.params.id]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message: "Hali ya malipo imebadilishwa."
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
  }
);

/* =========================================================
   SCHOOL ADMINS
========================================================= */

app.get(
  "/api/admin/school-admins",
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          a.id,
          a.school_id,
          a.full_name,
          a.phone,
          a.email,
          a.status,
          a.last_login,
          a.created_at,
          a.updated_at,
          s.name AS school_name,
          s.region,
          s.district
        FROM school_admins a
        LEFT JOIN schools s
          ON s.id = a.school_id
        ORDER BY a.created_at DESC
      `);

      res.json({
        success: true,
        admins: result.rows
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

app.get(
  "/api/admin/school-admins/:id",
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          a.id,
          a.school_id,
          a.full_name,
          a.phone,
          a.email,
          a.status,
          a.last_login,
          a.created_at,
          a.updated_at,
          s.name AS school_name,
          s.region,
          s.district
        FROM school_admins a
        LEFT JOIN schools s
          ON s.id = a.school_id
        WHERE a.id = $1
        `,
        [req.params.id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Admin hajapatikana."
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
  }
);

app.post(
  "/api/admin/school-admins",
  async (req, res) => {
    try {
      const {
        school_id,
        full_name,
        phone,
        email,
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
            "Shule, jina, email na password vinahitajika."
        });
      }

      const normalizedEmail =
        normalizeEmail(email);

      const existing =
        await pool.query(
          `
          SELECT id
          FROM school_admins
          WHERE LOWER(email) = LOWER($1)
          `,
          [normalizedEmail]
        );

      if (existing.rows.length) {
        return res.status(409).json({
          success: false,
          message:
            "Email hiyo tayari inatumika."
        });
      }

      const passwordHash =
        await hashPassword(password);

      const result =
        await pool.query(
          `
          INSERT INTO school_admins
          (
            school_id,
            full_name,
            phone,
            email,
            password_hash,
            status
          )
          VALUES
          ($1,$2,$3,$4,$5,$6)
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
            cleanText(full_name),
            cleanText(phone),
            normalizedEmail,
            passwordHash,
            status || "active"
          ]
        );

      res.json({
        success: true,
        message:
          "Admin wa shule ameongezwa.",
        admin: result.rows[0]
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

app.put(
  "/api/admin/school-admins/:id",
  async (req, res) => {
    try {
      const {
        school_id,
        full_name,
        phone,
        email,
        status
      } = req.body;

      const normalizedEmail =
        normalizeEmail(email);

      const duplicate =
        await pool.query(
          `
          SELECT id
          FROM school_admins
          WHERE LOWER(email) = LOWER($1)
          AND id <> $2
          `,
          [
            normalizedEmail,
            req.params.id
          ]
        );

      if (duplicate.rows.length) {
        return res.status(409).json({
          success: false,
          message:
            "Email hiyo tayari inatumiwa na admin mwingine."
        });
      }

      const result =
        await pool.query(
          `
          UPDATE school_admins
          SET
            school_id = $1,
            full_name = $2,
            phone = $3,
            email = $4,
            status = $5,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $6
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
            school_id,
            cleanText(full_name),
            cleanText(phone),
            normalizedEmail,
            status || "active",
            req.params.id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Admin hajapatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Admin amesasishwa.",
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

/* =========================================================
   RESET PASSWORD
========================================================= */

app.put(
  "/api/admin/school-admins/:id/reset-password",
  async (req, res) => {
    try {
      const password =
        String(req.body.password || "");

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Password lazima iwe na angalau characters 6."
        });
      }

      const admin =
        await pool.query(
          `
          SELECT id, email
          FROM school_admins
          WHERE id = $1
          `,
          [req.params.id]
        );

      if (!admin.rows.length) {
        return res.status(404).json({
          success: false,
          message:
            "Admin hajapatikana."
        });
      }

      const passwordHash =
        await hashPassword(password);

      await pool.query(
        `
        UPDATE school_admins
        SET
          password_hash = $1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
        `,
        [
          passwordHash,
          req.params.id
        ]
      );

      // Ondoa sessions zote za zamani.
      await pool.query(
        `
        DELETE FROM school_admin_sessions
        WHERE admin_id = $1
        `,
        [req.params.id]
      );

      // TEST YA HASH MARA MOJA
      const verified =
        await verifyPassword(
          password,
          passwordHash
        );

      if (!verified) {
        return res.status(500).json({
          success: false,
          message:
            "Password imehifadhiwa lakini verification test imeshindwa."
        });
      }

      res.json({
        success: true,
        message:
          "Password imebadilishwa kikamilifu. Admin anaweza kuingia sasa.",
        email: admin.rows[0].email
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

/* =========================================================
   ACTIVATE / DEACTIVATE SCHOOL ADMIN
========================================================= */

app.put(
  "/api/admin/school-admins/:id/status",
  async (req, res) => {
    const client = await pool.connect();

    try {
      const status =
        req.body.status || "active";

      await client.query("BEGIN");

      const result =
        await client.query(
          `
          UPDATE school_admins
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

      if (!result.rows.length) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          success: false,
          message:
            "Admin hajapatikana."
        });
      }

      if (status !== "active") {
        await client.query(
          `
          DELETE FROM school_admin_sessions
          WHERE admin_id = $1
          `,
          [req.params.id]
        );
      }

      await client.query("COMMIT");

      res.json({
        success: true,
        message:
          status === "active"
            ? "Admin amewezeshwa."
            : "Admin amezimwa.",
        admin: result.rows[0]
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
  }
);

app.delete(
  "/api/admin/school-admins/:id",
  async (req, res) => {
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

      await client.query(
        `
        DELETE FROM school_admins
        WHERE id = $1
        `,
        [req.params.id]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message:
          "Admin amefutwa."
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
  }
);

/* =========================================================
   SCHOOL ADMIN LOGIN
========================================================= */

app.post(
  "/api/school-admin/login",
  async (req, res) => {
    try {
      const email =
        normalizeEmail(req.body.email);

      const password =
        String(req.body.password || "");

      console.log(
        "School Admin Login:",
        email
      );

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Email na password vinahitajika."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            a.*,
            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.status AS school_status
          FROM school_admins a
          LEFT JOIN schools s
            ON s.id = a.school_id
          WHERE LOWER(TRIM(a.email))
                = LOWER(TRIM($1))
          LIMIT 1
          `,
          [email]
        );

      console.log(
        "Admin records found:",
        result.rows.length
      );

      if (!result.rows.length) {
        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });
      }

      const admin =
        result.rows[0];

      console.log(
        "Admin:",
        admin.id,
        admin.email,
        admin.status,
        admin.school_name
      );

      if (admin.status !== "active") {
        return res.status(403).json({
          success: false,
          message:
            "Akaunti ya admin imezimwa."
        });
      }

      if (
        admin.school_status &&
        admin.school_status !== "active"
      ) {
        return res.status(403).json({
          success: false,
          message:
            "Shule hii haipo active."
        });
      }

      const passwordCorrect =
        await verifyPassword(
          password,
          admin.password_hash
        );

      console.log(
        "Password correct:",
        passwordCorrect
      );

      if (!passwordCorrect) {
        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });
      }

      // Futa sessions zilizokwisha muda.
      await pool.query(
        `
        DELETE FROM school_admin_sessions
        WHERE expires_at < CURRENT_TIMESTAMP
        `
      );

      // Tengeneza session mpya.
      const token =
        generateSessionToken();

      const tokenHash =
        hashSessionToken(token);

      await pool.query(
        `
        INSERT INTO school_admin_sessions
        (
          admin_id,
          token_hash,
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

      setSchoolAdminCookie(
        res,
        token
      );

      res.json({
        success: true,
        message:
          "Umefanikiwa kuingia.",
        admin: {
          id: admin.id,
          full_name: admin.full_name,
          email: admin.email,
          phone: admin.phone,
          school_id: admin.school_id,
          school_name: admin.school_name,
          region: admin.region,
          district: admin.district,
          school_type: admin.school_type
        }
      });
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Tatizo la server wakati wa login.",
        error: error.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN AUTH MIDDLEWARE
========================================================= */

async function getSchoolAdminFromRequest(req) {
  const token =
    getCookie(
      req,
      "school_admin_token"
    );

  if (!token) {
    return null;
  }

  const tokenHash =
    hashSessionToken(token);

  const result =
    await pool.query(
      `
      SELECT
        a.*,
        s.name AS school_name,
        s.region,
        s.district,
        s.school_type,
        s.form_price,
        s.phone AS school_phone,
        s.email AS school_email,
        s.status AS school_status
      FROM school_admin_sessions ses
      INNER JOIN school_admins a
        ON a.id = ses.admin_id
      LEFT JOIN schools s
        ON s.id = a.school_id
      WHERE ses.token_hash = $1
      AND ses.expires_at > CURRENT_TIMESTAMP
      AND a.status = 'active'
      LIMIT 1
      `,
      [tokenHash]
    );

  if (!result.rows.length) {
    return null;
  }

  const admin =
    result.rows[0];

  if (
    admin.school_status &&
    admin.school_status !== "active"
  ) {
    return null;
  }

  return admin;
}

/* =========================================================
   SCHOOL ADMIN ME
========================================================= */

app.get(
  "/api/school-admin/me",
  async (req, res) => {
    try {
      const admin =
        await getSchoolAdminFromRequest(
          req
        );

      if (!admin) {
        return res.status(401).json({
          success: false,
          message:
            "Hujaingia kama School Admin."
        });
      }

      res.json({
        success: true,
        admin: {
          id: admin.id,
          full_name: admin.full_name,
          email: admin.email,
          phone: admin.phone,
          school_id: admin.school_id,
          school_name: admin.school_name,
          region: admin.region,
          district: admin.district,
          school_type: admin.school_type,
          form_price: admin.form_price,
          school_phone: admin.school_phone,
          school_email: admin.school_email
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

/* =========================================================
   SCHOOL ADMIN LOGOUT
========================================================= */

app.post(
  "/api/school-admin/logout",
  async (req, res) => {
    try {
      const token =
        getCookie(
          req,
          "school_admin_token"
        );

      if (token) {
        const tokenHash =
          hashSessionToken(token);

        await pool.query(
          `
          DELETE FROM school_admin_sessions
          WHERE token_hash = $1
          `,
          [tokenHash]
        );
      }

      clearSchoolAdminCookie(res);

      res.json({
        success: true,
        message:
          "Umetoka kwenye mfumo."
      });
    } catch (error) {
      clearSchoolAdminCookie(res);

      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN DASHBOARD STATS
========================================================= */

app.get(
  "/api/school-admin/dashboard-stats",
  async (req, res) => {
    try {
      const admin =
        await getSchoolAdminFromRequest(
          req
        );

      if (!admin) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            COUNT(*)::int AS total,

            COUNT(*) FILTER (
              WHERE status = 'pending'
            )::int AS pending,

            COUNT(*) FILTER (
              WHERE status = 'approved'
            )::int AS approved,

            COUNT(*) FILTER (
              WHERE status = 'rejected'
            )::int AS rejected,

            COUNT(*) FILTER (
              WHERE payment_status = 'paid'
            )::int AS paid,

            COUNT(*) FILTER (
              WHERE payment_status <> 'paid'
                 OR payment_status IS NULL
            )::int AS unpaid

          FROM applications

          WHERE school_id = $1
          `,
          [admin.school_id]
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

/* =========================================================
   SCHOOL ADMIN APPLICATIONS
========================================================= */

app.get(
  "/api/school-admin/applications",
  async (req, res) => {
    try {
      const admin =
        await getSchoolAdminFromRequest(
          req
        );

      if (!admin) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            a.*,
            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,
            p.payment_reference,
            p.status AS payment_record_status,
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
          ) p ON TRUE

          WHERE a.school_id = $1

          ORDER BY a.created_at DESC
          `,
          [admin.school_id]
        );

      res.json({
        success: true,
        applications: result.rows
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
   SCHOOL ADMIN SINGLE APPLICATION
========================================================= */

app.get(
  "/api/school-admin/applications/:id",
  async (req, res) => {
    try {
      const admin =
        await getSchoolAdminFromRequest(
          req
        );

      if (!admin) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized."
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            a.*,
            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,
            p.payment_reference,
            p.status AS payment_record_status,
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
          ) p ON TRUE

          WHERE a.id = $1
          AND a.school_id = $2

          LIMIT 1
          `,
          [
            req.params.id,
            admin.school_id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message:
            "Maombi hayapatikani kwenye shule yako."
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

/* =========================================================
   SCHOOL ADMIN UPDATE APPLICATION STATUS
========================================================= */

app.put(
  "/api/school-admin/applications/:id/status",
  async (req, res) => {
    try {
      const admin =
        await getSchoolAdminFromRequest(
          req
        );

      if (!admin) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized."
        });
      }

      const status =
        req.body.status || "pending";

      const result =
        await pool.query(
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
            admin.school_id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message:
            "Maombi hayajapatikana."
        });
      }

      res.json({
        success: true,
        message:
          "Hali ya maombi imebadilishwa.",
        application:
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

/* =========================================================
   SCHEMA CHECKS
========================================================= */

app.get(
  "/api/application-schema",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT column_name, data_type
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
        message: error.message
      });
    }
  }
);

app.get(
  "/api/payment-schema",
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT column_name, data_type
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
        message: error.message
      });
    }
  }
);

/* =========================================================
   CLEAN EXPIRED SESSIONS
========================================================= */

async function cleanExpiredSessions() {
  try {
    await pool.query(`
      DELETE FROM school_admin_sessions
      WHERE expires_at < CURRENT_TIMESTAMP
    `);

    console.log(
      "Expired sessions cleaned."
    );
  } catch (error) {
    console.error(
      "Session cleanup error:",
      error.message
    );
  }
}

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    await setupDatabase();

    await cleanExpiredSessions();

    setInterval(
      cleanExpiredSessions,
      60 * 60 * 1000
    );

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
      "SERVER START ERROR:",
      error
    );

    process.exit(1);
  }
}

startServer();