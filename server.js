const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});


/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(__dirname));


/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}


function hashPassword(password) {
  return new Promise((resolve, reject) => {

    const salt = crypto
      .randomBytes(16)
      .toString("hex");

    crypto.scrypt(
      String(password),
      salt,
      64,
      (err, derivedKey) => {

        if (err) {
          return reject(err);
        }

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

      const parts =
        String(storedHash || "").split(":");

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

          if (err) {
            return resolve(false);
          }

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
   COOKIE HELPERS
========================================================= */

function parseCookies(req) {

  const header =
    req.headers.cookie || "";

  const cookies = {};

  header
    .split(";")
    .forEach(part => {

      const index = part.indexOf("=");

      if (index === -1) return;

      const key =
        part.substring(0, index).trim();

      const value =
        part.substring(index + 1).trim();

      if (key) {
        cookies[key] =
          decodeURIComponent(value);
      }

    });

  return cookies;
}


function getSchoolAdminToken(req) {

  const cookies =
    parseCookies(req);

  return cookies.school_admin_token || null;

}


function hashToken(token) {

  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

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

    );

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

    );

  `);


  await pool.query(`

    ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS student_name VARCHAR(255);

  `);


  await pool.query(`

    ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS gender VARCHAR(50);

  `);


  await pool.query(`

    ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS date_of_birth DATE;

  `);


  await pool.query(`

    ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS class_level VARCHAR(100);

  `);


  await pool.query(`

    ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS phone VARCHAR(50);

  `);


  await pool.query(`

    ALTER TABLE applications
    ADD COLUMN IF NOT EXISTS email VARCHAR(255);

  `);


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

    );

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

    );

  `);


  await pool.query(`

    CREATE TABLE IF NOT EXISTS school_admin_sessions (

      id SERIAL PRIMARY KEY,

      admin_id INTEGER NOT NULL,

      token_hash VARCHAR(128) NOT NULL UNIQUE,

      expires_at TIMESTAMP NOT NULL,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

    );

  `);


  await pool.query(`

    CREATE INDEX IF NOT EXISTS
    idx_applications_school_id
    ON applications(school_id);

  `);


  await pool.query(`

    CREATE INDEX IF NOT EXISTS
    idx_applications_application_number
    ON applications(application_number);

  `);


  await pool.query(`

    CREATE INDEX IF NOT EXISTS
    idx_school_admins_school_id
    ON school_admins(school_id);

  `);


  await pool.query(`

    CREATE INDEX IF NOT EXISTS
    idx_school_admin_sessions_token
    ON school_admin_sessions(token_hash);

  `);

}


/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

async function requireSchoolAdmin(req, res, next) {

  try {

    const token =
      getSchoolAdminToken(req);

    if (!token) {

      return res.status(401).json({
        success: false,
        message: "Hujaingia kwenye mfumo."
      });

    }

    const tokenHash =
      hashToken(token);

    const result =
      await pool.query(`

        SELECT

          a.id,
          a.school_id,
          a.full_name,
          a.email,
          a.phone,
          a.status,

          s.name AS school_name,
          s.status AS school_status

        FROM school_admin_sessions sess

        INNER JOIN school_admins a
          ON a.id = sess.admin_id

        INNER JOIN schools s
          ON s.id = a.school_id

        WHERE sess.token_hash = $1

          AND sess.expires_at > CURRENT_TIMESTAMP

          AND a.status = 'active'

          AND s.status = 'active'

        LIMIT 1

      `, [tokenHash]);


    if (!result.rows.length) {

      return res.status(401).json({
        success: false,
        message: "Session imekwisha. Tafadhali ingia tena."
      });

    }


    req.schoolAdmin =
      result.rows[0];

    next();

  } catch (error) {

    console.error(
      "Auth error:",
      error
    );

    res.status(500).json({
      success: false,
      message: "Tatizo la uthibitishaji."
    });

  }

}


/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {

  res.sendFile(
    require("path").join(
      __dirname,
      "index.html"
    )
  );

});


/* =========================================================
   STATUS
========================================================= */

app.get("/api/status", async (req, res) => {

  res.json({
    success: true,
    message: "Shule Portal Tanzania API iko online.",
    time: new Date().toISOString()
  });

});


/* =========================================================
   PUBLIC SCHOOLS
========================================================= */

app.get("/api/schools", async (req, res) => {

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

    console.error(error);

    res.status(500).json({
      success: false,
      message: "Imeshindikana kupata shule."
    });

  }

});


/* =========================================================
   DATABASE CHECK
========================================================= */

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
        message: "database imeunganishwa kikamilifu.",
        time: result.rows[0].now
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message: "database haijaunganishwa bado",
        error: error.message
      });

    }

  }
);


/* =========================================================
   APPLICATION SCHEMA
========================================================= */

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
   PAYMENT SCHEMA
========================================================= */

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
   ADMIN — SCHOOLS
========================================================= */

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
            ) AS applicants

          FROM schools s

          ORDER BY s.created_at DESC

        `);


      res.json({
        success: true,
        schools: result.rows
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message: "Imeshindikana kupata shule."
      });

    }

  }
);


app.get(
  "/api/admin/schools/:id",
  async (req, res) => {

    try {

      const result =
        await pool.query(
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

  }
);


app.post(
  "/api/admin/schools",
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
        status
      } = req.body;


      if (!name) {

        return res.status(400).json({
          success: false,
          message: "Jina la shule linahitajika."
        });

      }


      const result =
        await pool.query(`

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
            status

          )

          VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
          )

          RETURNING *

        `, [

          name,
          region || null,
          district || null,
          school_type || null,
          Number(form_price || 0),
          phone || null,
          address || null,
          email || null,
          application_start || null,
          application_end || null,
          status || "active"

        ]);


      res.json({
        success: true,
        school: result.rows[0]
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
  "/api/admin/schools/:id",
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
        status
      } = req.body;


      const result =
        await pool.query(`

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
            status = COALESCE($11, status),
            updated_at = CURRENT_TIMESTAMP

          WHERE id = $12

          RETURNING *

        `, [

          name,
          region,
          district,
          school_type,
          form_price !== undefined
            ? Number(form_price)
            : null,
          phone,
          address,
          email,
          application_start,
          application_end,
          status,
          req.params.id

        ]);


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

      console.error(error);

      res.status(500).json({
        success: false,
        message: error.message
      });

    }

  }
);


app.put(
  "/api/admin/schools/:id/status",
  async (req, res) => {

    try {

      const {
        status
      } = req.body;


      const result =
        await pool.query(`

          UPDATE schools

          SET
            status = $1,
            updated_at = CURRENT_TIMESTAMP

          WHERE id = $2

          RETURNING *

        `, [
          status,
          req.params.id
        ]);


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
   APPLICATIONS — CREATE
========================================================= */

app.post(
  "/api/applications",
  async (req, res) => {

    const client =
      await pool.connect();

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
        parent_phone,
        parent_email,

        phone,
        email,

        address

      } = req.body;


      const schoolResult =
        await client.query(
          `
          SELECT *
          FROM schools
          WHERE id = $1
          AND status = 'active'
          `,
          [school_id]
        );


      if (!schoolResult.rows.length) {

        return res.status(404).json({
          success: false,
          message: "Shule haijapatikana."
        });

      }


      const school =
        schoolResult.rows[0];


      const finalStudentName =
        student_name ||
        applicant_name ||
        "";

      const finalGender =
        gender ||
        applicant_gender ||
        null;

      const finalDob =
        date_of_birth ||
        applicant_date_of_birth ||
        null;

      const finalPhone =
        phone ||
        parent_phone ||
        null;

      const finalEmail =
        email ||
        parent_email ||
        null;


      const applicationNumber =
        `SPT-${new Date().getFullYear()}-${Date.now()}-${Math.floor(
          Math.random() * 100
        )}`;


      await client.query("BEGIN");


      const applicationResult =
        await client.query(`

          INSERT INTO applications (

            application_number,
            school_id,
            form_id,

            applicant_name,
            applicant_gender,
            applicant_date_of_birth,

            student_name,
            gender,
            date_of_birth,
            class_level,

            parent_name,
            parent_phone,
            parent_email,

            phone,
            email,

            address,

            status,
            payment_status

          )

          VALUES (

            $1,$2,$3,
            $4,$5,$6,
            $7,$8,$9,$10,
            $11,$12,$13,
            $14,$15,
            $16,
            'pending',
            'unpaid'

          )

          RETURNING *

        `, [

          applicationNumber,
          school_id,
          form_id || null,

          finalStudentName,
          finalGender,
          finalDob,

          finalStudentName,
          finalGender,
          finalDob,
          class_level || null,

          parent_name || null,
          parent_phone || null,
          parent_email || null,

          finalPhone,
          finalEmail,

          address || null

        ]);


      const application =
        applicationResult.rows[0];


      const paymentReference =
        `PAY-${new Date().getFullYear()}-${Date.now()}-${Math.floor(
          Math.random() * 1000
        )}`;


      const paymentResult =
        await client.query(`

          INSERT INTO payments (

            application_id,
            payment_reference,
            amount,
            status

          )

          VALUES ($1,$2,$3,'pending')

          RETURNING *

        `, [

          application.id,
          paymentReference,
          Number(school.form_price || 0)

        ]);


      await client.query("COMMIT");


      res.json({
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

  }
);


/* =========================================================
   GET APPLICATION
========================================================= */

app.get(
  "/api/applications/:id",
  async (req, res) => {

    try {

      const result =
        await pool.query(`

          SELECT

            a.*,

            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,

            p.payment_reference,
            p.amount AS payment_amount,
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

        `, [req.params.id]);


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


/* =========================================================
   APPLICATION BY NUMBER
========================================================= */

app.get(
  "/api/application-by-number/:applicationNumber",
  async (req, res) => {

    try {

      const result =
        await pool.query(`

          SELECT

            a.*,

            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,

            p.payment_reference,
            p.amount AS payment_amount,
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

        `, [
          req.params.applicationNumber
        ]);


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

      console.error(error);

      res.status(500).json({
        success: false,
        message: error.message
      });

    }

  }
);


/* =========================================================
   ADMIN — APPLICATIONS
========================================================= */

app.get(
  "/api/admin/applications",
  async (req, res) => {

    try {

      const result =
        await pool.query(`

          SELECT

            a.*,

            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,

            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_record_status,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN payments p
            ON p.application_id = a.id

          ORDER BY a.created_at DESC

        `);


      res.json({
        success: true,
        applications: result.rows,
        count: result.rows.length
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


/* =========================================================
   ADMIN — DASHBOARD STATS
========================================================= */

app.get(
  "/api/admin/dashboard-stats",
  async (req, res) => {

    try {

      const result =
        await pool.query(`

          SELECT

            COUNT(*)::int AS total_applications,

            COUNT(*) FILTER (
              WHERE status = 'pending'
            )::int AS pending_applications,

            COUNT(*) FILTER (
              WHERE status = 'approved'
            )::int AS approved_applications,

            COUNT(*) FILTER (
              WHERE status = 'rejected'
            )::int AS rejected_applications,

            COUNT(*) FILTER (
              WHERE payment_status = 'paid'
            )::int AS paid_applications,

            COUNT(*) FILTER (
              WHERE payment_status = 'unpaid'
            )::int AS unpaid_applications

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


/* =========================================================
   ADMIN — APPLICATION STATUS
========================================================= */

app.put(
  "/api/admin/applications/:id/status",
  async (req, res) => {

    try {

      const {
        status
      } = req.body;


      const result =
        await pool.query(`

          UPDATE applications

          SET
            status = $1,
            updated_at = CURRENT_TIMESTAMP

          WHERE id = $2

          RETURNING *

        `, [
          status,
          req.params.id
        ]);


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


/* =========================================================
   ADMIN — PAYMENT STATUS
========================================================= */

app.put(
  "/api/admin/applications/:id/payment-status",
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const {
        payment_status
      } = req.body;


      await client.query("BEGIN");


      const applicationResult =
        await client.query(`

          UPDATE applications

          SET

            payment_status = $1,

            updated_at =
              CURRENT_TIMESTAMP

          WHERE id = $2

          RETURNING *

        `, [
          payment_status,
          req.params.id
        ]);


      if (!applicationResult.rows.length) {

        await client.query("ROLLBACK");

        return res.status(404).json({
          success: false,
          message: "Maombi hayajapatikana."
        });

      }


      if (payment_status === "paid") {

        await client.query(`

          UPDATE payments

          SET

            status = 'paid',

            paid_at =
              COALESCE(
                paid_at,
                CURRENT_TIMESTAMP
              ),

            updated_at =
              CURRENT_TIMESTAMP

          WHERE application_id = $1

        `, [
          req.params.id
        ]);

      }


      await client.query("COMMIT");


      res.json({
        success: true,
        application:
          applicationResult.rows[0]
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
   ADMIN — SCHOOL ADMINS
========================================================= */

app.get(
  "/api/admin/school-admins",
  async (req, res) => {

    try {

      const result =
        await pool.query(`

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

            s.name AS school_name

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

      const result =
        await pool.query(`

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

            s.name AS school_name

          FROM school_admins a

          LEFT JOIN schools s
            ON s.id = a.school_id

          WHERE a.id = $1

        `, [
          req.params.id
        ]);


      if (!result.rows.length) {

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
            "School, jina, email na password vinahitajika."
        });

      }


      if (String(password).length < 6) {

        return res.status(400).json({
          success: false,
          message:
            "Password lazima iwe na angalau herufi 6."
        });

      }


      const normalizedEmail =
        normalizeEmail(email);


      const existing =
        await pool.query(`

          SELECT id
          FROM school_admins

          WHERE LOWER(TRIM(email))
            = LOWER(TRIM($1))

          LIMIT 1

        `, [
          normalizedEmail
        ]);


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
        await pool.query(`

          INSERT INTO school_admins (

            school_id,
            full_name,
            phone,
            email,
            password_hash,
            status

          )

          VALUES ($1,$2,$3,$4,$5,$6)

          RETURNING

            id,
            school_id,
            full_name,
            phone,
            email,
            status,
            created_at

        `, [

          school_id,
          full_name,
          phone || null,
          normalizedEmail,
          passwordHash,
          status || "active"

        ]);


      res.json({
        success: true,
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


      const result =
        await pool.query(`

          UPDATE school_admins

          SET

            school_id =
              COALESCE($1, school_id),

            full_name =
              COALESCE($2, full_name),

            phone =
              COALESCE($3, phone),

            email =
              COALESCE($4, email),

            status =
              COALESCE($5, status),

            updated_at =
              CURRENT_TIMESTAMP

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

        `, [

          school_id,
          full_name,
          phone,
          email
            ? normalizeEmail(email)
            : null,
          status,
          req.params.id

        ]);


      if (!result.rows.length) {

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

  }
);


app.put(
  "/api/admin/school-admins/:id/status",
  async (req, res) => {

    try {

      const {
        status
      } = req.body;


      const result =
        await pool.query(`

          UPDATE school_admins

          SET

            status = $1,

            updated_at =
              CURRENT_TIMESTAMP

          WHERE id = $2

          RETURNING

            id,
            full_name,
            email,
            status

        `, [
          status,
          req.params.id
        ]);


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


/* =========================================================
   RESET SCHOOL ADMIN PASSWORD
========================================================= */

app.put(
  "/api/admin/school-admins/:id/reset-password",
  async (req, res) => {

    try {

      const password =
        String(
          req.body.password || ""
        );


      if (password.length < 6) {

        return res.status(400).json({
          success: false,
          message:
            "Password lazima iwe na angalau herufi 6."
        });

      }


      const admin =
        await pool.query(`

          SELECT
            id,
            email

          FROM school_admins

          WHERE id = $1

        `, [
          req.params.id
        ]);


      if (!admin.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hajapatikana."
        });

      }


      const passwordHash =
        await hashPassword(password);


      await pool.query(`

        UPDATE school_admins

        SET

          password_hash = $1,

          updated_at =
            CURRENT_TIMESTAMP

        WHERE id = $2

      `, [
        passwordHash,
        req.params.id
      ]);


      await pool.query(`

        DELETE FROM school_admin_sessions

        WHERE admin_id = $1

      `, [
        req.params.id
      ]);


      const verified =
        await verifyPassword(
          password,
          passwordHash
        );


      if (!verified) {

        return res.status(500).json({
          success: false,
          message:
            "Password haikuthibitishwa baada ya kuhifadhiwa."
        });

      }


      res.json({
        success: true,
        message:
          "Password imebadilishwa kikamilifu. Admin anaweza kuingia sasa.",
        email:
          admin.rows[0].email
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


/* =========================================================
   DELETE SCHOOL ADMIN
========================================================= */

app.delete(
  "/api/admin/school-admins/:id",
  async (req, res) => {

    try {

      await pool.query(`

        DELETE FROM school_admin_sessions

        WHERE admin_id = $1

      `, [
        req.params.id
      ]);


      await pool.query(`

        DELETE FROM school_admins

        WHERE id = $1

      `, [
        req.params.id
      ]);


      res.json({
        success: true,
        message:
          "School Admin amefutwa."
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
   SCHOOL ADMIN LOGIN
========================================================= */

app.post(
  "/api/school-admin/login",
  async (req, res) => {

    try {

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        String(
          req.body.password || ""
        );


      if (!email || !password) {

        return res.status(400).json({
          success: false,
          message:
            "Email na password vinahitajika."
        });

      }


      const result =
        await pool.query(`

          SELECT

            a.id,
            a.school_id,
            a.full_name,
            a.phone,
            a.email,
            a.password_hash,
            a.status,

            s.name AS school_name,
            s.status AS school_status

          FROM school_admins a

          INNER JOIN schools s
            ON s.id = a.school_id

          WHERE LOWER(TRIM(a.email))
            = LOWER(TRIM($1))

          LIMIT 1

        `, [
          email
        ]);


      if (!result.rows.length) {

        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });

      }


      const admin =
        result.rows[0];


      if (
        String(admin.status)
          .toLowerCase()
          !== "active"
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Akaunti hii haijawezeshwa."
        });

      }


      if (
        String(admin.school_status)
          .toLowerCase()
          !== "active"
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Shule hii haijawezeshwa."
        });

      }


      const valid =
        await verifyPassword(
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


      await pool.query(`

        DELETE FROM school_admin_sessions

        WHERE expires_at <= CURRENT_TIMESTAMP

      `);


      const token =
        crypto
          .randomBytes(48)
          .toString("hex");


      const tokenHash =
        hashToken(token);


      await pool.query(`

        INSERT INTO school_admin_sessions (

          admin_id,
          token_hash,
          expires_at

        )

        VALUES (

          $1,
          $2,
          CURRENT_TIMESTAMP
            + INTERVAL '12 hours'

        )

      `, [
        admin.id,
        tokenHash
      ]);


      await pool.query(`

        UPDATE school_admins

        SET

          last_login =
            CURRENT_TIMESTAMP,

          updated_at =
            CURRENT_TIMESTAMP

        WHERE id = $1

      `, [
        admin.id
      ]);


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


      res.json({

        success: true,

        message:
          "Login imefanikiwa.",

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

          school: {

            id:
              admin.school_id,

            name:
              admin.school_name

          }

        }

      });


    } catch (error) {

      console.error(
        "School admin login error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Tatizo limetokea wakati wa login."
      });

    }

  }
);


/* =========================================================
   SCHOOL ADMIN ME
   HII NDIYO ROUTE ILIYOREKEBISHWA
========================================================= */

app.get(
  "/api/school-admin/me",
  async (req, res) => {

    try {

      const token =
        getSchoolAdminToken(req);


      if (!token) {

        return res.status(401).json({
          success: false,
          message:
            "Hujaingia kwenye mfumo."
        });

      }


      const tokenHash =
        hashToken(token);


      const result =
        await pool.query(`

          SELECT

            a.id,
            a.full_name,
            a.email,
            a.phone,
            a.status,
            a.last_login,

            s.id AS school_id,
            s.name AS school_name,
            s.region AS school_region,
            s.district AS school_district,
            s.school_type,
            s.form_price,
            s.phone AS school_phone,
            s.address AS school_address,
            s.email AS school_email,
            s.application_start,
            s.application_end,
            s.status AS school_status

          FROM school_admin_sessions sess

          INNER JOIN school_admins a
            ON a.id = sess.admin_id

          INNER JOIN schools s
            ON s.id = a.school_id

          WHERE sess.token_hash = $1

            AND sess.expires_at >
              CURRENT_TIMESTAMP

            AND a.status = 'active'

            AND s.status = 'active'

          LIMIT 1

        `, [
          tokenHash
        ]);


      if (!result.rows.length) {

        return res.status(401).json({
          success: false,
          message:
            "Session imekwisha au akaunti haipo."
        });

      }


      const row =
        result.rows[0];


      res.json({

        success: true,

        admin: {

          id:
            row.id,

          full_name:
            row.full_name,

          email:
            row.email,

          phone:
            row.phone,

          status:
            row.status,

          last_login:
            row.last_login,

          school: {

            id:
              row.school_id,

            name:
              row.school_name,

            region:
              row.school_region,

            district:
              row.school_district,

            school_type:
              row.school_type,

            form_price:
              row.form_price,

            phone:
              row.school_phone,

            address:
              row.school_address,

            email:
              row.school_email,

            application_start:
              row.application_start,

            application_end:
              row.application_end,

            status:
              row.school_status

          }

        }

      });


    } catch (error) {

      console.error(
        "School admin me error:",
        error
      );

      res.status(500).json({

        success: false,

        message:
          "Imeshindikana kupata taarifa za School Admin."

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
        getSchoolAdminToken(req);


      if (token) {

        const tokenHash =
          hashToken(token);


        await pool.query(`

          DELETE FROM school_admin_sessions

          WHERE token_hash = $1

        `, [
          tokenHash
        ]);

      }


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


      res.json({
        success: true,
        message:
          "Umetoka kwenye mfumo."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kutoka."
      });

    }

  }
);


/* =========================================================
   SCHOOL ADMIN DASHBOARD STATS
========================================================= */

app.get(
  "/api/school-admin/dashboard-stats",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const schoolId =
        req.schoolAdmin.school_id;


      const result =
        await pool.query(`

          SELECT

            COUNT(*)::int
              AS total_applications,

            COUNT(*) FILTER (
              WHERE status = 'pending'
            )::int
              AS pending_applications,

            COUNT(*) FILTER (
              WHERE status = 'approved'
            )::int
              AS approved_applications,

            COUNT(*) FILTER (
              WHERE status = 'rejected'
            )::int
              AS rejected_applications,

            COUNT(*) FILTER (
              WHERE payment_status = 'paid'
            )::int
              AS paid_applications,

            COUNT(*) FILTER (
              WHERE payment_status = 'unpaid'
            )::int
              AS unpaid_applications

          FROM applications

          WHERE school_id = $1

        `, [
          schoolId
        ]);


      res.json({
        success: true,
        stats: result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata takwimu."
      });

    }

  }
);


/* =========================================================
   SCHOOL ADMIN APPLICATIONS
========================================================= */

app.get(
  "/api/school-admin/applications",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const schoolId =
        req.schoolAdmin.school_id;


      const result =
        await pool.query(`

          SELECT

            a.*,

            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,

            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_record_status,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN payments p
            ON p.application_id = a.id

          WHERE a.school_id = $1

          ORDER BY a.created_at DESC

        `, [
          schoolId
        ]);


      res.json({
        success: true,
        applications: result.rows,
        count: result.rows.length
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata maombi."
      });

    }

  }
);


/* =========================================================
   SCHOOL ADMIN SINGLE APPLICATION
========================================================= */

app.get(
  "/api/school-admin/applications/:id",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const schoolId =
        req.schoolAdmin.school_id;


      const result =
        await pool.query(`

          SELECT

            a.*,

            s.name AS school_name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,

            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_record_status,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN payments p
            ON p.application_id = a.id

          WHERE

            a.id = $1

            AND a.school_id = $2

          ORDER BY p.id DESC

          LIMIT 1

        `, [
          req.params.id,
          schoolId
        ]);


      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Maombi hayajapatikana."
        });

      }


      res.json({
        success: true,
        application: result.rows[0]
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


/* =========================================================
   SCHOOL ADMIN UPDATE APPLICATION STATUS
========================================================= */

app.put(
  "/api/school-admin/applications/:id/status",
  requireSchoolAdmin,
  async (req, res) => {

    try {

      const schoolId =
        req.schoolAdmin.school_id;


      const status =
        String(
          req.body.status || ""
        )
        .trim()
        .toLowerCase();


      if (
        ![
          "pending",
          "approved",
          "rejected"
        ].includes(status)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Hali ya maombi si sahihi."
        });

      }


      const result =
        await pool.query(`

          UPDATE applications

          SET

            status = $1,

            updated_at =
              CURRENT_TIMESTAMP

          WHERE

            id = $2

            AND school_id = $3

          RETURNING *

        `, [

          status,
          req.params.id,
          schoolId

        ]);


      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Maombi hayajapatikana kwenye shule yako."
        });

      }


      res.json({

        success: true,

        message:
          status === "approved"
            ? "Maombi yamekubaliwa."
            : status === "rejected"
              ? "Maombi yamekataliwa."
              : "Hali ya maombi imebadilishwa.",

        application:
          result.rows[0]

      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kubadilisha hali ya maombi."
      });

    }

  }
);


/* =========================================================
   404 API
========================================================= */

app.use(
  "/api",
  (req, res) => {

    res.status(404).json({

      success: false,

      message:
        "API endpoint haijapatikana."

    });

  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "Unhandled error:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({

      success: false,

      message:
        "Server error imetokea."

    });

  }
);


/* =========================================================
   START SERVER
========================================================= */

async function startServer() {

  try {

    console.log(
      "⏳ Inaanzisha database..."
    );


    await setupDatabase();


    console.log(
      "✅ Database iko tayari."
    );


    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `🚀 Shule Portal Tanzania inaendesha kwenye port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      "❌ Server startup error:",
      error
    );

    process.exit(1);

  }

}


startServer();