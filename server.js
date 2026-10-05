const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));


// =====================================================
// DATABASE SETUP
// =====================================================

async function setupDatabase() {
  try {

    // -------------------------------------------------
    // SCHOOLS TABLE
    // -------------------------------------------------

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

    const schoolColumns = [
      ["name", "VARCHAR(255)"],
      ["region", "VARCHAR(100)"],
      ["district", "VARCHAR(100)"],
      ["school_type", "VARCHAR(100)"],
      ["form_price", "NUMERIC(12,2) DEFAULT 0"],
      ["phone", "VARCHAR(50)"],
      ["address", "TEXT"],
      ["email", "VARCHAR(255)"],
      ["application_start", "TIMESTAMP NULL"],
      ["application_end", "TIMESTAMP NULL"],
      ["status", "VARCHAR(30) DEFAULT 'active'"],
      ["created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"],
      ["updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"]
    ];

    for (const [column, type] of schoolColumns) {
      await pool.query(`
        ALTER TABLE schools
        ADD COLUMN IF NOT EXISTS ${column} ${type}
      `);
    }

    await pool.query(`
      UPDATE schools
      SET status = 'active'
      WHERE status IS NULL
    `);


    // -------------------------------------------------
    // APPLICATIONS TABLE
    // -------------------------------------------------

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
      ["application_number", "VARCHAR(100)"],
      ["school_id", "INTEGER"],
      ["form_id", "INTEGER"],
      ["applicant_name", "VARCHAR(255)"],
      ["applicant_gender", "VARCHAR(50)"],
      ["applicant_date_of_birth", "DATE"],
      ["parent_name", "VARCHAR(255)"],
      ["parent_phone", "VARCHAR(50)"],
      ["parent_email", "VARCHAR(255)"],
      ["address", "TEXT"],
      ["status", "VARCHAR(50)"],
      ["payment_status", "VARCHAR(50)"],
      ["created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"],
      ["updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"],
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
      UPDATE applications
      SET status = 'pending'
      WHERE status IS NULL
    `);

    await pool.query(`
      UPDATE applications
      SET payment_status = 'unpaid'
      WHERE payment_status IS NULL
    `);


    // -------------------------------------------------
    // PAYMENTS TABLE
    // -------------------------------------------------

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

    const paymentColumns = [
      ["application_id", "INTEGER"],
      ["payment_reference", "VARCHAR(100)"],
      ["amount", "NUMERIC(12,2)"],
      ["status", "VARCHAR(50)"],
      ["provider", "VARCHAR(100)"],
      ["provider_reference", "VARCHAR(255)"],
      ["paid_at", "TIMESTAMP"],
      ["created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"],
      ["updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"]
    ];

    for (const [column, type] of paymentColumns) {
      await pool.query(`
        ALTER TABLE payments
        ADD COLUMN IF NOT EXISTS ${column} ${type}
      `);
    }

    await pool.query(`
      UPDATE payments
      SET status = 'pending'
      WHERE status IS NULL
    `);


    // -------------------------------------------------
    // SCHOOL ADMINS TABLE
    // -------------------------------------------------

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

    const schoolAdminColumns = [
      ["school_id", "INTEGER"],
      ["full_name", "VARCHAR(255)"],
      ["phone", "VARCHAR(50)"],
      ["email", "VARCHAR(255)"],
      ["password_hash", "TEXT"],
      ["status", "VARCHAR(30) DEFAULT 'active'"],
      ["last_login", "TIMESTAMP NULL"],
      ["created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"],
      ["updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"]
    ];

    for (const [column, type] of schoolAdminColumns) {
      await pool.query(`
        ALTER TABLE school_admins
        ADD COLUMN IF NOT EXISTS ${column} ${type}
      `);
    }

    await pool.query(`
      UPDATE school_admins
      SET status = 'active'
      WHERE status IS NULL
    `);


    // -------------------------------------------------
    // SCHOOL ADMIN SESSIONS TABLE
    // -------------------------------------------------

    await pool.query(`
      CREATE TABLE IF NOT EXISTS school_admin_sessions (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER NOT NULL,
        token_hash VARCHAR(128) NOT NULL UNIQUE,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);


    // -------------------------------------------------
    // INDEXES
    // -------------------------------------------------

    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
      applications_application_number_unique
      ON applications(application_number)
      WHERE application_number IS NOT NULL
    `);

    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
      payments_payment_reference_unique
      ON payments(payment_reference)
      WHERE payment_reference IS NOT NULL
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS schools_status_idx
      ON schools(status)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS schools_region_idx
      ON schools(region)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS applications_school_id_idx
      ON applications(school_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS school_admins_school_id_idx
      ON school_admins(school_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS school_admins_status_idx
      ON school_admins(status)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS school_admins_email_idx
      ON school_admins(email)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS
      school_admin_sessions_admin_id_idx
      ON school_admin_sessions(admin_id)
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS
      school_admin_sessions_expires_at_idx
      ON school_admin_sessions(expires_at)
    `);

    console.log("✅ Database setup completed");

  } catch (error) {

    console.error(
      "❌ Database setup error:",
      error
    );

    throw error;

  }
}


// =====================================================
// HOME
// =====================================================

app.get("/", (req, res) => {

  res.sendFile(
    __dirname + "/index.html"
  );

});


// =====================================================
// SYSTEM STATUS
// =====================================================

app.get(
  "/api/status",
  async (req, res) => {

    try {

      await pool.query("SELECT 1");

      res.json({
        success: true,
        message:
          "Shule Portal Tanzania iko online.",
        database: "connected",
        timestamp:
          new Date().toISOString()
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          "Database connection failed.",
        error: error.message
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

      res.json({
        success: true,
        schools: result.rows,
        count: result.rows.length
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata shule.",
        error: error.message
      });

    }

  }
);


// =====================================================
// DATABASE CHECK
// =====================================================

app.get(
  "/api/database-check",
  async (req, res) => {

    try {

      const result = await pool.query(`
        SELECT
          current_database() AS database,
          NOW() AS server_time
      `);

      res.json({
        success: true,
        message:
          "Database imeunganishwa.",
        data: result.rows[0]
      });

    } catch (error) {

      res.status(500).json({
        success: false,
        message:
          "Database haijaunganishwa bado.",
        error: error.message
      });

    }

  }
);


// =====================================================
// APPLICATION SCHEMA
// =====================================================

app.get(
  "/api/application-schema",
  async (req, res) => {

    try {

      const result = await pool.query(`
        SELECT
          column_name,
          data_type,
          is_nullable

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

  }
);


// =====================================================
// PAYMENT SCHEMA
// =====================================================

app.get(
  "/api/payment-schema",
  async (req, res) => {

    try {

      const result = await pool.query(`
        SELECT
          column_name,
          data_type,
          is_nullable

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

  }
);


// =====================================================
// ADMIN — SCHOOLS
// =====================================================


// -----------------------------------------------------
// GET ALL SCHOOLS
// -----------------------------------------------------

app.get(
  "/api/admin/schools",
  async (req, res) => {

    try {

      const {
        search = "",
        status = "",
        region = ""
      } = req.query;

      const values = [];
      const conditions = [];

      if (search.trim()) {

        values.push(
          `%${search.trim()}%`
        );

        conditions.push(`
          (
            s.name ILIKE $${values.length}
            OR s.region ILIKE $${values.length}
            OR s.district ILIKE $${values.length}
            OR s.school_type ILIKE $${values.length}
            OR s.phone ILIKE $${values.length}
            OR s.email ILIKE $${values.length}
          )
        `);

      }

      if (
        status &&
        ["active", "inactive"]
          .includes(status)
      ) {

        values.push(status);

        conditions.push(
          `s.status = $${values.length}`
        );

      }

      if (region.trim()) {

        values.push(region.trim());

        conditions.push(
          `s.region = $${values.length}`
        );

      }

      const whereClause =
        conditions.length
          ? `WHERE ${conditions.join(" AND ")}`
          : "";

      const schoolsResult =
        await pool.query(`
          SELECT
            s.id,
            s.name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,
            s.phone,
            s.address,
            s.email,
            s.application_start,
            s.application_end,
            s.status,
            s.created_at,
            s.updated_at,

            COUNT(a.id)::INTEGER
              AS application_count

          FROM schools s

          LEFT JOIN applications a
            ON a.school_id = s.id

          ${whereClause}

          GROUP BY s.id

          ORDER BY s.id DESC
        `, values);

      const statsResult =
        await pool.query(`
          SELECT
            COUNT(*)::INTEGER
              AS total_schools,

            COUNT(*) FILTER (
              WHERE status = 'active'
            )::INTEGER
              AS active_schools,

            COUNT(*) FILTER (
              WHERE status = 'inactive'
            )::INTEGER
              AS inactive_schools

          FROM schools
        `);

      const applicantsResult =
        await pool.query(`
          SELECT
            COUNT(*)::INTEGER
              AS total_applicants

          FROM applications
        `);

      const regionsResult =
        await pool.query(`
          SELECT DISTINCT region

          FROM schools

          WHERE region IS NOT NULL
            AND TRIM(region) <> ''

          ORDER BY region ASC
        `);

      const stats =
        statsResult.rows[0];

      res.json({
        success: true,
        schools:
          schoolsResult.rows,
        count:
          schoolsResult.rows.length,
        total_schools:
          Number(
            stats.total_schools || 0
          ),
        active_schools:
          Number(
            stats.active_schools || 0
          ),
        inactive_schools:
          Number(
            stats.inactive_schools || 0
          ),
        total_applicants:
          Number(
            applicantsResult.rows[0]
              .total_applicants || 0
          ),
        all_regions:
          regionsResult.rows
            .map(row => row.region)
            .filter(Boolean)
      });

    } catch (error) {

      console.error(
        "GET /api/admin/schools error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata orodha ya shule.",
        error: error.message
      });

    }

  }
);


// -----------------------------------------------------
// GET ONE SCHOOL
// -----------------------------------------------------

app.get(
  "/api/admin/schools/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "School ID si sahihi."
        });

      }

      const result =
        await pool.query(`
          SELECT
            s.id,
            s.name,
            s.region,
            s.district,
            s.school_type,
            s.form_price,
            s.phone,
            s.address,
            s.email,
            s.application_start,
            s.application_end,
            s.status,
            s.created_at,
            s.updated_at,

            COUNT(a.id)::INTEGER
              AS application_count

          FROM schools s

          LEFT JOIN applications a
            ON a.school_id = s.id

          WHERE s.id = $1

          GROUP BY s.id
        `, [id]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haijapatikana."
        });

      }

      res.json({
        success: true,
        school:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata taarifa za shule.",
        error: error.message
      });

    }

  }
);


// -----------------------------------------------------
// ADD SCHOOL
// -----------------------------------------------------

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
        email,
        address,
        application_start,
        application_end,
        status
      } = req.body;

      if (!name || !name.trim()) {

        return res.status(400).json({
          success: false,
          message:
            "Jina la shule linahitajika."
        });

      }

      if (!region || !region.trim()) {

        return res.status(400).json({
          success: false,
          message:
            "Mkoa unahitajika."
        });

      }

      if (!district || !district.trim()) {

        return res.status(400).json({
          success: false,
          message:
            "Wilaya inahitajika."
        });

      }

      if (
        !school_type ||
        !school_type.trim()
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Aina ya shule inahitajika."
        });

      }

      const price =
        Number(form_price);

      if (
        !Number.isFinite(price) ||
        price < 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Bei ya fomu si sahihi."
        });

      }

      const finalStatus =
        ["active", "inactive"]
          .includes(status)
          ? status
          : "active";

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

      const result =
        await pool.query(`
          INSERT INTO schools (
            name,
            region,
            district,
            school_type,
            form_price,
            phone,
            email,
            address,
            application_start,
            application_end,
            status,
            created_at,
            updated_at
          )

          VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            $11, NOW(), NOW()
          )

          RETURNING *
        `, [
          name.trim(),
          region.trim(),
          district.trim(),
          school_type.trim(),
          price,
          phone
            ? phone.trim()
            : null,
          email
            ? email.trim()
            : null,
          address
            ? address.trim()
            : null,
          application_start || null,
          application_end || null,
          finalStatus
        ]);

      res.status(201).json({
        success: true,
        message:
          "Shule imeongezwa kikamilifu.",
        school:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "POST /api/admin/schools error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuongeza shule.",
        error: error.message
      });

    }

  }
);


// -----------------------------------------------------
// UPDATE SCHOOL
// -----------------------------------------------------

app.put(
  "/api/admin/schools/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "School ID si sahihi."
        });

      }

      const {
        name,
        region,
        district,
        school_type,
        form_price,
        phone,
        email,
        address,
        application_start,
        application_end,
        status
      } = req.body;

      if (!name || !name.trim()) {

        return res.status(400).json({
          success: false,
          message:
            "Jina la shule linahitajika."
        });

      }

      if (!region || !region.trim()) {

        return res.status(400).json({
          success: false,
          message:
            "Mkoa unahitajika."
        });

      }

      if (!district || !district.trim()) {

        return res.status(400).json({
          success: false,
          message:
            "Wilaya inahitajika."
        });

      }

      const price =
        Number(form_price);

      if (
        !Number.isFinite(price) ||
        price < 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Bei ya fomu si sahihi."
        });

      }

      const finalStatus =
        ["active", "inactive"]
          .includes(status)
          ? status
          : "active";

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

      const result =
        await pool.query(`
          UPDATE schools

          SET
            name = $1,
            region = $2,
            district = $3,
            school_type = $4,
            form_price = $5,
            phone = $6,
            email = $7,
            address = $8,
            application_start = $9,
            application_end = $10,
            status = $11,
            updated_at = NOW()

          WHERE id = $12

          RETURNING *
        `, [
          name.trim(),
          region.trim(),
          district.trim(),
          school_type
            ? school_type.trim()
            : null,
          price,
          phone
            ? phone.trim()
            : null,
          email
            ? email.trim()
            : null,
          address
            ? address.trim()
            : null,
          application_start || null,
          application_end || null,
          finalStatus,
          id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haijapatikana."
        });

      }

      res.json({
        success: true,
        message:
          "Shule imehaririwa kikamilifu.",
        school:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "PUT /api/admin/schools/:id error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuhariri shule.",
        error: error.message
      });

    }

  }
);


// -----------------------------------------------------
// CHANGE SCHOOL STATUS
// -----------------------------------------------------

app.put(
  "/api/admin/schools/:id/status",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const { status } =
        req.body;

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "School ID si sahihi."
        });

      }

      if (
        !["active", "inactive"]
          .includes(status)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Status lazima iwe active au inactive."
        });

      }

      const result =
        await pool.query(`
          UPDATE schools

          SET
            status = $1,
            updated_at = NOW()

          WHERE id = $2

          RETURNING *
        `, [
          status,
          id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haijapatikana."
        });

      }

      res.json({
        success: true,
        message:
          status === "active"
            ? "Shule imewashwa."
            : "Shule imezimwa.",
        school:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kubadilisha hali ya shule.",
        error: error.message
      });

    }

  }
);


// -----------------------------------------------------
// DELETE SCHOOL
// -----------------------------------------------------

app.delete(
  "/api/admin/schools/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "School ID si sahihi."
        });

      }

      const applicationsResult =
        await pool.query(`
          SELECT
            COUNT(*)::INTEGER AS count

          FROM applications

          WHERE school_id = $1
        `, [id]);

      const applicationCount =
        Number(
          applicationsResult.rows[0]
            .count || 0
        );

      if (applicationCount > 0) {

        const result =
          await pool.query(`
            UPDATE schools

            SET
              status = 'inactive',
              updated_at = NOW()

            WHERE id = $1

            RETURNING *
          `, [id]);

        if (!result.rows.length) {

          return res.status(404).json({
            success: false,
            message:
              "Shule haijapatikana."
          });

        }

        return res.json({
          success: true,
          message:
            `Shule ina maombi ${applicationCount}. ` +
            "Haijafutwa kabisa; imewekwa INACTIVE ili kulinda historia ya maombi.",
          soft_deleted: true,
          school:
            result.rows[0]
        });

      }

      const result =
        await pool.query(`
          DELETE FROM schools

          WHERE id = $1

          RETURNING *
        `, [id]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haijapatikana."
        });

      }

      res.json({
        success: true,
        message:
          "Shule imefutwa kikamilifu.",
        soft_deleted: false,
        school:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kufuta shule.",
        error: error.message
      });

    }

  }
);


// =====================================================
// APPLICATIONS
// =====================================================


// -----------------------------------------------------
// CREATE APPLICATION
// -----------------------------------------------------

app.post(
  "/api/applications",
  async (req, res) => {

    const client =
      await pool.connect();

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
        address,
        student_name,
        gender,
        date_of_birth,
        class_level,
        phone,
        email
      } = req.body;

      if (!school_id) {

        return res.status(400).json({
          success: false,
          message:
            "School ID inahitajika."
        });

      }

      const schoolResult =
        await client.query(`
          SELECT *

          FROM schools

          WHERE id = $1
            AND status = 'active'
        `, [school_id]);

      if (!schoolResult.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani au haipo active."
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

      const finalDOB =
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

      if (!finalStudentName.trim()) {

        return res.status(400).json({
          success: false,
          message:
            "Jina la mwanafunzi linahitajika."
        });

      }

      const applicationNumber =
        `SPT-${new Date().getFullYear()}-` +
        `${Date.now()}-` +
        `${Math.floor(
          Math.random() * 90
        ) + 10}`;

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
            created_at,
            updated_at
          )

          VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            'pending', 'unpaid',
            $11, $12, $13, $14,
            $15, $16,
            NOW(), NOW()
          )

          RETURNING *
        `, [
          applicationNumber,
          school_id,
          form_id || null,
          applicant_name ||
            finalStudentName,
          applicant_gender ||
            finalGender,
          applicant_date_of_birth ||
            finalDOB,
          parent_name || null,
          parent_phone ||
            finalPhone,
          parent_email ||
            finalEmail,
          address || null,
          finalStudentName,
          finalGender,
          finalDOB,
          class_level || null,
          finalPhone,
          finalEmail
        ]);

      const application =
        applicationResult.rows[0];

      const paymentReference =
        `PAY-${new Date().getFullYear()}-` +
        `${Date.now()}-` +
        `${Math.floor(
          Math.random() * 900
        ) + 100}`;

      const paymentResult =
        await client.query(`
          INSERT INTO payments (
            application_id,
            payment_reference,
            amount,
            status,
            provider,
            created_at,
            updated_at
          )

          VALUES (
            $1,
            $2,
            $3,
            'pending',
            'manual',
            NOW(),
            NOW()
          )

          RETURNING *
        `, [
          application.id,
          paymentReference,
          school.form_price
        ]);

      await client.query("COMMIT");

      res.status(201).json({
        success: true,
        message:
          "Maombi yamepokelewa.",
        application,
        payment:
          paymentResult.rows[0]
      });

    } catch (error) {

      await client.query("ROLLBACK");

      console.error(
        "POST /api/applications error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kutengeneza maombi.",
        error: error.message
      });

    } finally {

      client.release();

    }

  }
);


// -----------------------------------------------------
// GET APPLICATION BY ID
// -----------------------------------------------------

app.get(
  "/api/applications/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

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
            p.status AS payment_current_status,
            p.provider,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments p
            WHERE p.application_id = a.id
            ORDER BY p.id DESC
            LIMIT 1
          ) p ON TRUE

          WHERE a.id = $1
        `, [id]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Application haijapatikana."
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
        message: error.message
      });

    }

  }
);


// -----------------------------------------------------
// GET APPLICATION BY NUMBER
// -----------------------------------------------------

app.get(
  "/api/application-by-number/:applicationNumber",
  async (req, res) => {

    try {

      const applicationNumber =
        req.params.applicationNumber;

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
            p.status AS payment_current_status,
            p.provider,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments p
            WHERE p.application_id = a.id
            ORDER BY p.id DESC
            LIMIT 1
          ) p ON TRUE

          WHERE a.application_number = $1
        `, [applicationNumber]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Namba ya maombi haijapatikana."
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
        message: error.message
      });

    }

  }
);


// =====================================================
// ADMIN — APPLICATIONS
// =====================================================


// -----------------------------------------------------
// GET ADMIN APPLICATIONS
// -----------------------------------------------------

app.get(
  "/api/admin/applications",
  async (req, res) => {

    try {

      const {
        search = "",
        school_id = "",
        status = "",
        payment_status = ""
      } = req.query;

      const values = [];
      const conditions = [];

      if (search.trim()) {

        values.push(
          `%${search.trim()}%`
        );

        conditions.push(`
          (
            a.application_number
              ILIKE $${values.length}

            OR a.student_name
              ILIKE $${values.length}

            OR a.applicant_name
              ILIKE $${values.length}

            OR a.parent_name
              ILIKE $${values.length}

            OR a.phone
              ILIKE $${values.length}

            OR a.parent_phone
              ILIKE $${values.length}
          )
        `);

      }

      if (school_id) {

        values.push(
          Number(school_id)
        );

        conditions.push(
          `a.school_id = $${values.length}`
        );

      }

      if (status) {

        values.push(status);

        conditions.push(
          `a.status = $${values.length}`
        );

      }

      if (payment_status) {

        values.push(payment_status);

        conditions.push(`
          COALESCE(
            p.status,
            a.payment_status,
            'unpaid'
          ) = $${values.length}
        `);

      }

      const whereClause =
        conditions.length
          ? `WHERE ${conditions.join(" AND ")}`
          : "";

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
            p.status AS payment_current_status,
            p.provider,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments p
            WHERE p.application_id = a.id
            ORDER BY p.id DESC
            LIMIT 1
          ) p ON TRUE

          ${whereClause}

          ORDER BY a.id DESC
        `, values);

      res.json({
        success: true,
        applications:
          result.rows,
        count:
          result.rows.length
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata applications.",
        error: error.message
      });

    }

  }
);


// -----------------------------------------------------
// ADMIN DASHBOARD STATS
// -----------------------------------------------------

app.get(
  "/api/admin/dashboard-stats",
  async (req, res) => {

    try {

      const result =
        await pool.query(`
          SELECT

            (
              SELECT COUNT(*)
              FROM applications
            )::INTEGER
              AS total_applications,

            (
              SELECT COUNT(*)
              FROM applications
              WHERE status = 'pending'
            )::INTEGER
              AS pending_applications,

            (
              SELECT COUNT(*)
              FROM applications
              WHERE status = 'approved'
            )::INTEGER
              AS approved_applications,

            (
              SELECT COUNT(*)
              FROM applications
              WHERE status = 'rejected'
            )::INTEGER
              AS rejected_applications,

            (
              SELECT COUNT(*)
              FROM applications
              WHERE payment_status = 'paid'
            )::INTEGER
              AS paid_applications,

            (
              SELECT COUNT(*)
              FROM applications
              WHERE payment_status <> 'paid'
                 OR payment_status IS NULL
            )::INTEGER
              AS unpaid_applications,

            (
              SELECT COUNT(*)
              FROM schools
              WHERE status = 'active'
            )::INTEGER
              AS active_schools,

            (
              SELECT COALESCE(
                SUM(amount),
                0
              )
              FROM payments
              WHERE status = 'paid'
            ) AS total_revenue
        `);

      res.json({
        success: true,
        stats:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          error.message
      });

    }

  }
);


// -----------------------------------------------------
// UPDATE APPLICATION STATUS
// -----------------------------------------------------

app.put(
  "/api/admin/applications/:id/status",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const { status } =
        req.body;

      const allowedStatuses = [
        "pending",
        "approved",
        "rejected",
        "processing",
        "completed"
      ];

      if (
        !allowedStatuses.includes(status)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Application status si sahihi."
        });

      }

      const result =
        await pool.query(`
          UPDATE applications

          SET
            status = $1,
            updated_at = NOW()

          WHERE id = $2

          RETURNING *
        `, [
          status,
          id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Application haijapatikana."
        });

      }

      res.json({
        success: true,
        message:
          "Hali ya application imebadilishwa.",
        application:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          error.message
      });

    }

  }
);


// -----------------------------------------------------
// UPDATE PAYMENT STATUS
// -----------------------------------------------------

app.put(
  "/api/admin/applications/:id/payment-status",
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const id =
        Number(req.params.id);

      const { payment_status } =
        req.body;

      const allowedStatuses = [
        "unpaid",
        "pending",
        "paid",
        "failed",
        "cancelled"
      ];

      if (
        !allowedStatuses.includes(
          payment_status
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Payment status si sahihi."
        });

      }

      await client.query("BEGIN");

      const applicationResult =
        await client.query(`
          UPDATE applications

          SET
            payment_status = $1,
            updated_at = NOW()

          WHERE id = $2

          RETURNING *
        `, [
          payment_status,
          id
        ]);

      if (
        !applicationResult.rows.length
      ) {

        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          success: false,
          message:
            "Application haijapatikana."
        });

      }

      const paidAt =
        payment_status === "paid"
          ? new Date()
          : null;

      const paymentResult =
        await client.query(`
          UPDATE payments

          SET
            status = $1,
            paid_at = $2,
            updated_at = NOW()

          WHERE id = (
            SELECT id
            FROM payments
            WHERE application_id = $3
            ORDER BY id DESC
            LIMIT 1
          )

          RETURNING *
        `, [
          payment_status,
          paidAt,
          id
        ]);

      await client.query("COMMIT");

      res.json({
        success: true,
        message:
          "Hali ya malipo imebadilishwa.",
        application:
          applicationResult.rows[0],
        payment:
          paymentResult.rows[0] || null
      });

    } catch (error) {

      await client.query(
        "ROLLBACK"
      );

      console.error(error);

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


// =====================================================
// SCHOOL ADMIN
// =====================================================


// -----------------------------------------------------
// PASSWORD HASHING
// -----------------------------------------------------

function hashPassword(password) {

  return new Promise(
    (resolve, reject) => {

      const salt =
        crypto.randomBytes(16)
          .toString("hex");

      crypto.scrypt(
        password,
        salt,
        64,
        (error, derivedKey) => {

          if (error) {
            return reject(error);
          }

          resolve(
            `${salt}:${derivedKey.toString("hex")}`
          );

        }
      );

    }
  );

}


// -----------------------------------------------------
// VERIFY PASSWORD
// -----------------------------------------------------

function verifyPassword(
  password,
  storedHash
) {

  return new Promise(
    (resolve, reject) => {

      try {

        if (
          !storedHash ||
          !storedHash.includes(":")
        ) {

          return resolve(false);

        }

        const [
          salt,
          key
        ] =
          storedHash.split(":");

        crypto.scrypt(
          password,
          salt,
          64,
          (error, derivedKey) => {

            if (error) {
              return reject(error);
            }

            const storedKey =
              Buffer.from(
                key,
                "hex"
              );

            if (
              storedKey.length !==
              derivedKey.length
            ) {

              return resolve(false);

            }

            const valid =
              crypto.timingSafeEqual(
                storedKey,
                derivedKey
              );

            resolve(valid);

          }
        );

      } catch (error) {

        reject(error);

      }

    }
  );

}


// -----------------------------------------------------
// CREATE AUTH TOKEN
// -----------------------------------------------------

function createAuthToken() {

  return crypto
    .randomBytes(48)
    .toString("hex");

}


// -----------------------------------------------------
// HASH AUTH TOKEN
// -----------------------------------------------------

function hashAuthToken(token) {

  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");

}


// -----------------------------------------------------
// GET COOKIE
// -----------------------------------------------------

function getCookie(
  req,
  name
) {

  const cookieHeader =
    req.headers.cookie || "";

  const cookies =
    cookieHeader
      .split(";")
      .map(
        cookie =>
          cookie.trim()
      );

  for (
    const cookie of cookies
  ) {

    const separator =
      cookie.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const key =
      cookie.substring(
        0,
        separator
      );

    const value =
      cookie.substring(
        separator + 1
      );

    if (key === name) {

      return decodeURIComponent(
        value
      );

    }

  }

  return null;

}


// -----------------------------------------------------
// GET CURRENT SCHOOL ADMIN
// -----------------------------------------------------

async function getSchoolAdminFromRequest(
  req
) {

  const token =
    getCookie(
      req,
      "school_admin_token"
    );

  if (!token) {
    return null;
  }

  const tokenHash =
    hashAuthToken(token);

  const result =
    await pool.query(`
      SELECT
        sa.id,
        sa.school_id,
        sa.full_name,
        sa.phone,
        sa.email,
        sa.status,
        sa.last_login,

        s.name AS school_name,
        s.region AS school_region,
        s.district AS school_district,
        s.school_type,
        s.form_price

      FROM school_admin_sessions sas

      INNER JOIN school_admins sa
        ON sa.id = sas.admin_id

      INNER JOIN schools s
        ON s.id = sa.school_id

      WHERE sas.token_hash = $1
        AND sas.expires_at > NOW()
        AND sa.status = 'active'
        AND s.status = 'active'

      LIMIT 1
    `, [tokenHash]);

  if (!result.rows.length) {
    return null;
  }

  return result.rows[0];

}


// =====================================================
// SCHOOL ADMIN LOGIN
// =====================================================

app.post(
  "/api/school-admin/login",
  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body;

      if (
        !email ||
        !email.trim()
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Email inahitajika."
        });

      }

      if (!password) {

        return res.status(400).json({
          success: false,
          message:
            "Password inahitajika."
        });

      }

      const result =
        await pool.query(`
          SELECT
            sa.*,

            s.name AS school_name,
            s.region AS school_region,
            s.district AS school_district,
            s.school_type,
            s.form_price,
            s.status AS school_status

          FROM school_admins sa

          INNER JOIN schools s
            ON s.id = sa.school_id

          WHERE LOWER(sa.email)
            = LOWER($1)

          LIMIT 1
        `, [
          email.trim()
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
        admin.status !== "active"
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Akaunti yako ya School Admin imezimwa."
        });

      }

      if (
        admin.school_status !== "active"
      ) {

        return res.status(403).json({
          success: false,
          message:
            "Shule yako haipo active kwa sasa."
        });

      }

      const passwordValid =
        await verifyPassword(
          password,
          admin.password_hash
        );

      if (!passwordValid) {

        return res.status(401).json({
          success: false,
          message:
            "Email au password si sahihi."
        });

      }

      const token =
        createAuthToken();

      const tokenHash =
        hashAuthToken(token);

      // Session ya saa 12
      const expiresAt =
        new Date(
          Date.now() +
          12 * 60 * 60 * 1000
        );

      // Ondoa session ya zamani
      await pool.query(`
        DELETE FROM school_admin_sessions

        WHERE admin_id = $1
      `, [
        admin.id
      ]);

      // Tengeneza session mpya
      await pool.query(`
        INSERT INTO school_admin_sessions (
          admin_id,
          token_hash,
          expires_at
        )

        VALUES (
          $1,
          $2,
          $3
        )
      `, [
        admin.id,
        tokenHash,
        expiresAt
      ]);

      await pool.query(`
        UPDATE school_admins

        SET
          last_login = NOW(),
          updated_at = NOW()

        WHERE id = $1
      `, [
        admin.id
      ]);

      res.setHeader(
        "Set-Cookie",
        `school_admin_token=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`
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
          phone:
            admin.phone,
          email:
            admin.email,
          status:
            admin.status,
          school_name:
            admin.school_name,
          school_region:
            admin.school_region,
          school_district:
            admin.school_district,
          school_type:
            admin.school_type,
          form_price:
            admin.form_price
        }
      });

    } catch (error) {

      console.error(
        "SCHOOL ADMIN LOGIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuingia.",
        error: error.message
      });

    }

  }
);


// =====================================================
// SCHOOL ADMIN — CURRENT USER
// =====================================================

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
            "Hujaingia au session imekwisha."
        });

      }

      res.json({
        success: true,
        admin
      });

    } catch (error) {

      console.error(
        "SCHOOL ADMIN ME ERROR:",
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


// =====================================================
// SCHOOL ADMIN — LOGOUT
// =====================================================

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
          hashAuthToken(token);

        await pool.query(`
          DELETE FROM school_admin_sessions

          WHERE token_hash = $1
        `, [
          tokenHash
        ]);

      }

      res.setHeader(
        "Set-Cookie",
        "school_admin_token=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0"
      );

      res.json({
        success: true,
        message:
          "Umetoka kwenye mfumo."
      });

    } catch (error) {

      console.error(
        "SCHOOL ADMIN LOGOUT ERROR:",
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


// =====================================================
// SCHOOL ADMIN — DASHBOARD STATS
// =====================================================

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
          message:
            "Hujaingia kama School Admin."
        });

      }

      const result =
        await pool.query(`
          SELECT

            COUNT(*)::INTEGER
              AS total_applications,

            COUNT(*) FILTER (
              WHERE status = 'pending'
            )::INTEGER
              AS pending_applications,

            COUNT(*) FILTER (
              WHERE status = 'approved'
            )::INTEGER
              AS approved_applications,

            COUNT(*) FILTER (
              WHERE status = 'rejected'
            )::INTEGER
              AS rejected_applications,

            COUNT(*) FILTER (
              WHERE payment_status = 'paid'
            )::INTEGER
              AS paid_applications,

            COUNT(*) FILTER (
              WHERE payment_status <> 'paid'
                 OR payment_status IS NULL
            )::INTEGER
              AS unpaid_applications

          FROM applications

          WHERE school_id = $1
        `, [
          admin.school_id
        ]);

      res.json({
        success: true,

        school: {
          id:
            admin.school_id,
          name:
            admin.school_name,
          region:
            admin.school_region,
          district:
            admin.school_district
        },

        stats:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "SCHOOL ADMIN STATS ERROR:",
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


// =====================================================
// SCHOOL ADMIN — APPLICATIONS
// =====================================================

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
          message:
            "Hujaingia kama School Admin."
        });

      }

      const result =
        await pool.query(`
          SELECT
            a.id,
            a.application_number,
            a.school_id,

            a.student_name,
            a.gender,
            a.date_of_birth,
            a.class_level,

            a.parent_name,
            a.phone,
            a.email,
            a.address,

            a.status,
            a.payment_status,

            a.created_at,
            a.updated_at,

            p.payment_reference,
            p.amount AS payment_amount,
            p.status AS payment_current_status,
            p.provider_reference,
            p.paid_at

          FROM applications a

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments p
            WHERE p.application_id = a.id
            ORDER BY p.id DESC
            LIMIT 1
          ) p ON TRUE

          WHERE a.school_id = $1

          ORDER BY a.id DESC
        `, [
          admin.school_id
        ]);

      res.json({
        success: true,

        school: {
          id:
            admin.school_id,
          name:
            admin.school_name,
          region:
            admin.school_region,
          district:
            admin.school_district
        },

        applications:
          result.rows,

        count:
          result.rows.length
      });

    } catch (error) {

      console.error(
        "SCHOOL ADMIN APPLICATIONS ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata maombi.",
        error: error.message
      });

    }

  }
);


// =====================================================
// SCHOOL ADMIN — ONE APPLICATION
// =====================================================

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
          message:
            "Hujaingia kama School Admin."
        });

      }

      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "Application ID si sahihi."
        });

      }

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
            p.status AS payment_current_status,
            p.provider,
            p.provider_reference,
            p.paid_at

          FROM applications a

          INNER JOIN schools s
            ON s.id = a.school_id

          LEFT JOIN LATERAL (
            SELECT *
            FROM payments p
            WHERE p.application_id = a.id
            ORDER BY p.id DESC
            LIMIT 1
          ) p ON TRUE

          WHERE a.id = $1
            AND a.school_id = $2
        `, [
          id,
          admin.school_id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Application haijapatikana kwenye shule yako."
        });

      }

      res.json({
        success: true,
        application:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "SCHOOL ADMIN ONE APPLICATION ERROR:",
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


// =====================================================
// SCHOOL ADMIN — UPDATE APPLICATION STATUS
// =====================================================

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
          message:
            "Hujaingia kama School Admin."
        });

      }

      const id =
        Number(req.params.id);

      const { status } =
        req.body;

      const allowedStatuses = [
        "pending",
        "approved",
        "rejected",
        "processing",
        "completed"
      ];

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "Application ID si sahihi."
        });

      }

      if (
        !allowedStatuses.includes(
          status
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Application status si sahihi."
        });

      }

      const result =
        await pool.query(`
          UPDATE applications

          SET
            status = $1,
            updated_at = NOW()

          WHERE id = $2
            AND school_id = $3

          RETURNING *
        `, [
          status,
          id,
          admin.school_id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Application haijapatikana kwenye shule yako."
        });

      }

      res.json({
        success: true,
        message:
          "Hali ya application imebadilishwa.",
        application:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "SCHOOL ADMIN STATUS ERROR:",
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


// =====================================================
// SCHOOL ADMIN — GET ALL ADMINS
// =====================================================

app.get(
  "/api/admin/school-admins",
  async (req, res) => {

    try {

      const {
        search = "",
        school_id = "",
        status = ""
      } = req.query;

      const values = [];
      const conditions = [];

      if (search.trim()) {

        values.push(
          `%${search.trim()}%`
        );

        conditions.push(`
          (
            sa.full_name
              ILIKE $${values.length}

            OR sa.phone
              ILIKE $${values.length}

            OR sa.email
              ILIKE $${values.length}

            OR s.name
              ILIKE $${values.length}
          )
        `);

      }

      if (school_id) {

        const schoolId =
          Number(school_id);

        if (
          !Number.isInteger(
            schoolId
          )
        ) {

          return res.status(400).json({
            success: false,
            message:
              "School ID si sahihi."
          });

        }

        values.push(schoolId);

        conditions.push(
          `sa.school_id = $${values.length}`
        );

      }

      if (
        status &&
        ["active", "inactive"]
          .includes(status)
      ) {

        values.push(status);

        conditions.push(
          `sa.status = $${values.length}`
        );

      }

      const whereClause =
        conditions.length
          ? `WHERE ${conditions.join(" AND ")}`
          : "";

      const result =
        await pool.query(`
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

          ${whereClause}

          ORDER BY sa.id DESC
        `, values);

      const statsResult =
        await pool.query(`
          SELECT
            COUNT(*)::INTEGER
              AS total_admins,

            COUNT(*) FILTER (
              WHERE status = 'active'
            )::INTEGER
              AS active_admins,

            COUNT(*) FILTER (
              WHERE status = 'inactive'
            )::INTEGER
              AS inactive_admins

          FROM school_admins
        `);

      const stats =
        statsResult.rows[0];

      res.json({
        success: true,

        admins:
          result.rows,

        count:
          result.rows.length,

        total_admins:
          Number(
            stats.total_admins || 0
          ),

        active_admins:
          Number(
            stats.active_admins || 0
          ),

        inactive_admins:
          Number(
            stats.inactive_admins || 0
          )
      });

    } catch (error) {

      console.error(
        "GET /api/admin/school-admins error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata School Admins.",
        error: error.message
      });

    }

  }
);


// =====================================================
// ADMIN — GET ONE SCHOOL ADMIN
// =====================================================

app.get(
  "/api/admin/school-admins/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "Admin ID si sahihi."
        });

      }

      const result =
        await pool.query(`
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
        `, [id]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hajapatikana."
        });

      }

      res.json({
        success: true,
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata School Admin.",
        error: error.message
      });

    }

  }
);


// =====================================================
// ADMIN — ADD SCHOOL ADMIN
// =====================================================

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

      const schoolId =
        Number(school_id);

      if (
        !Number.isInteger(
          schoolId
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Shule lazima ichaguliwe."
        });

      }

      if (
        !full_name ||
        !full_name.trim()
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Jina kamili la admin linahitajika."
        });

      }

      if (
        !password ||
        password.length < 6
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Password lazima iwe na angalau characters 6."
        });

      }

      const schoolResult =
        await pool.query(`
          SELECT
            id,
            name,
            status

          FROM schools

          WHERE id = $1
        `, [
          schoolId
        ]);

      if (
        !schoolResult.rows.length
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haijapatikana."
        });

      }

      if (
        email &&
        email.trim()
      ) {

        const emailCheck =
          await pool.query(`
            SELECT id

            FROM school_admins

            WHERE LOWER(email)
              = LOWER($1)
          `, [
            email.trim()
          ]);

        if (
          emailCheck.rows.length
        ) {

          return res.status(409).json({
            success: false,
            message:
              "Email hii tayari inatumika na School Admin mwingine."
          });

        }

      }

      const passwordHash =
        await hashPassword(
          password
        );

      const finalStatus =
        ["active", "inactive"]
          .includes(status)
          ? status
          : "active";

      const result =
        await pool.query(`
          INSERT INTO school_admins (
            school_id,
            full_name,
            phone,
            email,
            password_hash,
            status,
            created_at,
            updated_at
          )

          VALUES (
            $1, $2, $3, $4, $5,
            $6, NOW(), NOW()
          )

          RETURNING
            id,
            school_id,
            full_name,
            phone,
            email,
            status,
            last_login,
            created_at,
            updated_at
        `, [
          schoolId,
          full_name.trim(),
          phone
            ? phone.trim()
            : null,
          email
            ? email.trim()
            : null,
          passwordHash,
          finalStatus
        ]);

      res.status(201).json({
        success: true,
        message:
          "School Admin ameongezwa kikamilifu.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "POST /api/admin/school-admins error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuongeza School Admin.",
        error: error.message
      });

    }

  }
);


// =====================================================
// ADMIN — UPDATE SCHOOL ADMIN
// =====================================================

app.put(
  "/api/admin/school-admins/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "Admin ID si sahihi."
        });

      }

      const {
        school_id,
        full_name,
        phone,
        email,
        status
      } = req.body;

      const schoolId =
        Number(school_id);

      if (
        !Number.isInteger(
          schoolId
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Shule lazima ichaguliwe."
        });

      }

      if (
        !full_name ||
        !full_name.trim()
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Jina kamili la admin linahitajika."
        });

      }

      if (
        status &&
        !["active", "inactive"]
          .includes(status)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Status lazima iwe active au inactive."
        });

      }

      const schoolResult =
        await pool.query(`
          SELECT id

          FROM schools

          WHERE id = $1
        `, [
          schoolId
        ]);

      if (
        !schoolResult.rows.length
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Shule haijapatikana."
        });

      }

      if (
        email &&
        email.trim()
      ) {

        const emailCheck =
          await pool.query(`
            SELECT id

            FROM school_admins

            WHERE LOWER(email)
              = LOWER($1)

              AND id <> $2
          `, [
            email.trim(),
            id
          ]);

        if (
          emailCheck.rows.length
        ) {

          return res.status(409).json({
            success: false,
            message:
              "Email hii tayari inatumika na School Admin mwingine."
          });

        }

      }

      const finalStatus =
        ["active", "inactive"]
          .includes(status)
          ? status
          : "active";

      const result =
        await pool.query(`
          UPDATE school_admins

          SET
            school_id = $1,
            full_name = $2,
            phone = $3,
            email = $4,
            status = $5,
            updated_at = NOW()

          WHERE id = $6

          RETURNING
            id,
            school_id,
            full_name,
            phone,
            email,
            status,
            last_login,
            created_at,
            updated_at
        `, [
          schoolId,
          full_name.trim(),
          phone
            ? phone.trim()
            : null,
          email
            ? email.trim()
            : null,
          finalStatus,
          id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hajapatikana."
        });

      }

      res.json({
        success: true,
        message:
          "School Admin amehaririwa kikamilifu.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "PUT /api/admin/school-admins/:id error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuhariri School Admin.",
        error: error.message
      });

    }

  }
);


// =====================================================
// ADMIN — CHANGE SCHOOL ADMIN STATUS
// =====================================================

app.put(
  "/api/admin/school-admins/:id/status",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const { status } =
        req.body;

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "Admin ID si sahihi."
        });

      }

      if (
        !["active", "inactive"]
          .includes(status)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Status lazima iwe active au inactive."
        });

      }

      const result =
        await pool.query(`
          UPDATE school_admins

          SET
            status = $1,
            updated_at = NOW()

          WHERE id = $2

          RETURNING
            id,
            school_id,
            full_name,
            phone,
            email,
            status,
            last_login,
            created_at,
            updated_at
        `, [
          status,
          id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hajapatikana."
        });

      }

      // Kama admin amezimwa,
      // futa sessions zake zote.
      if (status === "inactive") {

        await pool.query(`
          DELETE FROM school_admin_sessions

          WHERE admin_id = $1
        `, [
          id
        ]);

      }

      res.json({
        success: true,
        message:
          status === "active"
            ? "School Admin amewashwa."
            : "School Admin amezimwa.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kubadilisha status ya School Admin.",
        error: error.message
      });

    }

  }
);


// =====================================================
// ADMIN — RESET SCHOOL ADMIN PASSWORD
// =====================================================

app.put(
  "/api/admin/school-admins/:id/reset-password",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const { password } =
        req.body;

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "Admin ID si sahihi."
        });

      }

      if (
        !password ||
        password.length < 6
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Password mpya lazima iwe na angalau characters 6."
        });

      }

      const passwordHash =
        await hashPassword(
          password
        );

      const result =
        await pool.query(`
          UPDATE school_admins

          SET
            password_hash = $1,
            updated_at = NOW()

          WHERE id = $2

          RETURNING
            id,
            school_id,
            full_name,
            phone,
            email,
            status,
            last_login,
            created_at,
            updated_at
        `, [
          passwordHash,
          id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hajapatikana."
        });

      }

      // Password ikibadilishwa,
      // session zote za admin huyo zinafutwa.
      await pool.query(`
        DELETE FROM school_admin_sessions

        WHERE admin_id = $1
      `, [
        id
      ]);

      res.json({
        success: true,
        message:
          "Password ya School Admin imebadilishwa.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "RESET SCHOOL ADMIN PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kubadilisha password.",
        error: error.message
      });

    }

  }
);


// =====================================================
// ADMIN — DELETE SCHOOL ADMIN
// =====================================================

app.delete(
  "/api/admin/school-admins/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      if (!Number.isInteger(id)) {

        return res.status(400).json({
          success: false,
          message:
            "Admin ID si sahihi."
        });

      }

      await pool.query(`
        DELETE FROM school_admin_sessions

        WHERE admin_id = $1
      `, [
        id
      ]);

      const result =
        await pool.query(`
          DELETE FROM school_admins

          WHERE id = $1

          RETURNING
            id,
            school_id,
            full_name,
            phone,
            email,
            status
        `, [
          id
        ]);

      if (!result.rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "School Admin hajapatikana."
        });

      }

      res.json({
        success: true,
        message:
          "School Admin amefutwa kikamilifu.",
        admin:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "DELETE /api/admin/school-admins/:id error:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Imeshindikana kufuta School Admin.",
        error: error.message
      });

    }

  }
);


// =====================================================
// CLEAN EXPIRED SCHOOL ADMIN SESSIONS
// =====================================================

async function cleanExpiredSessions() {

  try {

    await pool.query(`
      DELETE FROM school_admin_sessions

      WHERE expires_at <= NOW()
    `);

  } catch (error) {

    console.error(
      "SESSION CLEANUP ERROR:",
      error.message
    );

  }

}


// =====================================================
// START SERVER
// =====================================================

async function startServer() {

  try {

    await setupDatabase();

    await cleanExpiredSessions();

    app.listen(
      PORT,
      "0.0.0.0",
      () => {

        console.log(
          `🚀 Shule Portal Tanzania running on port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      "❌ Server failed to start:",
      error
    );

    process.exit(1);

  }

}

startServer();