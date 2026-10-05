const express = require("express");
const { Pool } = require("pg");

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


// ======================================================
// DATABASE SETUP
// ======================================================

async function setupDatabase() {

  try {

    console.log("Starting database setup...");

    // ==================================================
    // APPLICATIONS TABLE
    // ==================================================

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
        status VARCHAR(30) DEFAULT 'pending',
        payment_status VARCHAR(30) NOT NULL DEFAULT 'unpaid',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ==================================================
    // APPLICATION COLUMNS
    // ==================================================

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(100);
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS school_id INTEGER;
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS form_id INTEGER;
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS applicant_name VARCHAR(255);
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS applicant_gender VARCHAR(50);
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS applicant_date_of_birth DATE;
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS parent_name VARCHAR(255);
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS parent_phone VARCHAR(50);
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS parent_email VARCHAR(255);
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS address TEXT;
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS status VARCHAR(30)
      DEFAULT 'pending';
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS payment_status VARCHAR(30)
      DEFAULT 'unpaid';
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMP
      DEFAULT CURRENT_TIMESTAMP;
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP
      DEFAULT CURRENT_TIMESTAMP;
    `);

    // ==================================================
    // NEW APPLICATION COLUMNS
    // ==================================================

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

    // ==================================================
    // FIX APPLICATION STATUS
    // ==================================================

    await pool.query(`
      UPDATE applications
      SET payment_status = 'unpaid'
      WHERE payment_status IS NULL;
    `);

    await pool.query(`
      UPDATE applications
      SET status = 'pending'
      WHERE status IS NULL;
    `);

    // ==================================================
    // PAYMENTS TABLE
    // ==================================================

    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        application_id INTEGER,
        application_number VARCHAR(100),
        amount NUMERIC(12,2),
        payment_reference VARCHAR(150),
        provider_reference VARCHAR(150),
        status VARCHAR(30) DEFAULT 'pending',
        paid_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // ==================================================
    // PAYMENT COLUMNS
    // ==================================================

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS application_id INTEGER;
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(100);
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS amount NUMERIC(12,2);
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS payment_reference VARCHAR(150);
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS provider_reference VARCHAR(150);
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS status VARCHAR(30)
      DEFAULT 'pending';
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS paid_at TIMESTAMP NULL;
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMP
      DEFAULT CURRENT_TIMESTAMP;
    `);

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP
      DEFAULT CURRENT_TIMESTAMP;
    `);

    // ==================================================
    // FIX PAYMENT STATUS
    // ==================================================

    await pool.query(`
      UPDATE payments
      SET status = 'pending'
      WHERE status IS NULL;
    `);

    // ==================================================
    // UNIQUE INDEXES
    // ==================================================

    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
      applications_application_number_unique
      ON applications(application_number);
    `);

    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
      payments_payment_reference_unique
      ON payments(payment_reference);
    `);

    console.log(
      "Database setup completed successfully."
    );

  } catch (error) {

    console.error(
      "DATABASE SETUP ERROR:",
      error
    );

  }

}


// ======================================================
// HOME
// ======================================================

app.get("/", (req, res) => {

  res.send(
    "Shule Portal Tanzania iko hewani."
  );

});


// ======================================================
// STATUS
// ======================================================

app.get("/api/status", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    res.json({

      success: true,

      message:
        "Backend na PostgreSQL vinafanya kazi.",

      database:
        "connected"

    });

  } catch (error) {

    console.error(error);

    res.status(500).json({

      success: false,

      message:
        "Database haijaunganishwa.",

      database:
        "disconnected",

      error:
        error.message

    });

  }

});


// ======================================================
// GET PUBLIC SCHOOLS
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
        status,
        created_at,
        updated_at

      FROM schools

      WHERE status = 'active'

      ORDER BY id DESC

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
      "GET SCHOOLS ERROR:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kupata shule.",

      schools: [],

      error:
        error.message

    });

  }

});


// ======================================================
// ADMIN - SCHOOL MANAGEMENT
// ======================================================


// ======================================================
// GET ADMIN SCHOOLS
// ======================================================

app.get(
  "/api/admin/schools",
  async (req, res) => {

    try {

      const {
        search = "",
        status = "",
        region = ""
      } = req.query;

      const conditions = [];
      const values = [];

      // SEARCH
      if (search.trim()) {

        values.push(
          `%${search.trim()}%`
        );

        conditions.push(`
          (
            s.name ILIKE $${values.length}
            OR s.region ILIKE $${values.length}
            OR s.district ILIKE $${values.length}
          )
        `);

      }

      // STATUS
      if (status.trim()) {

        values.push(
          status.trim()
        );

        conditions.push(
          `s.status = $${values.length}`
        );

      }

      // REGION
      if (region.trim()) {

        values.push(
          region.trim()
        );

        conditions.push(
          `s.region = $${values.length}`
        );

      }

      const whereClause =
        conditions.length > 0
          ? `WHERE ${conditions.join(" AND ")}`
          : "";

      const result =
        await pool.query(

          `

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

          GROUP BY

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
            s.updated_at

          ORDER BY s.id DESC

          `,

          values

        );


      // ==================================================
      // REGIONS
      // ==================================================

      const regionsResult =
        await pool.query(`

          SELECT DISTINCT
            region

          FROM schools

          WHERE region IS NOT NULL

          AND TRIM(region) <> ''

          ORDER BY region ASC

        `);


      // ==================================================
      // STATISTICS
      // ==================================================

      const statsResult =
        await pool.query(`

          SELECT

            COUNT(*)::INTEGER
              AS total_schools,

            COUNT(*) FILTER (
              WHERE status = 'active'
            )::INTEGER
              AS active_schools

          FROM schools

        `);


      const applicantsResult =
        await pool.query(`

          SELECT
            COUNT(*)::INTEGER
              AS total_applicants

          FROM applications

        `);


      return res.json({

        success: true,

        schools:
          result.rows,

        count:
          result.rows.length,

        total_schools:
          statsResult.rows[0].total_schools,

        active_schools:
          statsResult.rows[0].active_schools,

        total_applicants:
          applicantsResult.rows[0].total_applicants,

        all_regions:
          regionsResult.rows.map(
            row => row.region
          )

      });

    } catch (error) {

      console.error(
        "ADMIN GET SCHOOLS ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Imeshindikana kupata shule.",

        error:
          error.message

      });

    }

  }
);


// ======================================================
// ADMIN - ADD SCHOOL
// ======================================================

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


      if (
        !name ||
        !region ||
        !district
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Jina la shule, mkoa na wilaya vinahitajika."

        });

      }


      const price =
        Number(form_price || 0);


      if (
        Number.isNaN(price) ||
        price < 0
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Bei ya fomu si sahihi."

        });

      }


      const result =
        await pool.query(

          `

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
            $11,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP

          )

          RETURNING *

          `,

          [

            name.trim(),
            region.trim(),
            district.trim(),
            school_type ||
              "Primary & Secondary",
            price,
            phone || null,
            email || null,
            address || null,
            application_start || null,
            application_end || null,
            status || "active"

          ]

        );


      return res.status(201).json({

        success: true,

        message:
          "Shule imeongezwa kikamilifu.",

        school:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        "ADMIN ADD SCHOOL ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Imeshindikana kuongeza shule.",

        error:
          error.message

      });

    }

  }
);


// ======================================================
// ADMIN - UPDATE SCHOOL
// ======================================================

app.put(
  "/api/admin/schools/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);


      if (
        !Number.isInteger(id)
      ) {

        return res.status(400).json({

          success: false,

          message:
            "ID ya shule si sahihi."

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


      if (
        !name ||
        !region ||
        !district
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Jina la shule, mkoa na wilaya vinahitajika."

        });

      }


      const price =
        Number(form_price || 0);


      if (
        Number.isNaN(price) ||
        price < 0
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Bei ya fomu si sahihi."

        });

      }


      const result =
        await pool.query(

          `

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
            updated_at = CURRENT_TIMESTAMP

          WHERE id = $12

          RETURNING *

          `,

          [

            name.trim(),
            region.trim(),
            district.trim(),
            school_type ||
              "Primary & Secondary",
            price,
            phone || null,
            email || null,
            address || null,
            application_start || null,
            application_end || null,
            status || "active",
            id

          ]

        );


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({

          success: false,

          message:
            "Shule haijapatikana."

        });

      }


      return res.json({

        success: true,

        message:
          "Taarifa za shule zimehaririwa.",

        school:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        "ADMIN UPDATE SCHOOL ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Imeshindikana kuhariri shule.",

        error:
          error.message

      });

    }

  }
);


// ======================================================
// ADMIN - SCHOOL STATUS
// ======================================================

app.put(
  "/api/admin/schools/:id/status",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);

      const {
        status
      } = req.body;


      if (
        !Number.isInteger(id)
      ) {

        return res.status(400).json({

          success: false,

          message:
            "ID ya shule si sahihi."

        });

      }


      if (
        !["active", "inactive"]
          .includes(status)
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Hali ya shule si sahihi."

        });

      }


      const result =
        await pool.query(

          `

          UPDATE schools

          SET

            status = $1,

            updated_at =
              CURRENT_TIMESTAMP

          WHERE id = $2

          RETURNING *

          `,

          [
            status,
            id
          ]

        );


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({

          success: false,

          message:
            "Shule haijapatikana."

        });

      }


      return res.json({

        success: true,

        message:
          "Hali ya shule imebadilishwa.",

        school:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        "ADMIN SCHOOL STATUS ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Imeshindikana kubadilisha hali ya shule.",

        error:
          error.message

      });

    }

  }
);


// ======================================================
// ADMIN - DELETE SCHOOL
// ======================================================

app.delete(
  "/api/admin/schools/:id",
  async (req, res) => {

    try {

      const id =
        Number(req.params.id);


      if (
        !Number.isInteger(id)
      ) {

        return res.status(400).json({

          success: false,

          message:
            "ID ya shule si sahihi."

        });

      }


      // ==================================================
      // CHECK APPLICATIONS
      // ==================================================

      const applicationsResult =
        await pool.query(

          `

          SELECT
            COUNT(*)::INTEGER AS count

          FROM applications

          WHERE school_id = $1

          `,

          [id]

        );


      const applicationCount =
        applicationsResult
          .rows[0]
          .count;


      if (
        applicationCount > 0
      ) {

        return res.status(400).json({

          success: false,

          message:
            `Shule hii ina maombi ${applicationCount}. Haiwezi kufutwa. Badala yake unaweza kuiweka INACTIVE.`

        });

      }


      const result =
        await pool.query(

          `

          DELETE FROM schools

          WHERE id = $1

          RETURNING *

          `,

          [id]

        );


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({

          success: false,

          message:
            "Shule haijapatikana."

        });

      }


      return res.json({

        success: true,

        message:
          "Shule imefutwa kikamilifu."

      });

    } catch (error) {

      console.error(
        "ADMIN DELETE SCHOOL ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Imeshindikana kufuta shule.",

        error:
          error.message

      });

    }

  }
);


// ======================================================
// DATABASE CHECK
// ======================================================

app.get(
  "/api/database-check",
  async (req, res) => {

    try {

      const result =
        await pool.query(`

          SELECT
            table_name

          FROM information_schema.tables

          WHERE table_schema = 'public'

          AND table_name IN (
            'applications',
            'payments',
            'schools'
          )

          ORDER BY table_name;

        `);


      res.json({

        success: true,

        tables:
          result.rows.map(
            row => row.table_name
          )

      });

    } catch (error) {

      console.error(
        "DATABASE CHECK ERROR:",
        error
      );

      res.status(500).json({

        success: false,

        message:
          "Imeshindikana kukagua database.",

        error:
          error.message

      });

    }

  }
);


// ======================================================
// APPLICATION SCHEMA
// ======================================================

app.get(
  "/api/application-schema",
  async (req, res) => {

    try {

      const result =
        await pool.query(`

          SELECT

            ordinal_position,
            column_name,
            data_type,
            is_nullable,
            column_default

          FROM information_schema.columns

          WHERE table_schema = 'public'

          AND table_name = 'applications'

          ORDER BY ordinal_position;

        `);


      res.json({

        success: true,

        table:
          "applications",

        columns:
          result.rows

      });

    } catch (error) {

      console.error(
        "APPLICATION SCHEMA ERROR:",
        error
      );

      res.status(500).json({

        success: false,

        error:
          error.message

      });

    }

  }
);


// ======================================================
// PAYMENT SCHEMA
// ======================================================

app.get(
  "/api/payment-schema",
  async (req, res) => {

    try {

      const result =
        await pool.query(`

          SELECT

            ordinal_position,
            column_name,
            data_type,
            is_nullable,
            column_default

          FROM information_schema.columns

          WHERE table_schema = 'public'

          AND table_name = 'payments'

          ORDER BY ordinal_position;

        `);


      res.json({

        success: true,

        table:
          "payments",

        columns:
          result.rows

      });

    } catch (error) {

      console.error(
        "PAYMENT SCHEMA ERROR:",
        error
      );

      res.status(500).json({

        success: false,

        error:
          error.message

      });

    }

  }
);


// ======================================================
// CREATE APPLICATION
// ======================================================

app.post(
  "/api/applications",
  async (req, res) => {

    const {

      school_id,
      student_name,
      gender,
      date_of_birth,
      class_level,
      parent_name,
      phone,
      email,
      address

    } = req.body;


    if (!school_id) {

      return res.status(400).json({

        success: false,

        message:
          "School ID haijatumwa."

      });

    }

    if (!student_name) {

      return res.status(400).json({

        success: false,

        message:
          "Jina la mwanafunzi linahitajika."

      });

    }

    if (!gender) {

      return res.status(400).json({

        success: false,

        message:
          "Jinsia inahitajika."

      });

    }

    if (!date_of_birth) {

      return res.status(400).json({

        success: false,

        message:
          "Tarehe ya kuzaliwa inahitajika."

      });

    }

    if (!class_level) {

      return res.status(400).json({

        success: false,

        message:
          "Darasa/Kidato linahitajika."

      });

    }

    if (!parent_name) {

      return res.status(400).json({

        success: false,

        message:
          "Jina la mzazi/mlezi linahitajika."

      });

    }

    if (!phone) {

      return res.status(400).json({

        success: false,

        message:
          "Namba ya simu inahitajika."

      });

    }


    const client =
      await pool.connect();


    try {

      await client.query(
        "BEGIN"
      );


      // CHECK SCHOOL

      const schoolResult =
        await client.query(

          `

          SELECT

            id,
            name,
            form_price,
            status

          FROM schools

          WHERE id = $1

          AND status = 'active'

          `,

          [
            Number(school_id)
          ]

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
            "Shule haipatikani au haijawezeshwa."

        });

      }


      const school =
        schoolResult.rows[0];


      // APPLICATION NUMBER

      const applicationNumber =

        "SPT-" +

        new Date().getFullYear() +

        "-" +

        Date.now() +

        "-" +

        Math.floor(
          Math.random() * 1000
        );


      // INSERT APPLICATION

      const applicationResult =

        await client.query(

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

            status,
            payment_status,

            student_name,
            gender,
            date_of_birth,
            class_level,
            phone,
            email

          )

          VALUES (

            $1,
            $2,
            NULL,

            $3,
            $4,
            $5::date,

            $6,
            $7,
            $8,

            $9,

            'pending',
            'unpaid',

            $3,
            $4,
            $5::date,
            $10,
            $7,
            $8

          )

          RETURNING

            id,
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
            phone