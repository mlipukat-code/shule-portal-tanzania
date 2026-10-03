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


// ==========================================
// DATABASE SETUP
// ==========================================

async function setupDatabase() {

  try {

    // ======================================
    // APPLICATIONS TABLE
    // ======================================

    await pool.query(`
      CREATE TABLE IF NOT EXISTS applications (
        id SERIAL PRIMARY KEY,
        school_id INTEGER NOT NULL,
        student_name VARCHAR(255) NOT NULL,
        gender VARCHAR(50),
        date_of_birth DATE,
        class_level VARCHAR(100),
        parent_name VARCHAR(255),
        phone VARCHAR(50),
        email VARCHAR(255),
        address TEXT,
        application_number VARCHAR(100),
        status VARCHAR(30) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);


    // ======================================
    // APPLICATION COLUMNS
    // ======================================

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
      ADD COLUMN IF NOT EXISTS parent_name VARCHAR(255);
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
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS address TEXT;
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS application_number VARCHAR(100);
    `);

    await pool.query(`
      ALTER TABLE applications
      ADD COLUMN IF NOT EXISTS status VARCHAR(30)
      DEFAULT 'pending';
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


    // ======================================
    // IMPORTANT:
    // form_id IS NOT REQUIRED FOR NOW
    // ======================================

    await pool.query(`
      ALTER TABLE applications
      ALTER COLUMN form_id DROP NOT NULL;
    `);


    // ======================================
    // PAYMENTS TABLE
    // ======================================

    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        application_id INTEGER NOT NULL,
        amount NUMERIC(12,2) NOT NULL,
        payment_reference VARCHAR(150),
        provider_reference VARCHAR(150),
        status VARCHAR(30) DEFAULT 'pending',
        paid_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);


    // ======================================
    // PAYMENT COLUMNS
    // ======================================

    await pool.query(`
      ALTER TABLE payments
      ADD COLUMN IF NOT EXISTS application_id INTEGER;
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


    // ======================================
    // UNIQUE INDEXES
    // ======================================

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


// ==========================================
// HOME
// ==========================================

app.get("/", (req, res) => {

  res.send(
    "Shule Portal Tanzania iko hewani."
  );

});


// ==========================================
// STATUS
// ==========================================

app.get("/api/status", async (req, res) => {

  try {

    await pool.query("SELECT 1");

    res.json({
      success: true,
      message:
        "Backend na PostgreSQL vinafanya kazi.",
      database: "connected"
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      success: false,
      message:
        "Database haijaunganishwa.",
      database: "disconnected",
      error: error.message
    });

  }

});


// ==========================================
// GET SCHOOLS
// ==========================================

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
      schools: result.rows,
      count: result.rows.length
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
      error: error.message
    });

  }

});


// ==========================================
// DATABASE CHECK
// ==========================================

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
            'payments'
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


// ==========================================
// CREATE APPLICATION
// ==========================================

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


    // ======================================
    // VALIDATION
    // ======================================

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


    // ======================================
    // DATABASE CLIENT
    // ======================================

    const client =
      await pool.connect();


    try {

      await client.query(
        "BEGIN"
      );


      // ====================================
      // CHECK SCHOOL
      // ====================================

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


      // ====================================
      // GENERATE APPLICATION NUMBER
      // ====================================

      const applicationNumber =
        "SPT-" +
        new Date().getFullYear() +
        "-" +
        Date.now() +
        "-" +
        Math.floor(
          Math.random() * 1000
        );


      // ====================================
      // INSERT APPLICATION
      // ====================================

      const applicationResult =
        await client.query(
          `
          INSERT INTO applications (
            school_id,
            form_id,
            student_name,
            gender,
            date_of_birth,
            class_level,
            parent_name,
            phone,
            email,
            address,
            application_number,
            status
          )

          VALUES (
            $1,
            NULL,
            $2,
            $3,
            $4::date,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            'pending'
          )

          RETURNING
            id,
            school_id,
            form_id,
            student_name,
            gender,
            date_of_birth,
            class_level,
            parent_name,
            phone,
            email,
            address,
            application_number,
            status,
            created_at
          `,
          [
            Number(school_id),
            student_name,
            gender,
            date_of_birth,
            class_level,
            parent_name,
            phone,
            email || null,
            address || null,
            applicationNumber
          ]
        );


      const application =
        applicationResult.rows[0];


      // ====================================
      // GENERATE PAYMENT REFERENCE
      // ====================================

      const paymentReference =
        "PAY-" +
        new Date().getFullYear() +
        "-" +
        Date.now() +
        "-" +
        Math.floor(
          Math.random() * 1000
        );


      // ====================================
      // CREATE PENDING PAYMENT
      // ====================================

      const paymentResult =
        await client.query(
          `
          INSERT INTO payments (
            application_id,
            amount,
            payment_reference,
            status
          )

          VALUES (
            $1,
            $2,
            $3,
            'pending'
          )

          RETURNING
            id,
            application_id,
            amount,
            payment_reference,
            status,
            created_at
          `,
          [
            application.id,
            school.form_price,
            paymentReference
          ]
        );


      const payment =
        paymentResult.rows[0];


      // ====================================
      // COMMIT
      // ====================================

      await client.query(
        "COMMIT"
      );


      // ====================================
      // RESPONSE
      // ====================================

      return res.status(201).json({

        success: true,

        message:
          "Maombi yamehifadhiwa na payment order imeundwa.",

        application: {

          id:
            application.id,

          application_number:
            application.application_number,

          student_name:
            application.student_name,

          school_id:
            application.school_id,

          form_id:
            application.form_id,

          status:
            application.status

        },

        payment: {

          id:
            payment.id,

          amount:
            payment.amount,

          payment_reference:
            payment.payment_reference,

          status:
            payment.status

        },

        school: {

          id:
            school.id,

          name:
            school.name,

          form_price:
            school.form_price

        }

      });

    } catch (error) {

      // ====================================
      // ROLLBACK
      // ====================================

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


      // ====================================
      // REAL ERROR
      // ====================================

      console.error(
        "CREATE APPLICATION ERROR:",
        error
      );


      return res.status(500).json({

        success: false,

        message:
          "Imeshindikana kuhifadhi maombi.",

        error:
          error.message,

        code:
          error.code || null,

        detail:
          error.detail || null

      });

    } finally {

      client.release();

    }

  }
);


// ==========================================
// GET APPLICATION
// ==========================================

app.get(
  "/api/applications/:id",
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            a.*,

            p.id AS payment_id,

            p.amount,

            p.payment_reference,

            p.status AS payment_status,

            p.paid_at

          FROM applications a

          LEFT JOIN payments p
            ON p.application_id = a.id

          WHERE a.id = $1
          `,
          [
            req.params.id
          ]
        );


      if (
        result.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Application haijapatikana."
        });

      }


      return res.json({

        success: true,

        application:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        "GET APPLICATION ERROR:",
        error
      );

      return res.status(500).json({

        success: false,

        message:
          "Imeshindikana kupata application.",

        error:
          error.message

      });

    }

  }
);


// ==========================================
// START SERVER
// ==========================================

async function startServer() {

  await setupDatabase();

  app.listen(
    PORT,
    () => {

      console.log(
        `Shule Portal Tanzania running on port ${PORT}`
      );

    }
  );

}


startServer();