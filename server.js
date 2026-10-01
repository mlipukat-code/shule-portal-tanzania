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
// PASSWORD HASH
// =====================================================

function hashPassword(password) {

  const salt =
    crypto.randomBytes(16).toString("hex");

  const hash =
    crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

  return `${salt}:${hash}`;
}


// =====================================================
// PASSWORD VERIFY
// =====================================================

function verifyPassword(password, storedHash) {

  if (!storedHash || !storedHash.includes(":")) {
    return false;
  }

  const parts =
    storedHash.split(":");

  if (parts.length !== 2) {
    return false;
  }

  const salt = parts[0];
  const originalHash = parts[1];

  const hash =
    crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

  const hashBuffer =
    Buffer.from(hash, "hex");

  const originalBuffer =
    Buffer.from(originalHash, "hex");

  if (
    hashBuffer.length !==
    originalBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    hashBuffer,
    originalBuffer
  );
}


// =====================================================
// APPLICATION NUMBER
// =====================================================

function generateApplicationNumber() {

  const year =
    new Date().getFullYear();

  const random =
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase();

  return `SPT-${year}-${random}`;
}


// =====================================================
// PAYMENT REFERENCE
// =====================================================

function generatePaymentReference() {

  const year =
    new Date().getFullYear();

  const random =
    crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase();

  return `PAY-${year}-${random}`;
}


// =====================================================
// ADMIN SESSION TOKEN
// =====================================================

function generateSessionToken() {

  return crypto
    .randomBytes(32)
    .toString("hex");
}


// =====================================================
// DATABASE INITIALIZATION
// =====================================================

async function initializeDatabase() {

  try {

    // =================================================
    // SCHOOLS TABLE
    // =================================================

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


    // =================================================
    // SCHOOL ADMINS TABLE
    // =================================================

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


    // =================================================
    // SCHOOL FORMS TABLE
    // =================================================

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


    // =================================================
    // APPLICATIONS TABLE
    // =================================================

    await pool.query(`
      CREATE TABLE IF NOT EXISTS applications (

        id SERIAL PRIMARY KEY,

        application_number VARCHAR(50) NOT NULL UNIQUE,

        school_id INTEGER NOT NULL,

        form_id INTEGER NOT NULL,

        applicant_name VARCHAR(255) NOT NULL,

        applicant_gender VARCHAR(30),

        applicant_date_of_birth DATE,

        parent_name VARCHAR(255),

        parent_phone VARCHAR(30),

        parent_email VARCHAR(255),

        address TEXT,

        status VARCHAR(50) NOT NULL DEFAULT 'pending',

        payment_status VARCHAR(50) NOT NULL DEFAULT 'unpaid',

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

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


    // =================================================
    // PAYMENTS TABLE
    // =================================================

    await pool.query(`
      CREATE TABLE IF NOT EXISTS payments (

        id SERIAL PRIMARY KEY,

        payment_reference VARCHAR(100) NOT NULL UNIQUE,

        application_id INTEGER NOT NULL,

        application_number VARCHAR(50) NOT NULL,

        amount NUMERIC(12,2) NOT NULL,

        payment_method VARCHAR(50),

        transaction_id VARCHAR(100),

        payer_phone VARCHAR(30),

        status VARCHAR(30) NOT NULL DEFAULT 'pending',

        paid_at TIMESTAMP,

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        CONSTRAINT fk_payment_application
          FOREIGN KEY (application_id)
          REFERENCES applications(id)
          ON DELETE RESTRICT

      );
    `);


    // =================================================
    // ADMIN USERS TABLE
    // =================================================

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_users (

        id SERIAL PRIMARY KEY,

        full_name VARCHAR(255) NOT NULL,

        email VARCHAR(255) NOT NULL UNIQUE,

        password_hash TEXT NOT NULL,

        role VARCHAR(50) NOT NULL DEFAULT 'super_admin',

        status VARCHAR(30) NOT NULL DEFAULT 'active',

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

      );
    `);


    // =================================================
    // ADMIN SESSIONS TABLE
    // =================================================

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_sessions (

        id SERIAL PRIMARY KEY,

        admin_id INTEGER NOT NULL,

        session_token TEXT NOT NULL UNIQUE,

        expires_at TIMESTAMP NOT NULL,

        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        CONSTRAINT fk_admin_session_admin
          FOREIGN KEY (admin_id)
          REFERENCES admin_users(id)
          ON DELETE CASCADE

      );
    `);


    console.log("Schools table iko tayari.");
    console.log("School Admins table iko tayari.");
    console.log("School Forms table iko tayari.");
    console.log("Applications table iko tayari.");
    console.log("Payments table iko tayari.");
    console.log("Admin Users table iko tayari.");
    console.log("Admin Sessions table iko tayari.");


    // =================================================
    // CREATE FIRST ADMIN FROM RAILWAY VARIABLES
    // =================================================

    const adminEmail =
      process.env.ADMIN_EMAIL;

    const adminPassword =
      process.env.ADMIN_PASSWORD;

    const adminName =
      process.env.ADMIN_NAME ||
      "Admin Mkuu";


    if (
      adminEmail &&
      adminPassword
    ) {

      const existingAdmin =
        await pool.query(
          `
          SELECT id
          FROM admin_users
          WHERE email = $1
          `,
          [adminEmail]
        );


      if (
        existingAdmin.rows.length === 0
      ) {

        const passwordHash =
          hashPassword(adminPassword);


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
          ($1,$2,$3,'super_admin','active')
          `,
          [
            adminName,
            adminEmail,
            passwordHash
          ]
        );

        console.log(
          "Admin Mkuu ameundwa."
        );

      } else {

        console.log(
          "Admin Mkuu tayari yupo."
        );

      }

    } else {

      console.log(
        "ADMIN_EMAIL au ADMIN_PASSWORD haijawekwa Railway Variables."
      );

    }

  }

  catch (error) {

    console.error(
      "Database initialization error:",
      error
    );

  }

}


// =====================================================
// ADMIN AUTHENTICATION MIDDLEWARE
// =====================================================

async function requireAdmin(req, res, next) {

  try {

    const authHeader =
      req.headers.authorization;


    if (
      !authHeader ||
      !authHeader.startsWith("Bearer ")
    ) {

      return res.status(401).json({

        success: false,

        message:
          "Huruhusiwi. Tafadhali login kwanza."

      });

    }


    const token =
      authHeader.substring(7);


    if (!token) {

      return res.status(401).json({

        success: false,

        message:
          "Admin token haipo."

      });

    }


    const result =
      await pool.query(
        `
        SELECT
          admin_sessions.id,
          admin_sessions.admin_id,
          admin_sessions.expires_at,

          admin_users.full_name,
          admin_users.email,
          admin_users.role,
          admin_users.status

        FROM admin_sessions

        INNER JOIN admin_users
          ON admin_users.id =
             admin_sessions.admin_id

        WHERE
          admin_sessions.session_token = $1

        AND
          admin_sessions.expires_at > CURRENT_TIMESTAMP

        AND
          admin_users.status = 'active'
        `,
        [token]
      );


    if (
      result.rows.length === 0
    ) {

      return res.status(401).json({

        success: false,

        message:
          "Session imekwisha au si sahihi."

      });

    }


    req.admin =
      result.rows[0];


    next();

  }

  catch (error) {

    console.error(
      "Admin authentication error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kuthibitisha Admin."

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
// DATABASE STATUS
// =====================================================

app.get("/api/status", async (req, res) => {

  try {

    const result =
      await pool.query(
        "SELECT NOW()"
      );


    res.json({

      success: true,

      message:
        "Shule Portal Tanzania backend na PostgreSQL vimeunganishwa",

      database:
        "connected",

      time:
        result.rows[0].now

    });

  }

  catch (error) {

    console.error(
      "Database error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Database connection failed"

    });

  }

});


// =====================================================
// ADMIN LOGIN
// =====================================================

app.post("/api/admin/login", async (req, res) => {

  try {

    const {
      email,
      password
    } = req.body;


    if (
      !email ||
      !password
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Email na password ni lazima."

      });

    }


    const result =
      await pool.query(
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


    if (
      result.rows.length === 0
    ) {

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
          "Admin account hii imezuiwa."

      });

    }


    const passwordCorrect =
      verifyPassword(
        password,
        admin.password_hash
      );


    if (!passwordCorrect) {

      return res.status(401).json({

        success: false,

        message:
          "Email au password si sahihi."

      });

    }


    // Remove old sessions

    await pool.query(
      `
      DELETE FROM admin_sessions
      WHERE admin_id = $1
      `,
      [admin.id]
    );


    // Create new session

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


    res.json({

      success: true,

      message:
        "Login imefanikiwa.",

      token:
        sessionToken,

      admin: {

        id:
          admin.id,

        full_name:
          admin.full_name,

        email:
          admin.email,

        role:
          admin.role

      }

    });

  }

  catch (error) {

    console.error(
      "Admin login error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kufanya login."

    });

  }

});


// =====================================================
// ADMIN ME
// =====================================================

app.get(
  "/api/admin/me",
  requireAdmin,
  async (req, res) => {

    res.json({

      success: true,

      admin: {

        id:
          req.admin.admin_id,

        full_name:
          req.admin.full_name,

        email:
          req.admin.email,

        role:
          req.admin.role

      }

    });

  }
);


// =====================================================
// ADMIN DASHBOARD STATISTICS
// =====================================================

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  async (req, res) => {

    try {

      // -----------------------------------------------
      // COUNT SCHOOLS
      // -----------------------------------------------

      const schoolsResult =
        await pool.query(`
          SELECT COUNT(*)::INTEGER AS total
          FROM schools
        `);


      // -----------------------------------------------
      // COUNT SCHOOL FORMS
      // -----------------------------------------------

      const formsResult =
        await pool.query(`
          SELECT COUNT(*)::INTEGER AS total
          FROM school_forms
        `);


      // -----------------------------------------------
      // COUNT APPLICATIONS
      // -----------------------------------------------

      const applicationsResult =
        await pool.query(`
          SELECT COUNT(*)::INTEGER AS total
          FROM applications
        `);


      // -----------------------------------------------
      // COUNT PAYMENTS
      // -----------------------------------------------

      const paymentsResult =
        await pool.query(`
          SELECT
            COUNT(*)::INTEGER AS total,
            COALESCE(
              SUM(
                CASE
                  WHEN status = 'paid'
                  THEN amount
                  ELSE 0
                END
              ),
              0
            )::NUMERIC AS paid_amount
          FROM payments
        `);


      // -----------------------------------------------
      // COUNT PENDING PAYMENTS
      // -----------------------------------------------

      const pendingPaymentsResult =
        await pool.query(`
          SELECT COUNT(*)::INTEGER AS total
          FROM payments
          WHERE status = 'pending'
        `);


      // -----------------------------------------------
      // APPLICATION STATUS
      // -----------------------------------------------

      const pendingApplicationsResult =
        await pool.query(`
          SELECT COUNT(*)::INTEGER AS total
          FROM applications
          WHERE status = 'pending'
        `);


      const approvedApplicationsResult =
        await pool.query(`
          SELECT COUNT(*)::INTEGER AS total
          FROM applications
          WHERE status = 'approved'
        `);


      res.json({

        success: true,

        statistics: {

          schools:
            schoolsResult.rows[0].total,

          forms:
            formsResult.rows[0].total,

          applications:
            applicationsResult.rows[0].total,

          payments:
            paymentsResult.rows[0].total,

          pending_payments:
            pendingPaymentsResult.rows[0].total,

          paid_amount:
            paymentsResult.rows[0].paid_amount,

          pending_applications:
            pendingApplicationsResult.rows[0].total,

          approved_applications:
            approvedApplicationsResult.rows[0].total

        }

      });

    }

    catch (error) {

      console.error(
        "Dashboard statistics error:",
        error
      );

      res.status(500).json({

        success: false,

        message:
          "Imeshindikana kupata takwimu za Dashboard."

      });

    }

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
        req.headers.authorization;

      const token =
        authHeader.substring(7);


      await pool.query(
        `
        DELETE FROM admin_sessions
        WHERE session_token = $1
        `,
        [token]
      );


      res.json({

        success: true,

        message:
          "Umetoka kwenye mfumo."

      });

    }

    catch (error) {

      console.error(
        "Admin logout error:",
        error
      );

      res.status(500).json({

        success: false,

        message:
          "Imeshindikana kutoka."

      });

    }

  }
);


// =====================================================
// GET ALL SCHOOLS
// =====================================================

app.get("/api/schools", async (req, res) => {

  try {

    const result =
      await pool.query(`
        SELECT *
        FROM schools
        ORDER BY id DESC
      `);


    res.json({

      success: true,

      schools:
        result.rows

    });

  }

  catch (error) {

    console.error(
      "Get schools error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kupata taarifa za shule."

    });

  }

});


// =====================================================
// ADD SCHOOL
// =====================================================

app.post("/api/schools", async (req, res) => {

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
      !school_type ||
      form_price === undefined

    ) {

      return res.status(400).json({

        success: false,

        message:
          "Tafadhali jaza taarifa muhimu za shule."

      });

    }


    const result =
      await pool.query(

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
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)

        RETURNING *
        `,

        [

          name,
          region,
          district,
          school_type,
          form_price,
          phone || null,
          address || null,
          email || null,
          application_start || null,
          application_end || null

        ]

      );


    res.status(201).json({

      success: true,

      message:
        "Shule imeongezwa kwa mafanikio.",

      school:
        result.rows[0]

    });

  }

  catch (error) {

    console.error(
      "Add school error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kuongeza shule."

    });

  }

});


// =====================================================
// GET SCHOOL ADMINS
// =====================================================

app.get("/api/school-admins", async (req, res) => {

  try {

    const result =
      await pool.query(`
        SELECT
          school_admins.id,
          school_admins.full_name,
          school_admins.email,
          school_admins.phone,
          school_admins.school_id,
          schools.name AS school_name,
          school_admins.status,
          school_admins.created_at

        FROM school_admins

        INNER JOIN schools
          ON schools.id =
             school_admins.school_id

        ORDER BY school_admins.id DESC
      `);


    res.json({

      success: true,

      admins:
        result.rows

    });

  }

  catch (error) {

    console.error(
      "Get school admins error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kupata School Admins."

    });

  }

});


// =====================================================
// ADD SCHOOL ADMIN
// =====================================================

app.post("/api/school-admins", async (req, res) => {

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
          "Tafadhali jaza taarifa zote muhimu."

      });

    }


    if (
      password.length < 6
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Password lazima iwe na angalau herufi 6."

      });

    }


    const school =
      await pool.query(

        `
        SELECT id, name
        FROM schools
        WHERE id = $1
        `,

        [school_id]

      );


    if (
      school.rows.length === 0
    ) {

      return res.status(404).json({

        success: false,

        message:
          "Shule iliyochaguliwa haipo."

      });

    }


    const passwordHash =
      hashPassword(password);


    const result =
      await pool.query(

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
          email,
          phone || null,
          school_id,
          passwordHash

        ]

      );


    res.status(201).json({

      success: true,

      message:
        "School Admin ameongezwa kwa mafanikio.",

      admin:
        result.rows[0]

    });

  }

  catch (error) {

    console.error(
      "Add school admin error:",
      error
    );


    if (
      error.code === "23505"
    ) {

      return res.status(409).json({

        success: false,

        message:
          "Email hii tayari imetumika kwa School Admin."

      });

    }


    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kuongeza School Admin."

    });

  }

});


// =====================================================
// GET SCHOOL FORMS
// =====================================================

app.get("/api/school-forms", async (req, res) => {

  try {

    const result =
      await pool.query(`
        SELECT
          school_forms.id,
          school_forms.school_id,
          schools.name AS school_name,
          school_forms.form_name,
          school_forms.price,
          school_forms.status,
          school_forms.application_start,
          school_forms.application_end,
          school_forms.created_at

        FROM school_forms

        INNER JOIN schools
          ON schools.id =
             school_forms.school_id

        ORDER BY school_forms.id DESC
      `);


    res.json({

      success: true,

      forms:
        result.rows

    });

  }

  catch (error) {

    console.error(
      "Get school forms error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kupata fomu za shule."

    });

  }

});


// =====================================================
// ADD SCHOOL FORM
// =====================================================

app.post("/api/school-forms", async (req, res) => {

  try {

    const {

      school_id,
      form_name,
      price,
      status,
      application_start,
      application_end

    } = req.body;


    if (

      !school_id ||
      !form_name ||
      price === undefined

    ) {

      return res.status(400).json({

        success: false,

        message:
          "Tafadhali jaza taarifa muhimu za fomu."

      });

    }


    if (
      Number(price) < 0
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Bei ya fomu haiwezi kuwa chini ya sifuri."

      });

    }


    const school =
      await pool.query(

        `
        SELECT id, name
        FROM schools
        WHERE id = $1
        `,

        [school_id]

      );


    if (
      school.rows.length === 0
    ) {

      return res.status(404).json({

        success: false,

        message:
          "Shule iliyochaguliwa haipo."

      });

    }


    const result =
      await pool.query(

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

          school_id,
          form_name,
          price,
          status || "active",
          application_start || null,
          application_end || null

        ]

      );


    res.status(201).json({

      success: true,

      message:
        "Fomu ya shule imeongezwa na kuhifadhiwa kwenye database.",

      form:
        result.rows[0]

    });

  }

  catch (error) {

    console.error(
      "Add school form error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kuongeza fomu ya shule."

    });

  }

});


// =====================================================
// GET APPLICATIONS
// =====================================================

app.get("/api/applications", async (req, res) => {

  try {

    const result =
      await pool.query(`

        SELECT

          applications.id,

          applications.application_number,

          applications.school_id,

          schools.name AS school_name,

          applications.form_id,

          school_forms.form_name,

          school_forms.price AS form_price,

          applications.applicant_name,

          applications.applicant_gender,

          applications.applicant_date_of_birth,

          applications.parent_name,

          applications.parent_phone,

          applications.parent_email,

          applications.address,

          applications.status,

          applications.payment_status,

          applications.created_at,

          applications.updated_at

        FROM applications

        INNER JOIN schools
          ON schools.id =
             applications.school_id

        INNER JOIN school_forms
          ON school_forms.id =
             applications.form_id

        ORDER BY applications.id DESC

      `);


    res.json({

      success: true,

      applications:
        result.rows

    });

  }

  catch (error) {

    console.error(
      "Get applications error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kupata Applications."

    });

  }

});


// =====================================================
// ADD APPLICATION
// =====================================================

app.post("/api/applications", async (req, res) => {

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
          "Shule, fomu na jina la mwombaji ni lazima."

      });

    }


    const formResult =
      await pool.query(

        `
        SELECT
          school_forms.id,
          school_forms.school_id,
          school_forms.form_name,
          school_forms.price,
          school_forms.status,
          schools.name AS school_name

        FROM school_forms

        INNER JOIN schools
          ON schools.id =
             school_forms.school_id

        WHERE
          school_forms.id = $1

        AND
          school_forms.school_id = $2
        `,

        [
          form_id,
          school_id
        ]

      );


    if (
      formResult.rows.length === 0
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Fomu hii haihusiani na shule iliyochaguliwa."

      });

    }


    const selectedForm =
      formResult.rows[0];


    if (
      selectedForm.status !== "active"
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Fomu hii haipo kwenye hali ya kupokea maombi."

      });

    }


    let applicationNumber;

    let exists = true;


    while (exists) {

      applicationNumber =
        generateApplicationNumber();


      const check =
        await pool.query(

          `
          SELECT id
          FROM applications
          WHERE application_number = $1
          `,

          [applicationNumber]

        );


      exists =
        check.rows.length > 0;

    }


    const result =
      await pool.query(

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
          address
        )

        VALUES
        (
          $1,$2,$3,$4,$5,
          $6,$7,$8,$9,$10
        )

        RETURNING *
        `,

        [

          applicationNumber,

          school_id,

          form_id,

          applicant_name,

          applicant_gender || null,

          applicant_date_of_birth || null,

          parent_name || null,

          parent_phone || null,

          parent_email || null,

          address || null

        ]

      );


    res.status(201).json({

      success: true,

      message:
        "Application imehifadhiwa kwa mafanikio.",

      application:
        result.rows[0],

      school:
        selectedForm.school_name,

      form:
        selectedForm.form_name,

      price:
        selectedForm.price

    });

  }

  catch (error) {

    console.error(
      "Add application error:",
      error
    );


    if (
      error.code === "23505"
    ) {

      return res.status(409).json({

        success: false,

        message:
          "Application number tayari ipo. Jaribu tena."

      });

    }


    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kuhifadhi Application."

    });

  }

});


// =====================================================
// GET PAYMENTS
// =====================================================

app.get("/api/payments", async (req, res) => {

  try {

    const result =
      await pool.query(`

        SELECT

          payments.id,

          payments.payment_reference,

          payments.application_id,

          payments.application_number,

          applications.applicant_name,

          schools.name AS school_name,

          payments.amount,

          payments.payment_method,

          payments.transaction_id,

          payments.payer_phone,

          payments.status,

          payments.paid_at,

          payments.created_at,

          payments.updated_at

        FROM payments

        INNER JOIN applications
          ON applications.id =
             payments.application_id

        INNER JOIN schools
          ON schools.id =
             applications.school_id

        ORDER BY payments.id DESC

      `);


    res.json({

      success: true,

      payments:
        result.rows

    });

  }

  catch (error) {

    console.error(
      "Get payments error:",
      error
    );

    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kupata Payments."

    });

  }

});


// =====================================================
// ADD PAYMENT
// =====================================================

app.post("/api/payments", async (req, res) => {

  try {

    const {

      application_id,
      amount,
      payment_method,
      transaction_id,
      payer_phone

    } = req.body;


    if (
      !application_id ||
      amount === undefined
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Application na kiasi cha malipo ni lazima."

      });

    }


    if (
      Number(amount) <= 0
    ) {

      return res.status(400).json({

        success: false,

        message:
          "Kiasi cha malipo lazima kiwe zaidi ya sifuri."

      });

    }


    const applicationResult =
      await pool.query(

        `
        SELECT
          applications.id,
          applications.application_number,
          applications.payment_status,
          school_forms.price

        FROM applications

        INNER JOIN school_forms
          ON school_forms.id =
             applications.form_id

        WHERE applications.id = $1
        `,

        [application_id]

      );


    if (
      applicationResult.rows.length === 0
    ) {

      return res.status(404).json({

        success: false,

        message:
          "Application haikupatikana."

      });

    }


    const application =
      applicationResult.rows[0];


    let paymentReference;

    let exists = true;


    while (exists) {

      paymentReference =
        generatePaymentReference();


      const check =
        await pool.query(

          `
          SELECT id
          FROM payments
          WHERE payment_reference = $1
          `,

          [paymentReference]

        );


      exists =
        check.rows.length > 0;

    }


    const paymentResult =
      await pool.query(

        `
        INSERT INTO payments
        (
          payment_reference,
          application_id,
          application_number,
          amount,
          payment_method,
          transaction_id,
          payer_phone,
          status
        )

        VALUES
        (
          $1,$2,$3,$4,$5,$6,$7,'pending'
        )

        RETURNING *
        `,

        [

          paymentReference,

          application.id,

          application.application_number,

          amount,

          payment_method || null,

          transaction_id || null,

          payer_phone || null

        ]

      );


    res.status(201).json({

      success: true,

      message:
        "Payment imehifadhiwa kwa mafanikio.",

      payment:
        paymentResult.rows[0],

      application:
        application.application_number

    });

  }

  catch (error) {

    console.error(
      "Add payment error:",
      error
    );


    if (
      error.code === "23505"
    ) {

      return res.status(409).json({

        success: false,

        message:
          "Payment reference tayari ipo."

      });

    }


    res.status(500).json({

      success: false,

      message:
        "Imeshindikana kuhifadhi Payment."

    });

  }

});


// =====================================================
// START SERVER
// =====================================================

async function startServer() {

  await initializeDatabase();


  app.listen(

    PORT,

    "0.0.0.0",

    () => {

      console.log(
        `Shule Portal Tanzania running on port ${PORT}`
      );

    }

  );

}


startServer();