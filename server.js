const express = require("express");
const path = require("path");
const crypto = require("crypto");
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


// ================================
// PASSWORD HASH
// ================================

function hashPassword(password) {

  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}


// ================================
// DATABASE INITIALIZATION
// ================================

async function initializeDatabase() {

  try {

    // ================================
    // SCHOOLS TABLE
    // ================================

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


    // ================================
    // SCHOOL ADMINS TABLE
    // ================================

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


    // ================================
    // SCHOOL FORMS TABLE
    // ================================

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


    console.log("Schools table iko tayari.");

    console.log("School Admins table iko tayari.");

    console.log("School Forms table iko tayari.");

  }

  catch (error) {

    console.error(
      "Database initialization error:",
      error
    );

  }

}


// ================================
// HOME
// ================================

app.get("/", (req, res) => {

  res.sendFile(
    path.join(__dirname, "index.html")
  );

});


// ================================
// DATABASE STATUS
// ================================

app.get("/api/status", async (req, res) => {

  try {

    const result =
      await pool.query("SELECT NOW()");

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


// ================================
// GET ALL SCHOOLS
// ================================

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


// ================================
// ADD SCHOOL
// ================================

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


// ================================
// GET SCHOOL ADMINS
// ================================

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
          ON schools.id = school_admins.school_id
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


// ================================
// ADD SCHOOL ADMIN
// ================================

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


    if (password.length < 6) {

      return res.status(400).json({

        success: false,

        message:
          "Password lazima iwe na angalau herufi 6."

      });

    }


    // Hakikisha shule ipo

    const school =
      await pool.query(

        `
        SELECT id, name
        FROM schools
        WHERE id = $1
        `,

        [school_id]

      );


    if (school.rows.length === 0) {

      return res.status(404).json({

        success: false,

        message:
          "Shule iliyochaguliwa haipo."

      });

    }


    // Hash password kabla ya kuihifadhi

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


    if (error.code === "23505") {

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


// ================================
// GET SCHOOL FORMS
// ================================

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
          ON schools.id = school_forms.school_id
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


// ================================
// ADD SCHOOL FORM
// ================================

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


    if (Number(price) < 0) {

      return res.status(400).json({

        success: false,

        message:
          "Bei ya fomu haiwezi kuwa chini ya sifuri."

      });

    }


    // Hakikisha shule ipo

    const school =
      await pool.query(

        `
        SELECT id, name
        FROM schools
        WHERE id = $1
        `,

        [school_id]

      );


    if (school.rows.length === 0) {

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


// ================================
// START SERVER
// ================================

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