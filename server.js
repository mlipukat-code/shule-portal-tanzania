const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

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
// HELPERS
// =====================================================

function hashPassword(password) {
  return crypto
    .createHash('sha256')
    .update(String(password))
    .digest('hex');
}

function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

function generateApplicationNumber() {
  return `SPT-${new Date().getFullYear()}-${crypto
    .randomBytes(4)
    .toString('hex')
    .toUpperCase()}`;
}

function generatePaymentReference() {
  return `PAY-${Date.now()}-${crypto
    .randomBytes(3)
    .toString('hex')
    .toUpperCase()}`;
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// =====================================================
// DATABASE INITIALIZATION
// =====================================================

async function initializeDatabase() {

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
      application_start DATE,
      application_end DATE,
      status VARCHAR(30) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS school_admins (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      phone VARCHAR(50),
      school_id INTEGER REFERENCES schools(id) ON DELETE SET NULL,
      password_hash TEXT NOT NULL,
      status VARCHAR(30) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS school_forms (
      id SERIAL PRIMARY KEY,
      school_id INTEGER REFERENCES schools(id) ON DELETE CASCADE,
      form_name VARCHAR(255) NOT NULL,
      price NUMERIC(12,2) DEFAULT 0,
      status VARCHAR(30) DEFAULT 'active',
      application_start DATE,
      application_end DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS applications (
      id SERIAL PRIMARY KEY,
      application_number VARCHAR(100) UNIQUE NOT NULL,
      school_id INTEGER REFERENCES schools(id) ON DELETE SET NULL,
      form_id INTEGER REFERENCES school_forms(id) ON DELETE SET NULL,
      applicant_name VARCHAR(255) NOT NULL,
      applicant_gender VARCHAR(30),
      applicant_date_of_birth DATE,
      parent_name VARCHAR(255),
      parent_phone VARCHAR(50),
      parent_email VARCHAR(255),
      address TEXT,
      status VARCHAR(30) DEFAULT 'pending',
      payment_status VARCHAR(30) DEFAULT 'unpaid',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      payment_reference VARCHAR(100) UNIQUE NOT NULL,
      application_id INTEGER REFERENCES applications(id) ON DELETE SET NULL,
      application_number VARCHAR(100),
      amount NUMERIC(12,2) NOT NULL,
      payment_method VARCHAR(50),
      transaction_id VARCHAR(255),
      payer_phone VARCHAR(50),
      status VARCHAR(30) DEFAULT 'pending',
      paid_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      status VARCHAR(30) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      id SERIAL PRIMARY KEY,
      admin_id INTEGER REFERENCES admin_users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

// =====================================================
// ADMIN USER
// =====================================================

async function syncAdminUser() {

  const email =
    process.env.ADMIN_EMAIL ||
    'admin@shuleportal.co.tz';

  const password =
    process.env.ADMIN_PASSWORD ||
    'Admin1234';

  const name =
    process.env.ADMIN_NAME ||
    'Main Administrator';

  const passwordHash =
    hashPassword(password);

  const existing =
    await pool.query(
      `
      SELECT id
      FROM admin_users
      WHERE email = $1
      LIMIT 1
      `,
      [email]
    );

  if (existing.rows.length === 0) {

    await pool.query(
      `
      INSERT INTO admin_users
      (
        name,
        email,
        password_hash,
        status
      )
      VALUES
      (
        $1,
        $2,
        $3,
        'active'
      )
      `,
      [
        name,
        email,
        passwordHash
      ]
    );

  } else {

    await pool.query(
      `
      UPDATE admin_users
      SET
        name = $1,
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
  }
}

// =====================================================
// ADMIN AUTH
// =====================================================

async function requireAdmin(req, res, next) {

  try {

    const auth =
      req.headers.authorization || '';

    if (!auth.startsWith('Bearer ')) {

      return res.status(401).json({
        success: false,
        message: 'Authorization inahitajika.'
      });
    }

    const token =
      auth.substring(7).trim();

    if (!token) {

      return res.status(401).json({
        success: false,
        message: 'Token haipo.'
      });
    }

    const result =
      await pool.query(
        `
        SELECT
          a.id,
          a.name,
          a.email
        FROM admin_sessions s
        JOIN admin_users a
          ON a.id = s.admin_id
        WHERE
          s.token = $1
          AND s.expires_at > CURRENT_TIMESTAMP
          AND a.status = 'active'
        LIMIT 1
        `,
        [token]
      );

    if (result.rows.length === 0) {

      return res.status(401).json({
        success: false,
        message:
          'Session imekwisha au si sahihi.'
      });
    }

    req.admin =
      result.rows[0];

    req.adminToken =
      token;

    return next();

  } catch (error) {

    console.error(
      'Admin auth error:',
      error
    );

    return res.status(500).json({
      success: false,
      message:
        'Imeshindikana kuthibitisha admin.'
    });
  }
}

// =====================================================
// HOME
// =====================================================

app.get('/', (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      'index.html'
    )
  );

});

// =====================================================
// API STATUS
// =====================================================

app.get('/api/status', async (req, res) => {

  try {

    await pool.query(
      'SELECT 1'
    );

    return res.json({

      success: true,

      message:
        'Shule Portal Tanzania backend na PostgreSQL vimeunganishwa',

      database:
        'connected',

      time:
        new Date().toISOString()

    });

  } catch (error) {

    console.error(
      'Status error:',
      error
    );

    return res.status(500).json({

      success: false,

      message:
        'Database haijaunganishwa.',

      database:
        'disconnected'

    });
  }
});

// =====================================================
// ADMIN LOGIN
// =====================================================

app.post(
  '/api/admin/login',
  async (req, res) => {

    try {

      const {
        email,
        password
      } = req.body;

      if (!email || !password) {

        return res.status(400).json({

          success: false,

          message:
            'Email na password vinahitajika.'

        });
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            email,
            password_hash
          FROM admin_users
          WHERE
            LOWER(email) =
            LOWER($1)
            AND status = 'active'
          LIMIT 1
          `,
          [email.trim()]
        );

      if (
        result.rows.length === 0 ||
        !verifyPassword(
          password,
          result.rows[0].password_hash
        )
      ) {

        return res.status(401).json({

          success: false,

          message:
            'Email au password si sahihi.'

        });
      }

      const admin =
        result.rows[0];

      const token =
        generateSessionToken();

      const expiresAt =
        new Date(
          Date.now() +
          12 * 60 * 60 * 1000
        );

      await pool.query(
        `
        INSERT INTO admin_sessions
        (
          admin_id,
          token,
          expires_at
        )
        VALUES
        (
          $1,
          $2,
          $3
        )
        `,
        [
          admin.id,
          token,
          expiresAt
        ]
      );

      return res.json({

        success: true,

        message:
          'Login imefanikiwa.',

        token,

        admin: {
          id: admin.id,
          name: admin.name,
          email: admin.email
        },

        expires_at:
          expiresAt

      });

    } catch (error) {

      console.error(
        'Admin login error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kuingia.'

      });
    }
  }
);

// =====================================================
// ADMIN ME
// =====================================================

app.get(
  '/api/admin/me',
  requireAdmin,
  async (req, res) => {

    return res.json({

      success: true,

      admin:
        req.admin

    });

  }
);

// =====================================================
// ADMIN LOGOUT
// =====================================================

app.post(
  '/api/admin/logout',
  requireAdmin,
  async (req, res) => {

    try {

      await pool.query(
        `
        DELETE FROM admin_sessions
        WHERE token = $1
        `,
        [req.adminToken]
      );

      return res.json({

        success: true,

        message:
          'Umetoka kwenye mfumo.'

      });

    } catch (error) {

      console.error(
        'Admin logout error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kutoka.'

      });
    }
  }
);

// =====================================================
// ADMIN DASHBOARD
// =====================================================

app.get(
  '/api/admin/dashboard',
  requireAdmin,
  async (req, res) => {

    try {

      const [
        schools,
        forms,
        applications,
        payments,
        paid,
        pendingPayments,
        paidAmount,
        pendingApplications,
        recentApplications,
        recentPayments
      ] =
        await Promise.all([

          pool.query(`
            SELECT COUNT(*)::int AS count
            FROM schools
          `),

          pool.query(`
            SELECT COUNT(*)::int AS count
            FROM school_forms
          `),

          pool.query(`
            SELECT COUNT(*)::int AS count
            FROM applications
          `),

          pool.query(`
            SELECT COUNT(*)::int AS count
            FROM payments
          `),

          pool.query(`
            SELECT COUNT(*)::int AS count
            FROM payments
            WHERE status = 'paid'
          `),

          pool.query(`
            SELECT COUNT(*)::int AS count
            FROM payments
            WHERE status = 'pending'
          `),

          pool.query(`
            SELECT
              COALESCE(
                SUM(amount),
                0
              )::numeric AS total
            FROM payments
            WHERE status = 'paid'
          `),

          pool.query(`
            SELECT COUNT(*)::int AS count
            FROM applications
            WHERE status = 'pending'
          `),

          pool.query(`
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
          `),

          pool.query(`
            SELECT
              p.id,
              p.payment_reference,
              p.amount,
              p.status,
              p.payment_method,
              p.transaction_id,
              p.created_at,
              a.application_number,
              a.applicant_name,
              s.name AS school_name
            FROM payments p
            LEFT JOIN applications a
              ON a.id = p.application_id
            LEFT JOIN schools s
              ON s.id = a.school_id
            ORDER BY p.id DESC
            LIMIT 10
          `)

        ]);

      const stats = {

        totalSchools:
          schools.rows[0].count,

        totalForms:
          forms.rows[0].count,

        totalApplications:
          applications.rows[0].count,

        totalPayments:
          payments.rows[0].count,

        paidPayments:
          paid.rows[0].count,

        pendingPayments:
          pendingPayments.rows[0].count,

        totalPaid:
          paidAmount.rows[0].total,

        pendingApplications:
          pendingApplications.rows[0].count

      };

      return res.json({

        success: true,

        stats,

        statistics:
          stats,

        recentApplications:
          recentApplications.rows,

        recentPayments:
          recentPayments.rows

      });

    } catch (error) {

      console.error(
        'Dashboard error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kupata dashboard.'

      });
    }
  }
);

// =====================================================
// ADMIN SCHOOLS
// =====================================================

app.get(
  '/api/admin/schools',
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(`
          SELECT *
          FROM schools
          ORDER BY id DESC
        `);

      return res.json({

        success: true,

        schools:
          result.rows,

        count:
          result.rows.length

      });

    } catch (error) {

      console.error(
        'Get admin schools error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kupata shule.'

      });
    }
  }
);

// =====================================================
// CREATE SCHOOL
// =====================================================

app.post(
  '/api/admin/schools',
  requireAdmin,
  async (req, res) => {

    try {

      const {
        name,
        region,
        district,
        school_type,
        type,
        form_price,
        price,
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

          message:
            'Jina la shule linahitajika.'

        });
      }

      const finalType =
        school_type ||
        type ||
        null;

      const finalPrice =
        form_price !== undefined
          ? form_price
          : (
              price !== undefined
                ? price
                : 0
            );

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
            application_end,
            status
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,
            $7,$8,$9,$10,$11
          )
          RETURNING *
          `,
          [
            name,
            region || null,
            district || null,
            finalType,
            Number(finalPrice) || 0,
            phone || null,
            address || null,
            email || null,
            application_start || null,
            application_end || null,
            status || 'active'
          ]
        );

      return res.json({

        success: true,

        message:
          'Shule imeongezwa.',

        school:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        'Create school error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kuongeza shule.'

      });
    }
  }
);

// =====================================================
// PUBLIC SCHOOLS
// =====================================================

app.get(
  '/api/schools',
  async (req, res) => {

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
          ORDER BY id DESC
        `);

      return res.json({

        success: true,

        schools:
          result.rows,

        count:
          result.rows.length

      });

    } catch (error) {

      console.error(
        'Get schools error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kupata taarifa za shule.',

        schools: []

      });
    }
  }
);

// =====================================================
// SCHOOL ADMINS
// =====================================================

app.get(
  '/api/admin/school-admins',
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(`
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
        `);

      return res.json({

        success: true,

        school_admins:
          result.rows,

        admins:
          result.rows

      });

    } catch (error) {

      console.error(
        'Get school admins error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kupata school admins.'

      });
    }
  }
);

// =====================================================
// CREATE SCHOOL ADMIN
// =====================================================

app.post(
  '/api/admin/school-admins',
  requireAdmin,
  async (req, res) => {

    try {

      const {
        full_name,
        name,
        email,
        phone,
        school_id,
        password,
        status
      } = req.body;

      const finalName =
        full_name ||
        name;

      if (
        !finalName ||
        !email ||
        !school_id ||
        !password
      ) {

        return res.status(400).json({

          success: false,

          message:
            'Jina, email, shule na password vinahitajika.'

        });
      }

      const school =
        await pool.query(
          `
          SELECT id
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [Number(school_id)]
        );

      if (school.rows.length === 0) {

        return res.status(404).json({

          success: false,

          message:
            'Shule haijapatikana.'

        });
      }

      const result =
        await pool.query(
          `
          INSERT INTO school_admins
          (
            full_name,
            email,
            phone,
            school_id,
            password_hash,
            status
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6
          )
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
            finalName,
            email.trim().toLowerCase(),
            phone || null,
            Number(school_id),
            hashPassword(password),
            status || 'active'
          ]
        );

      return res.json({

        success: true,

        message:
          'School admin ameongezwa.',

        school_admin:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        'Create school admin error:',
        error
      );

      if (error.code === '23505') {

        return res.status(409).json({

          success: false,

          message:
            'Email hiyo tayari ipo.'

        });
      }

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kuongeza school admin.'

      });
    }
  }
);

// =====================================================
// SCHOOL FORMS - ADMIN
// =====================================================

app.get(
  '/api/admin/school-forms',
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(`
          SELECT
            f.*,
            s.name AS school_name
          FROM school_forms f
          LEFT JOIN schools s
            ON s.id = f.school_id
          ORDER BY f.id DESC
        `);

      return res.json({

        success: true,

        forms:
          result.rows

      });

    } catch (error) {

      console.error(
        'Get school forms error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kupata fomu.'

      });
    }
  }
);

// =====================================================
// CREATE SCHOOL FORM
// =====================================================

app.post(
  '/api/admin/school-forms',
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

      if (
        !school_id ||
        !form_name
      ) {

        return res.status(400).json({

          success: false,

          message:
            'Shule na jina la fomu vinahitajika.'

        });
      }

      const school =
        await pool.query(
          `
          SELECT id
          FROM schools
          WHERE id = $1
          LIMIT 1
          `,
          [Number(school_id)]
        );

      if (school.rows.length === 0) {

        return res.status(404).json({

          success: false,

          message:
            'Shule haijapatikana.'

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
          (
            $1,$2,$3,$4,$5,$6
          )
          RETURNING *
          `,
          [
            Number(school_id),
            form_name,
            Number(price) || 0,
            status || 'active',
            application_start || null,
            application_end || null
          ]
        );

      return res.json({

        success: true,

        message:
          'Fomu imeongezwa.',

        form:
          result.rows[0]

      });

    } catch (error) {

      console.error(
        'Create school form error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kuongeza fomu.'

      });
    }
  }
);

// =====================================================
// PUBLIC SCHOOL FORMS
// =====================================================

app.get(
  '/api/school-forms',
  async (req, res) => {

    try {

      const schoolId =
        req.query.school_id
          ? Number(req.query.school_id)
          : null;

      const result =
        await pool.query(
          `
          SELECT
            f.*,
            s.name AS school_name,
            f.price AS form_price,
            f.form_name AS name
          FROM school_forms f
          LEFT JOIN schools s
            ON s.id = f.school_id
          WHERE
            f.status = 'active'
            AND
            (
              $1::int IS NULL
              OR f.school_id = $1
            )
          ORDER BY f.id DESC
          `,
          [schoolId]
        );

      return res.json({

        success: true,

        forms:
          result.rows,

        school_forms:
          result.rows

      });

    } catch (error) {

      console.error(
        'Get public school forms error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kupata fomu.',

        forms: []

      });
    }
  }
);

// =====================================================
// APPLICATIONS - ADMIN
// =====================================================

app.get(
  '/api/admin/applications',
  requireAdmin,
  async (req, res) => {

    try {

      const result =
        await pool.query(`
          SELECT
            a.*,
            s.name AS school_name,
            f.form_name,
            f.price AS form_price
          FROM applications a
          LEFT JOIN schools s
            ON s.id = a.school_id
          LEFT JOIN school_forms f
            ON f.id = a.form_id
          ORDER BY a.id DESC
        `);

      return res.json({

        success: true,

        applications:
          result.rows,

        count:
          result.rows.length

      });

    } catch (error) {

      console.error(
        'Get applications error:',
        error
      );

      return res.status(500).json({

        success: false,

        message:
          'Imeshindikana kupata applications.'

      });
    }
  }
);

// =====================================================
// CREATE APPLICATION
// =====================================================

app.post(
  '/api/applications',
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
            'School, form na jina la mwombaji vinahitajika.'

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

      if (
        schoolResult.rows.length === 0
      ) {

        return res.status(404).json({

          success: false,

          message:
            'Shule haipatikani au haijawezeshwa.'

        });
      }

      const formResult =
        await pool.query(
          `
          SELECT
            id,
            school_id,