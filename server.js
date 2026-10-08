const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);

const SESSION_SECRET =
  process.env.SESSION_SECRET || 'change-this-secret-in-production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

/* =========================================================
   BODY PARSERS
========================================================= */

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/* =========================================================
   STATIC FILES
========================================================= */

app.use(express.static(path.join(__dirname, 'public')));

app.get('/:file.html', (req, res, next) => {
  const fileName = String(req.params.file || '').trim();

  if (!/^[a-zA-Z0-9_-]+$/.test(fileName)) {
    return next();
  }

  const rootFile = path.join(__dirname, `${fileName}.html`);

  res.sendFile(rootFile, err => {
    if (err) return next();
  });
});

/* =========================================================
   SESSIONS
========================================================= */

const sessions = new Map();

/* =========================================================
   HELPERS
========================================================= */

function hashPassword(password) {
  return crypto
    .createHash('sha256')
    .update(String(password))
    .digest('hex');
}

function randomHex(bytes = 4) {
  return crypto
    .randomBytes(bytes)
    .toString('hex')
    .toUpperCase();
}

function generateApplicationNumber() {
  return `SPT-${new Date().getFullYear()}-${Date.now()}-${randomHex(3)}`;
}

function generatePaymentReference() {
  return `PAY-${new Date().getFullYear()}-${Date.now()}-${randomHex(3)}`;
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getBearerToken(req) {
  return String(req.headers.authorization || '')
    .replace(/^Bearer\s+/i, '')
    .trim();
}

async function q(sql, params = []) {
  const result = await pool.query(sql, params);
  return result.rows;
}

function toBoolean(value, defaultValue = false) {
  if (
    value === undefined ||
    value === null ||
    value === ''
  ) {
    return defaultValue;
  }

  if (typeof value === 'boolean') {
    return value;
  }

  const v = String(value).trim().toLowerCase();

  if (['true', '1', 'yes', 'on'].includes(v)) {
    return true;
  }

  if (['false', '0', 'no', 'off'].includes(v)) {
    return false;
  }

  return Boolean(value);
}

function cleanText(value, max = 5000) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* =========================================================
   CUSTOM FIELDS
========================================================= */

const ALLOWED_CUSTOM_FIELD_TYPES = [
  'text',
  'textarea',
  'number',
  'email',
  'phone',
  'date',
  'dropdown',
  'radio',
  'checkbox',
  'file'
];

function normalizeFieldKey(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '_')
    .replace(/[^a-z0-9_]/g, '')
    .replace(/^_+|_+$/g, '')
    .slice(0, 100);
}

function normalizeOptions(options) {
  if (!Array.isArray(options)) {
    return [];
  }

  return options
    .map(item => {
      if (item && typeof item === 'object') {
        return {
          value: String(item.value ?? '').trim(),
          label: String(
            item.label ?? item.value ?? ''
          ).trim()
        };
      }

      return {
        value: String(item ?? '').trim(),
        label: String(item ?? '').trim()
      };
    })
    .filter(x => x.value && x.label)
    .slice(0, 100);
}

function cleanCustomData(raw) {
  if (
    !raw ||
    typeof raw !== 'object' ||
    Array.isArray(raw)
  ) {
    return {};
  }

  const result = {};

  for (const [key, value] of Object.entries(raw)) {
    const safeKey = normalizeFieldKey(key);

    if (!safeKey) continue;

    if (typeof value === 'string') {
      result[safeKey] = value.trim();
    } else if (Array.isArray(value)) {
      result[safeKey] = value.map(v => String(v));
    } else if (
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      value === null
    ) {
      result[safeKey] = value;
    }
  }

  return result;
}

/* =========================================================
   AUTH
========================================================= */

function mainAdmin(req, res, next) {
  const token = getBearerToken(req);
  const session = sessions.get(token);

  if (
    !session ||
    session.role !== 'main_admin'
  ) {
    return res.status(401).json({
      success: false,
      message: 'Login ya Admin Mkuu inahitajika'
    });
  }

  req.auth = session;
  next();
}

function schoolAdmin(req, res, next) {
  const token = getBearerToken(req);
  const session = sessions.get(token);

  if (
    !session ||
    session.role !== 'school_admin'
  ) {
    return res.status(401).json({
      success: false,
      message: 'Login ya Admin wa Shule inahitajika'
    });
  }

  req.auth = session;
  next();
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {

  /* =======================================================
     SCHOOLS
  ======================================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS schools (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      region TEXT,
      district TEXT,
      school_type TEXT,
      type TEXT,
      form_price NUMERIC(12,2) DEFAULT 0,
      phone TEXT,
      address TEXT,
      email TEXT,
      application_start DATE,
      application_end DATE,
      status TEXT DEFAULT 'active',
      payment_provider TEXT,
      payment_account_id TEXT,
      payment_account_status TEXT DEFAULT 'pending',
      commission_type TEXT DEFAULT 'percent',
      commission_value NUMERIC(12,2) DEFAULT 0,
      custom_data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  /* =======================================================
     APPLICATIONS
  ======================================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS applications (
      id SERIAL PRIMARY KEY,
      application_number TEXT UNIQUE NOT NULL,
      school_id INT REFERENCES schools(id),
      form_id INT,

      applicant_name TEXT,
      applicant_gender TEXT,
      applicant_date_of_birth DATE,

      parent_name TEXT,
      parent_phone TEXT,
      parent_email TEXT,
      address TEXT,

      status TEXT DEFAULT 'Inasubiri',
      payment_status TEXT DEFAULT 'pending',

      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),

      student_name TEXT,
      gender TEXT,
      date_of_birth DATE,
      class_level TEXT,
      phone TEXT,
      email TEXT,

      custom_data JSONB NOT NULL DEFAULT '{}'::jsonb
    )
  `);

  /* =======================================================
     PAYMENTS
  ======================================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      application_id INT REFERENCES applications(id) ON DELETE CASCADE,
      application_number TEXT,
      payment_reference TEXT UNIQUE,
      amount NUMERIC(12,2) DEFAULT 0,
      status TEXT DEFAULT 'pending',
      payment_method TEXT,
      transaction_reference TEXT,
      provider TEXT,
      school_id INT REFERENCES schools(id),
      provider_account_id TEXT,
      commission_amount NUMERIC(12,2) DEFAULT 0,
      school_amount NUMERIC(12,2) DEFAULT 0,
      webhook_event_id TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  /* =======================================================
     SCHOOL ADMINS
  ======================================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS school_admins (
      id SERIAL PRIMARY KEY,
      school_id INT REFERENCES schools(id) ON DELETE CASCADE,
      full_name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  /* =======================================================
     SCHOOL ADMIN SESSIONS
  ======================================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS school_admin_sessions (
      id BIGSERIAL PRIMARY KEY,
      token_hash TEXT UNIQUE NOT NULL,
      admin_id INT REFERENCES school_admins(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  /* =======================================================
     SCHOOL CUSTOM FIELDS
  ======================================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS school_custom_fields (
      id BIGSERIAL PRIMARY KEY,
      school_id INTEGER NOT NULL
        REFERENCES schools(id)
        ON DELETE CASCADE,
      field_key VARCHAR(100) NOT NULL,
      field_label VARCHAR(255) NOT NULL,
      field_type VARCHAR(50) NOT NULL DEFAULT 'text',
      placeholder TEXT,
      options JSONB NOT NULL DEFAULT '[]'::jsonb,
      is_required BOOLEAN NOT NULL DEFAULT FALSE,
      is_visible BOOLEAN NOT NULL DEFAULT TRUE,
      show_on_public BOOLEAN NOT NULL DEFAULT TRUE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

      CONSTRAINT unique_school_custom_field_key
        UNIQUE (school_id, field_key)
    )
  `);

  /* =======================================================
     SCHOOL FORM PDF
  ======================================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS school_form_pdfs (
      id BIGSERIAL PRIMARY KEY,
      school_id INTEGER NOT NULL
        REFERENCES schools(id)
        ON DELETE CASCADE,
      file_name TEXT NOT NULL,
      mime_type TEXT NOT NULL DEFAULT 'application/pdf',
      file_data TEXT NOT NULL,
      file_size INTEGER DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      uploaded_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  /* =======================================================
     SAFE MIGRATIONS
  ======================================================= */

  const migrations = [

    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS custom_data JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS payment_provider TEXT`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS payment_account_id TEXT`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS payment_account_status TEXT DEFAULT 'pending'`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS commission_type TEXT DEFAULT 'percent'`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS commission_value NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS application_start DATE`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS application_end DATE`,
    `ALTER TABLE schools ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`,

    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS form_id INT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS applicant_name TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS applicant_gender TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS applicant_date_of_birth DATE`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS parent_name TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS parent_phone TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS parent_email TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS address TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'Inasubiri'`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS payment_status TEXT DEFAULT 'pending'`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS student_name TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS gender TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS date_of_birth DATE`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS class_level TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS phone TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS email TEXT`,
    `ALTER TABLE applications ADD COLUMN IF NOT EXISTS custom_data JSONB NOT NULL DEFAULT '{}'::jsonb`,

    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS application_number TEXT`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS amount NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'pending'`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS payment_method TEXT`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS transaction_reference TEXT`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS provider TEXT`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS school_id INT`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS provider_account_id TEXT`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS commission_amount NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS school_amount NUMERIC(12,2) DEFAULT 0`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS webhook_event_id TEXT`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`,
    `ALTER TABLE payments ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`
  ];

  for (const sql of migrations) {
    await q(sql);
  }

  /* =======================================================
     INDEXES
  ======================================================= */

  await q(`
    CREATE INDEX IF NOT EXISTS idx_applications_school
    ON applications(school_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_applications_number
    ON applications(application_number)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_payments_school
    ON payments(school_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_payments_application
    ON payments(application_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_custom_fields_school
    ON school_custom_fields(school_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS idx_school_form_pdfs_school
    ON school_form_pdfs(school_id)
  `);

  /* =======================================================
     DEMO SCHOOLS
  ======================================================= */

  const schoolCount = Number(
    (
      await q(`
        SELECT COUNT(*)::int AS count
        FROM schools
      `)
    )[0].count
  );

  if (schoolCount === 0) {

    await q(`
      INSERT INTO schools
      (
        name,
        region,
        district,
        school_type,
        type,
        form_price,
        phone,
        address,
        email,
        status
      )
      VALUES
      (
        'Mlipuka Academy',
        'Dar es Salaam',
        'Ubungo',
        'Primary & Secondary',
        'Primary & Secondary',
        20000,
        '0765447073',
        'Msumi',
        'thomsonchristom@gmail.com',
        'active'
      ),
      (
        'Brothers',
        'Arusha',
        'Ngarenaro',
        'Primary & Secondary',
        'Primary & Secondary',
        30000,
        '0616084704',
        '',
        '',
        'active'
      ),
      (
        'Bright Future School',
        'Dar es Salaam',
        'Kinondoni',
        'Primary',
        'Primary',
        20000,
        '0742505055',
        '',
        '',
        'active'
      )
    `);
  }

  /* =======================================================
     DEMO SCHOOL ADMIN
  ======================================================= */

  const adminCount = Number(
    (
      await q(`
        SELECT COUNT(*)::int AS count
        FROM school_admins
      `)
    )[0].count
  );

  if (adminCount === 0) {

    const school = (
      await q(`
        SELECT id
        FROM schools
        ORDER BY id
        LIMIT 1
      `)
    )[0];

    if (school) {

      await q(`
        INSERT INTO school_admins
        (
          school_id,
          full_name,
          email,
          password_hash,
          active
        )
        VALUES
        ($1,$2,$3,$4,true)
      `, [
        school.id,
        'Imanuel',
        'ima@john.com',
        hashPassword('123456')
      ]);
    }
  }
}

/* =========================================================
   CUSTOM FIELD FUNCTIONS
========================================================= */

async function getSchoolCustomFields(
  schoolId,
  publicOnly = false
) {

  const where = publicOnly
    ? `
      WHERE
        school_id=$1
        AND is_visible=true
        AND show_on_public=true
    `
    : `
      WHERE school_id=$1
    `;

  return q(`
    SELECT
      id,
      school_id,
      field_key,
      field_label,
      field_type,
      placeholder,
      options,
      is_required,
      is_visible,
      show_on_public,
      sort_order,
      created_at,
      updated_at
    FROM school_custom_fields
    ${where}
    ORDER BY sort_order ASC, id ASC
  `, [schoolId]);
}

function validateCustomData(fields, rawData) {

  const data = cleanCustomData(rawData);
  const errors = [];

  for (const field of fields) {

    const value = data[field.field_key];

    const empty =
      value === undefined ||
      value === null ||
      value === '' ||
      (
        Array.isArray(value) &&
        value.length === 0
      );

    if (field.is_required && empty) {

      errors.push(
        `Jaza: ${field.field_label}`
      );

      continue;
    }

    if (empty) continue;

    if (
      ['dropdown', 'radio'].includes(
        field.field_type
      )
    ) {

      const allowed = new Set(
        (
          Array.isArray(field.options)
            ? field.options
            : []
        ).map(
          o => String(o.value ?? o)
        )
      );

      if (!allowed.has(String(value))) {

        errors.push(
          `Chaguo si sahihi kwa: ${field.field_label}`
        );
      }
    }
  }

  return {
    data,
    errors
  };
}

/* =========================================================
   BASIC
========================================================= */

app.get('/api/status', (req, res) => {

  res.json({
    success: true,
    app: 'Shule Portal Tanzania',
    status: 'online',
    time: new Date().toISOString()
  });
});

app.get('/api/database-check', async (req, res) => {

  try {

    await q('SELECT 1');

    res.json({
      success: true,
      database: 'connected'
    });

  } catch (e) {

    res.status(500).json({
      success: false,
      database: 'error',
      message: e.message
    });
  }
});

/* =========================================================
   PUBLIC SCHOOLS
========================================================= */

app.get('/api/schools', async (req, res) => {

  try {

    const schools = await q(`
      SELECT *
      FROM schools
      WHERE status='active'
      ORDER BY id DESC
    `);

    res.json({
      success: true,
      schools
    });

  } catch (e) {

    res.status(500).json({
      success: false,
      message: e.message
    });
  }
});

app.get('/api/schools/:id', async (req, res) => {

  try {

    const schools = await q(`
      SELECT *
      FROM schools
      WHERE id=$1
    `, [req.params.id]);

    if (!schools[0]) {

      return res.status(404).json({
        success: false,
        message: 'Shule haipo'
      });
    }

    res.json({
      success: true,
      school: schools[0]
    });

  } catch (e) {

    res.status(500).json({
      success: false,
      message: e.message
    });
  }
});

/* =========================================================
   PUBLIC CUSTOM FIELDS
========================================================= */

app.get(
  '/api/schools/:id/custom-fields',
  async (req, res) => {

    try {

      const school = (
        await q(`
          SELECT id,status
          FROM schools
          WHERE id=$1
        `, [req.params.id])
      )[0];

      if (!school) {

        return res.status(404).json({
          success: false,
          message: 'Shule haipo'
        });
      }

      const fields =
        await getSchoolCustomFields(
          req.params.id,
          true
        );

      res.json({
        success: true,
        fields
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   CREATE APPLICATION
========================================================= */

app.post('/api/applications', async (req, res) => {

  const client = await pool.connect();

  try {

    const b = req.body || {};

    const schoolId =
      Number(b.school_id);

    const studentName =
      cleanText(b.student_name, 255);

    const gender =
      cleanText(b.gender, 50) || null;

    const dateOfBirth =
      b.date_of_birth || null;

    const classApplied =
      cleanText(
        b.class_applied,
        255
      ) || null;

    const parentName =
      cleanText(
        b.parent_name,
        255
      );

    const parentPhone =
      cleanText(
        b.parent_phone,
        100
      );

    const parentEmail =
      cleanText(
        b.parent_email,
        255
      ) || null;

    const address =
      cleanText(
        b.address,
        2000
      ) || null;

    const formId =
      b.form_id
        ? Number(b.form_id)
        : null;

    if (
      !schoolId ||
      !studentName ||
      !parentName ||
      !parentPhone
    ) {

      return res.status(400).json({
        success: false,
        message:
          'Jaza taarifa muhimu: shule, jina la mwanafunzi, jina la mzazi na simu ya mzazi.'
      });
    }

    if (
      parentEmail &&
      !isValidEmail(parentEmail)
    ) {

      return res.status(400).json({
        success: false,
        message:
          'Email ya mzazi si sahihi.'
      });
    }

    await client.query('BEGIN');

    const schoolResult =
      await client.query(`
        SELECT *
        FROM schools
        WHERE id=$1
        AND status='active'
        FOR SHARE
      `, [schoolId]);

    const school =
      schoolResult.rows[0];

    if (!school) {

      await client.query('ROLLBACK');

      return res.status(404).json({
        success: false,
        message:
          'Shule haipatikani au haijawa live.'
      });
    }

    const fields =
      await getSchoolCustomFields(
        schoolId,
        true
      );

    const validation =
      validateCustomData(
        fields,
        b.custom_data
      );

    if (validation.errors.length) {

      await client.query('ROLLBACK');

      return res.status(400).json({
        success: false,
        message:
          validation.errors.join(', '),
        errors:
          validation.errors
      });
    }

    let applicationNumber =
      generateApplicationNumber();

    let exists =
      await client.query(`
        SELECT id
        FROM applications
        WHERE application_number=$1
      `, [applicationNumber]);

    while (exists.rows[0]) {

      applicationNumber =
        generateApplicationNumber();

      exists =
        await client.query(`
          SELECT id
          FROM applications
          WHERE application_number=$1
        `, [applicationNumber]);
    }

    const insert =
      await client.query(`
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

          status,
          payment_status,

          student_name,
          gender,
          date_of_birth,
          class_level,
          phone,
          email,

          custom_data
        )
        VALUES
        (
          $1,$2,$3,
          $4,$5,$6,
          $7,$8,$9,$10,
          'Inasubiri',
          'pending',
          $4,$5,$6,$11,$8,$9,
          $12
        )
        RETURNING *
      `, [

        applicationNumber,
        schoolId,
        formId,

        studentName,
        gender,
        dateOfBirth,

        parentName,
        parentPhone,
        parentEmail,
        address,

        classApplied,
        validation.data
      ]);

    const application =
      insert.rows[0];

    const amount =
      Number(
        school.form_price || 0
      );

    const paymentReference =
      generatePaymentReference();

    const commissionType =
      school.commission_type ||
      'percent';

    const commissionValue =
      Number(
        school.commission_value || 0
      );

    let commission = 0;

    if (
      commissionType === 'fixed'
    ) {

      commission =
        commissionValue;

    } else {

      commission =
        amount *
        commissionValue /
        100;
    }

    const schoolAmount =
      Math.max(
        0,
        amount - commission
      );

    await client.query(`
      INSERT INTO payments
      (
        application_id,
        application_number,
        payment_reference,
        amount,
        status,
        provider,
        school_id,
        provider_account_id,
        commission_amount,
        school_amount
      )
      VALUES
      (
        $1,$2,$3,$4,
        'pending',
        $5,$6,$7,$8,$9
      )
    `, [

      application.id,
      applicationNumber,
      paymentReference,
      amount,

      school.payment_provider ||
        null,

      schoolId,

      school.payment_account_id ||
        null,

      commission,
      schoolAmount
    ]);

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message:
        'Maombi yamepokelewa kikamilifu.',
      application,
      application_number:
        applicationNumber,
      payment_reference:
        paymentReference,
      amount
    });

  } catch (e) {

    try {
      await client.query('ROLLBACK');
    } catch (_) {}

    console.error(
      'CREATE APPLICATION ERROR:',
      e
    );

    res.status(500).json({
      success: false,
      message:
        'Imeshindikana kutengeneza maombi.',
      error: e.message
    });

  } finally {

    client.release();
  }
});

/* =========================================================
   APPLICATION LOOKUP
========================================================= */

app.get(
  '/api/application-by-number/:applicationNumber',
  async (req, res) => {

    try {

      const application =
        (
          await q(`
            SELECT
              a.*,
              s.name AS school_name,
              s.region,
              s.district,
              s.form_price
            FROM applications a
            LEFT JOIN schools s
              ON s.id=a.school_id
            WHERE
              a.application_number=$1
          `, [
            req.params.applicationNumber
          ])
        )[0];

      if (!application) {

        return res.status(404).json({
          success: false,
          message:
            'Application haijapatikana.'
        });
      }

      const payments =
        await q(`
          SELECT *
          FROM payments
          WHERE application_number=$1
          ORDER BY id DESC
        `, [
          req.params.applicationNumber
        ]);

      res.json({
        success: true,
        application,
        payments
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   PAYMENT LOOKUP
========================================================= */

app.get(
  '/api/payments/:reference',
  async (req, res) => {

    try {

      const payment =
        (
          await q(`
            SELECT
              p.*,
              s.name AS school_name
            FROM payments p
            LEFT JOIN schools s
              ON s.id=p.school_id
            WHERE
              p.payment_reference=$1
          `, [
            req.params.reference
          ])
        )[0];

      if (!payment) {

        return res.status(404).json({
          success: false,
          message:
            'Payment haijapatikana.'
        });
      }

      res.json({
        success: true,
        payment
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   TEST PAYMENT CONFIRMATION
========================================================= */

app.put(
  '/api/payments/:reference/confirm',
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      await client.query('BEGIN');

      const payment =
        (
          await client.query(`
            SELECT *
            FROM payments
            WHERE payment_reference=$1
            FOR UPDATE
          `, [
            req.params.reference
          ])
        ).rows[0];

      if (!payment) {

        await client.query('ROLLBACK');

        return res.status(404).json({
          success: false,
          message:
            'Payment haijapatikana.'
        });
      }

      const transactionReference =
        cleanText(
          req.body.transaction_reference ||
          `TEST-${Date.now()}`,
          255
        );

      await client.query(`
        UPDATE payments
        SET
          status='paid',
          transaction_reference=$1,
          payment_method=$2,
          updated_at=NOW()
        WHERE id=$3
      `, [

        transactionReference,

        cleanText(
          req.body.payment_method ||
          'test',
          100
        ),

        payment.id
      ]);

      await client.query(`
        UPDATE applications
        SET
          payment_status='paid',
          status='Imelipiwa',
          updated_at=NOW()
        WHERE id=$1
      `, [
        payment.application_id
      ]);

      await client.query('COMMIT');

      res.json({
        success: true,
        message:
          'Malipo yamethibitishwa.',
        payment_reference:
          payment.payment_reference,
        transaction_reference:
          transactionReference
      });

    } catch (e) {

      try {
        await client.query('ROLLBACK');
      } catch (_) {}

      res.status(500).json({
        success: false,
        message: e.message
      });

    } finally {

      client.release();
    }
  }
);

/* =========================================================
   PAYMENT WEBHOOK
========================================================= */

app.post(
  '/api/payments/webhook',
  async (req, res) => {

    try {

      const body =
        req.body || {};

      const reference =
        body.payment_reference ||
        body.reference ||
        body.order_id;

      const status =
        String(
          body.status || ''
        ).toLowerCase();

      if (!reference) {

        return res.status(400).json({
          success: false,
          message:
            'Payment reference haipo.'
        });
      }

      const payment =
        (
          await q(`
            SELECT *
            FROM payments
            WHERE payment_reference=$1
          `, [reference])
        )[0];

      if (!payment) {

        return res.status(404).json({
          success: false,
          message:
            'Payment haijapatikana.'
        });
      }

      const paid =
        [
          'paid',
          'success',
          'successful',
          'completed'
        ].includes(status);

      if (paid) {

        await q(`
          UPDATE payments
          SET
            status='paid',
            transaction_reference=$1,
            payment_method=$2,
            updated_at=NOW()
          WHERE id=$3
        `, [

          body.transaction_reference ||
          body.transaction_id ||
          null,

          body.payment_method ||
          body.method ||
          null,

          payment.id
        ]);

        await q(`
          UPDATE applications
          SET
            payment_status='paid',
            status='Imelipiwa',
            updated_at=NOW()
          WHERE id=$1
        `, [
          payment.application_id
        ]);
      }

      res.json({
        success: true
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN LOGIN
========================================================= */

app.post(
  '/api/school-admin/login',
  async (req, res) => {

    try {

      const email =
        String(
          req.body.email || ''
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ''
        );

      const admin =
        (
          await q(`
            SELECT *
            FROM school_admins
            WHERE LOWER(email)=LOWER($1)
            AND active=true
          `, [email])
        )[0];

      if (
        !admin ||
        admin.password_hash !==
          hashPassword(password)
      ) {

        return res.status(401).json({
          success: false,
          message:
            'Email au password si sahihi.'
        });
      }

      const token =
        generateToken();

      sessions.set(token, {
        role: 'school_admin',
        adminId: admin.id,
        schoolId: admin.school_id,
        email: admin.email,
        createdAt: Date.now()
      });

      res.json({
        success: true,
        token,
        admin: {
          id: admin.id,
          full_name: admin.full_name,
          email: admin.email,
          school_id: admin.school_id
        }
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.get(
  '/api/school-admin/me',
  schoolAdmin,
  async (req, res) => {

    try {

      const admin =
        (
          await q(`
            SELECT
              id,
              school_id,
              full_name,
              email,
              active
            FROM school_admins
            WHERE id=$1
          `, [
            req.auth.adminId
          ])
        )[0];

      if (!admin || !admin.active) {

        return res.status(401).json({
          success: false,
          message:
            'Admin wa shule hayupo au amezimwa.'
        });
      }

      res.json({
        success: true,
        admin
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.post(
  '/api/school-admin/logout',
  schoolAdmin,
  (req, res) => {

    const token =
      getBearerToken(req);

    sessions.delete(token);

    res.json({
      success: true
    });
  }
);

/* =========================================================
   SCHOOL ADMIN SCHOOL
========================================================= */

app.get(
  '/api/school-admin/school',
  schoolAdmin,
  async (req, res) => {

    try {

      const school =
        (
          await q(`
            SELECT *
            FROM schools
            WHERE id=$1
          `, [
            req.auth.schoolId
          ])
        )[0];

      if (!school) {

        return res.status(404).json({
          success: false,
          message:
            'Shule ya Admin haipo.'
        });
      }

      res.json({
        success: true,
        school
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.put(
  '/api/school-admin/school',
  schoolAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const school =
        (
          await q(`
            UPDATE schools
            SET
              name=COALESCE($1,name),
              region=COALESCE($2,region),
              district=COALESCE($3,district),
              school_type=COALESCE($4,school_type),
              type=COALESCE($5,type),
              form_price=COALESCE($6,form_price),
              phone=COALESCE($7,phone),
              address=COALESCE($8,address),
              email=COALESCE($9,email),
              application_start=COALESCE($10,application_start),
              application_end=COALESCE($11,application_end),
              updated_at=NOW()
            WHERE id=$12
            RETURNING *
          `, [

            b.name,
            b.region,
            b.district,
            b.school_type,
            b.type,

            b.form_price !== undefined
              ? Number(b.form_price)
              : null,

            b.phone,
            b.address,
            b.email,

            b.application_start,
            b.application_end,

            req.auth.schoolId
          ])
        )[0];

      if (!school) {

        return res.status(404).json({
          success: false,
          message:
            'Shule haipo.'
        });
      }

      res.json({
        success: true,
        school
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   PUBLISH SCHOOL
========================================================= */

app.post(
  '/api/school-admin/school/publish',
  schoolAdmin,
  async (req, res) => {

    try {

      const school =
        (
          await q(`
            UPDATE schools
            SET
              status='active',
              updated_at=NOW()
            WHERE id=$1
            RETURNING *
          `, [
            req.auth.schoolId
          ])
        )[0];

      res.json({
        success: true,
        school
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.post(
  '/api/school-admin/school/unpublish',
  schoolAdmin,
  async (req, res) => {

    try {

      const school =
        (
          await q(`
            UPDATE schools
            SET
              status='inactive',
              updated_at=NOW()
            WHERE id=$1
            RETURNING *
          `, [
            req.auth.schoolId
          ])
        )[0];

      res.json({
        success: true,
        school
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN CUSTOM FIELDS - LIST
========================================================= */

app.get(
  '/api/school-admin/custom-fields',
  schoolAdmin,
  async (req, res) => {

    try {

      const fields =
        await getSchoolCustomFields(
          req.auth.schoolId,
          false
        );

      res.json({
        success: true,
        fields
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN CUSTOM FIELDS - CREATE
========================================================= */

app.post(
  '/api/school-admin/custom-fields',
  schoolAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const key =
        normalizeFieldKey(
          b.field_key ||
          b.field_label
        );

      const label =
        cleanText(
          b.field_label,
          255
        );

      const type =
        String(
          b.field_type ||
          'text'
        ).trim();

      if (!key || !label) {

        return res.status(400).json({
          success: false,
          message:
            'Field label na field key vinahitajika.'
        });
      }

      if (
        !ALLOWED_CUSTOM_FIELD_TYPES
          .includes(type)
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Field type si sahihi.'
        });
      }

      const field =
        (
          await q(`
            INSERT INTO school_custom_fields
            (
              school_id,
              field_key,
              field_label,
              field_type,
              placeholder,
              options,
              is_required,
              is_visible,
              show_on_public,
              sort_order
            )
            VALUES
            (
              $1,$2,$3,$4,$5,$6,
              $7,$8,$9,$10
            )
            RETURNING *
          `, [

            req.auth.schoolId,

            key,

            label,

            type,

            b.placeholder || null,

            JSON.stringify(
              normalizeOptions(
                b.options
              )
            ),

            toBoolean(
              b.is_required
            ),

            toBoolean(
              b.is_visible,
              true
            ),

            toBoolean(
              b.show_on_public,
              true
            ),

            Number(
              b.sort_order || 0
            )
          ])
        )[0];

      res.status(201).json({
        success: true,
        field
      });

    } catch (e) {

      if (e.code === '23505') {

        return res.status(409).json({
          success: false,
          message:
            'Field yenye jina hilo tayari ipo.'
        });
      }

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN CUSTOM FIELDS - UPDATE
========================================================= */

app.put(
  '/api/school-admin/custom-fields/:fieldId',
  schoolAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const key =
        b.field_key !== undefined
          ? normalizeFieldKey(
              b.field_key
            )
          : null;

      const label =
        b.field_label !== undefined
          ? cleanText(
              b.field_label,
              255
            )
          : null;

      const type =
        b.field_type !== undefined
          ? String(
              b.field_type
            ).trim()
          : null;

      if (
        type &&
        !ALLOWED_CUSTOM_FIELD_TYPES
          .includes(type)
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Field type si sahihi.'
        });
      }

      const field =
        (
          await q(`
            UPDATE school_custom_fields
            SET
              field_label=
                COALESCE($1,field_label),

              field_key=
                COALESCE($2,field_key),

              field_type=
                COALESCE($3,field_type),

              placeholder=
                COALESCE($4,placeholder),

              options=
                COALESCE($5,options),

              is_required=
                COALESCE($6,is_required),

              is_visible=
                COALESCE($7,is_visible),

              show_on_public=
                COALESCE($8,show_on_public),

              sort_order=
                COALESCE($9,sort_order),

              updated_at=NOW()

            WHERE
              id=$10
              AND school_id=$11

            RETURNING *
          `, [

            label,

            key,

            type,

            b.placeholder !== undefined
              ? b.placeholder
              : null,

            b.options !== undefined
              ? JSON.stringify(
                  normalizeOptions(
                    b.options
                  )
                )
              : null,

            b.is_required !== undefined
              ? toBoolean(
                  b.is_required
                )
              : null,

            b.is_visible !== undefined
              ? toBoolean(
                  b.is_visible
                )
              : null,

            b.show_on_public !== undefined
              ? toBoolean(
                  b.show_on_public
                )
              : null,

            b.sort_order !== undefined
              ? Number(
                  b.sort_order
                )
              : null,

            req.params.fieldId,

            req.auth.schoolId
          ])
        )[0];

      if (!field) {

        return res.status(404).json({
          success: false,
          message:
            'Field haipo.'
        });
      }

      res.json({
        success: true,
        field
      });

    } catch (e) {

      if (e.code === '23505') {

        return res.status(409).json({
          success: false,
          message:
            'Field key hiyo tayari ipo.'
        });
      }

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN CUSTOM FIELDS - DELETE
========================================================= */

app.delete(
  '/api/school-admin/custom-fields/:fieldId',
  schoolAdmin,
  async (req, res) => {

    try {

      const result =
        await q(`
          DELETE FROM school_custom_fields
          WHERE
            id=$1
            AND school_id=$2
          RETURNING id
        `, [

          req.params.fieldId,

          req.auth.schoolId
        ]);

      if (!result[0]) {

        return res.status(404).json({
          success: false,
          message:
            'Field haipo.'
        });
      }

      res.json({
        success: true
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN PDF - INFORMATION
========================================================= */

app.get(
  '/api/school-admin/form-pdf',
  schoolAdmin,
  async (req, res) => {

    try {

      const pdf =
        (
          await q(`
            SELECT
              id,
              school_id,
              file_name,
              mime_type,
              file_size,
              active,
              uploaded_at,
              updated_at
            FROM school_form_pdfs
            WHERE
              school_id=$1
              AND active=true
            ORDER BY id DESC
            LIMIT 1
          `, [
            req.auth.schoolId
          ])
        )[0];

      res.json({
        success: true,
        pdf: pdf || null
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN PDF - UPLOAD
========================================================= */

app.post(
  '/api/school-admin/form-pdf',
  schoolAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const fileName =
        cleanText(
          b.file_name ||
          'school-form.pdf',
          255
        );

      const mimeType =
        String(
          b.mime_type ||
          'application/pdf'
        ).trim();

      let fileData =
        String(
          b.file_data || ''
        ).trim();

      if (!fileData) {

        return res.status(400).json({
          success: false,
          message:
            'PDF haijawekwa.'
        });
      }

      if (
        mimeType !==
        'application/pdf'
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Tafadhali upload PDF pekee.'
        });
      }

      /*
        Kama frontend imetuma:
        data:application/pdf;base64,XXXX

        tunabaki na sehemu ya base64.
      */

      if (
        fileData.startsWith(
          'data:application/pdf;base64,'
        )
      ) {

        fileData =
          fileData.replace(
            'data:application/pdf;base64,',
            ''
          );
      }

      /*
        Ondoa spaces/new lines za base64
      */

      fileData =
        fileData.replace(
          /\s/g,
          ''
        );

      /*
        Maximum takriban 7MB
        kwa PDF iliyohifadhiwa.
      */

      const estimatedSize =
        Math.floor(
          fileData.length * 0.75
        );

      const MAX_PDF_SIZE =
        7 * 1024 * 1024;

      if (
        estimatedSize >
        MAX_PDF_SIZE
      ) {

        return res.status(413).json({
          success: false,
          message:
            'PDF ni kubwa sana. Tafadhali tumia PDF isiyozidi 7MB.'
        });
      }

      /*
        Hakikisha inaonekana kama Base64.
      */

      if (
        !/^[A-Za-z0-9+/]*={0,2}$/.test(
          fileData
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            'PDF data si sahihi.'
        });
      }

      /*
        Zima PDF ya zamani
      */

      await q(`
        UPDATE school_form_pdfs
        SET
          active=false,
          updated_at=NOW()
        WHERE
          school_id=$1
      `, [
        req.auth.schoolId
      ]);

      /*
        Weka mpya
      */

      const pdf =
        (
          await q(`
            INSERT INTO school_form_pdfs
            (
              school_id,
              file_name,
              mime_type,
              file_data,
              file_size,
              active
            )
            VALUES
            (
              $1,$2,$3,$4,$5,true
            )
            RETURNING
              id,
              school_id,
              file_name,
              mime_type,
              file_size,
              active,
              uploaded_at,
              updated_at
          `, [

            req.auth.schoolId,

            fileName,

            'application/pdf',

            fileData,

            estimatedSize
          ])
        )[0];

      res.status(201).json({
        success: true,
        message:
          'PDF ya fomu imewekwa kikamilifu.',
        pdf
      });

    } catch (e) {

      console.error(
        'PDF UPLOAD ERROR:',
        e
      );

      res.status(500).json({
        success: false,
        message:
          'Imeshindikana kuhifadhi PDF.',
        error: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN PDF - DELETE
========================================================= */

app.delete(
  '/api/school-admin/form-pdf',
  schoolAdmin,
  async (req, res) => {

    try {

      await q(`
        UPDATE school_form_pdfs
        SET
          active=false,
          updated_at=NOW()
        WHERE
          school_id=$1
      `, [
        req.auth.schoolId
      ]);

      res.json({
        success: true,
        message:
          'PDF imeondolewa kwenye mfumo.'
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   PAID APPLICATION → DOWNLOAD ACTUAL SCHOOL PDF
========================================================= */

app.get(
  '/api/application/:applicationNumber/form-pdf',
  async (req, res) => {

    try {

      const application =
        (
          await q(`
            SELECT
              a.id,
              a.application_number,
              a.school_id,
              a.payment_status,
              s.name AS school_name
            FROM applications a
            LEFT JOIN schools s
              ON s.id=a.school_id
            WHERE
              a.application_number=$1
          `, [
            req.params.applicationNumber
          ])
        )[0];

      if (!application) {

        return res.status(404).json({
          success: false,
          message:
            'Application haijapatikana.'
        });
      }

      /*
        PDF inatolewa baada ya malipo
        kuthibitishwa.
      */

      if (
        String(
          application.payment_status
        ).toLowerCase() !== 'paid'
      ) {

        return res.status(403).json({
          success: false,
          message:
            'Fomu haiwezi kutolewa kabla ya malipo kuthibitishwa.'
        });
      }

      const pdf =
        (
          await q(`
            SELECT
              file_name,
              mime_type,
              file_data
            FROM school_form_pdfs
            WHERE
              school_id=$1
              AND active=true
            ORDER BY id DESC
            LIMIT 1
          `, [
            application.school_id
          ])
        )[0];

      if (!pdf) {

        return res.status(404).json({
          success: false,
          message:
            'Shule bado haijaweka PDF ya fomu.'
        });
      }

      const buffer =
        Buffer.from(
          pdf.file_data,
          'base64'
        );

      const safeFileName =
        String(
          pdf.file_name ||
          'school-form.pdf'
        )
          .replace(
            /[^a-zA-Z0-9._-]/g,
            '_'
          );

      res.setHeader(
        'Content-Type',
        'application/pdf'
      );

      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${safeFileName}"`
      );

      res.setHeader(
        'Content-Length',
        buffer.length
      );

      res.send(buffer);

    } catch (e) {

      console.error(
        'DOWNLOAD SCHOOL PDF ERROR:',
        e
      );

      res.status(500).json({
        success: false,
        message:
          'Imeshindikana kutoa PDF.'
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN APPLICATIONS
========================================================= */

app.get(
  '/api/school-admin/applications',
  schoolAdmin,
  async (req, res) => {

    try {

      const applications =
        await q(`
          SELECT
            a.*,
            p.payment_reference,
            p.amount,
            p.status AS payment_record_status,
            p.transaction_reference,
            p.payment_method,
            p.updated_at AS payment_updated_at
          FROM applications a
          LEFT JOIN payments p
            ON p.application_id=a.id
          WHERE a.school_id=$1
          ORDER BY a.id DESC
        `, [
          req.auth.schoolId
        ]);

      res.json({
        success: true,
        applications
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.put(
  '/api/school-admin/applications/:id/status',
  schoolAdmin,
  async (req, res) => {

    try {

      const status =
        cleanText(
          req.body.status,
          100
        );

      if (!status) {

        return res.status(400).json({
          success: false,
          message:
            'Status inahitajika.'
        });
      }

      const application =
        (
          await q(`
            UPDATE applications
            SET
              status=$1,
              updated_at=NOW()
            WHERE
              id=$2
              AND school_id=$3
            RETURNING *
          `, [

            status,

            req.params.id,

            req.auth.schoolId
          ])
        )[0];

      if (!application) {

        return res.status(404).json({
          success: false,
          message:
            'Application haipo.'
        });
      }

      res.json({
        success: true,
        application
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHOOL ADMIN PAYMENTS
========================================================= */

app.get(
  '/api/school-admin/payments',
  schoolAdmin,
  async (req, res) => {

    try {

      const payments =
        await q(`
          SELECT *
          FROM payments
          WHERE school_id=$1
          ORDER BY id DESC
        `, [
          req.auth.schoolId
        ]);

      res.json({
        success: true,
        payments
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN LOGIN
========================================================= */

app.post(
  '/api/admin/login',
  async (req, res) => {

    try {

      const email =
        String(
          req.body.email || ''
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ''
        );

      const adminEmail =
        process.env.ADMIN_EMAIL ||
        'admin@shuleportal.co.tz';

      const adminPassword =
        process.env.ADMIN_PASSWORD ||
        'Admin@123';

      if (
        email !==
          adminEmail.toLowerCase() ||
        password !==
          adminPassword
      ) {

        return res.status(401).json({
          success: false,
          message:
            'Email au password si sahihi.'
        });
      }

      const token =
        generateToken();

      sessions.set(token, {
        role: 'main_admin',
        email,
        createdAt: Date.now()
      });

      res.json({
        success: true,
        token,
        admin: {
          email
        }
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.get(
  '/api/admin/me',
  mainAdmin,
  (req, res) => {

    res.json({
      success: true,
      admin: {
        email:
          req.auth.email
      }
    });
  }
);

app.post(
  '/api/admin/logout',
  mainAdmin,
  (req, res) => {

    const token =
      getBearerToken(req);

    sessions.delete(token);

    res.json({
      success: true
    });
  }
);

/* =========================================================
   MAIN ADMIN SCHOOLS
========================================================= */

app.get(
  '/api/admin/schools',
  mainAdmin,
  async (req, res) => {

    try {

      const schools =
        await q(`
          SELECT
            s.*,
            (
              SELECT COUNT(*)
              FROM applications a
              WHERE a.school_id=s.id
            )::int AS applicant_count
          FROM schools s
          ORDER BY s.id DESC
        `);

      res.json({
        success: true,
        schools
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.post(
  '/api/admin/schools',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const name =
        cleanText(
          b.name,
          255
        );

      if (!name) {

        return res.status(400).json({
          success: false,
          message:
            'Jina la shule linahitajika.'
        });
      }

      const school =
        (
          await q(`
            INSERT INTO schools
            (
              name,
              region,
              district,
              school_type,
              type,
              form_price,
              phone,
              address,
              email,
              status,
              application_start,
              application_end
            )
            VALUES
            (
              $1,$2,$3,$4,$5,$6,
              $7,$8,$9,$10,$11,$12
            )
            RETURNING *
          `, [

            name,

            b.region || null,

            b.district || null,

            b.school_type ||
              b.type ||
              null,

            b.type ||
              b.school_type ||
              null,

            Number(
              b.form_price || 0
            ),

            b.phone || null,

            b.address || null,

            b.email || null,

            b.status ||
              'active',

            b.application_start ||
              null,

            b.application_end ||
              null
          ])
        )[0];

      res.status(201).json({
        success: true,
        school
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.put(
  '/api/admin/schools/:id',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const school =
        (
          await q(`
            UPDATE schools
            SET
              name=COALESCE($1,name),
              region=COALESCE($2,region),
              district=COALESCE($3,district),
              school_type=COALESCE($4,school_type),
              type=COALESCE($5,type),
              form_price=COALESCE($6,form_price),
              phone=COALESCE($7,phone),
              address=COALESCE($8,address),
              email=COALESCE($9,email),
              status=COALESCE($10,status),
              application_start=COALESCE($11,application_start),
              application_end=COALESCE($12,application_end),
              updated_at=NOW()
            WHERE id=$13
            RETURNING *
          `, [

            b.name,

            b.region,

            b.district,

            b.school_type,

            b.type,

            b.form_price !== undefined
              ? Number(
                  b.form_price
                )
              : null,

            b.phone,

            b.address,

            b.email,

            b.status,

            b.application_start,

            b.application_end,

            req.params.id
          ])
        )[0];

      if (!school) {

        return res.status(404).json({
          success: false,
          message:
            'Shule haipo.'
        });
      }

      res.json({
        success: true,
        school
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.delete(
  '/api/admin/schools/:id',
  mainAdmin,
  async (req, res) => {

    try {

      const school =
        (
          await q(`
            UPDATE schools
            SET
              status='inactive',
              updated_at=NOW()
            WHERE id=$1
            RETURNING *
          `, [
            req.params.id
          ])
        )[0];

      if (!school) {

        return res.status(404).json({
          success: false,
          message:
            'Shule haipo.'
        });
      }

      res.json({
        success: true,
        school
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN CUSTOM FIELDS
========================================================= */

app.get(
  '/api/admin/schools/:schoolId/custom-fields',
  mainAdmin,
  async (req, res) => {

    try {

      const fields =
        await getSchoolCustomFields(
          req.params.schoolId,
          false
        );

      res.json({
        success: true,
        fields
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.post(
  '/api/admin/schools/:schoolId/custom-fields',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const school =
        (
          await q(`
            SELECT id
            FROM schools
            WHERE id=$1
          `, [
            req.params.schoolId
          ])
        )[0];

      if (!school) {

        return res.status(404).json({
          success: false,
          message:
            'Shule haipo.'
        });
      }

      const key =
        normalizeFieldKey(
          b.field_key ||
          b.field_label
        );

      const label =
        cleanText(
          b.field_label,
          255
        );

      const type =
        String(
          b.field_type ||
          'text'
        ).trim();

      if (!key || !label) {

        return res.status(400).json({
          success: false,
          message:
            'Jina la kipengele na Field Key vinahitajika.'
        });
      }

      if (
        !ALLOWED_CUSTOM_FIELD_TYPES
          .includes(type)
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Aina ya field si sahihi.'
        });
      }

      const field =
        (
          await q(`
            INSERT INTO school_custom_fields
            (
              school_id,
              field_key,
              field_label,
              field_type,
              placeholder,
              options,
              is_required,
              is_visible,
              show_on_public,
              sort_order
            )
            VALUES
            (
              $1,$2,$3,$4,$5,$6,
              $7,$8,$9,$10
            )
            RETURNING *
          `, [

            req.params.schoolId,

            key,

            label,

            type,

            b.placeholder ||
              null,

            JSON.stringify(
              normalizeOptions(
                b.options
              )
            ),

            toBoolean(
              b.is_required
            ),

            toBoolean(
              b.is_visible,
              true
            ),

            toBoolean(
              b.show_on_public,
              true
            ),

            Number(
              b.sort_order || 0
            )
          ])
        )[0];

      res.status(201).json({
        success: true,
        field
      });

    } catch (e) {

      if (e.code === '23505') {

        return res.status(409).json({
          success: false,
          message:
            'Field key hiyo tayari ipo.'
        });
      }

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.put(
  '/api/admin/schools/:schoolId/custom-fields/:fieldId',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const field =
        (
          await q(`
            UPDATE school_custom_fields
            SET
              field_label=
                COALESCE($1,field_label),

              field_key=
                COALESCE($2,field_key),

              field_type=
                COALESCE($3,field_type),

              placeholder=
                COALESCE($4,placeholder),

              options=
                COALESCE($5,options),

              is_required=
                COALESCE($6,is_required),

              is_visible=
                COALESCE($7,is_visible),

              show_on_public=
                COALESCE($8,show_on_public),

              sort_order=
                COALESCE($9,sort_order),

              updated_at=NOW()

            WHERE
              id=$10
              AND school_id=$11

            RETURNING *
          `, [

            b.field_label ||
              null,

            b.field_key
              ? normalizeFieldKey(
                  b.field_key
                )
              : null,

            b.field_type ||
              null,

            b.placeholder ||
              null,

            b.options
              ? JSON.stringify(
                  normalizeOptions(
                    b.options
                  )
                )
              : null,

            b.is_required !==
              undefined
              ? toBoolean(
                  b.is_required
                )
              : null,

            b.is_visible !==
              undefined
              ? toBoolean(
                  b.is_visible
                )
              : null,

            b.show_on_public !==
              undefined
              ? toBoolean(
                  b.show_on_public
                )
              : null,

            b.sort_order !==
              undefined
              ? Number(
                  b.sort_order
                )
              : null,

            req.params.fieldId,

            req.params.schoolId
          ])
        )[0];

      if (!field) {

        return res.status(404).json({
          success: false,
          message:
            'Field haipo.'
        });
      }

      res.json({
        success: true,
        field
      });

    } catch (e) {

      if (e.code === '23505') {

        return res.status(409).json({
          success: false,
          message:
            'Field key hiyo tayari ipo.'
        });
      }

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

app.delete(
  '/api/admin/schools/:schoolId/custom-fields/:fieldId',
  mainAdmin,
  async (req, res) => {

    try {

      const result =
        await q(`
          DELETE FROM school_custom_fields
          WHERE
            id=$1
            AND school_id=$2
          RETURNING id
        `, [

          req.params.fieldId,

          req.params.schoolId
        ]);

      if (!result[0]) {

        return res.status(404).json({
          success: false,
          message:
            'Field haipo.'
        });
      }

      res.json({
        success: true
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN STATS
========================================================= */

app.get(
  '/api/admin/dashboard-stats',
  mainAdmin,
  async (req, res) => {

    try {

      const schools =
        Number(
          (
            await q(`
              SELECT COUNT(*)::int AS count
              FROM schools
            `)
          )[0].count
        );

      const activeSchools =
        Number(
          (
            await q(`
              SELECT COUNT(*)::int AS count
              FROM schools
              WHERE status='active'
            `)
          )[0].count
        );

      const applicants =
        Number(
          (
            await q(`
              SELECT COUNT(*)::int AS count
              FROM applications
            `)
          )[0].count
        );

      const paid =
        Number(
          (
            await q(`
              SELECT COUNT(*)::int AS count
              FROM applications
              WHERE payment_status='paid'
            `)
          )[0].count
        );

      res.json({
        success: true,
        stats: {
          schools,
          active_schools:
            activeSchools,
          applicants,
          paid_applications:
            paid
        }
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN SCHOOL ADMINS - LIST
========================================================= */

app.get(
  '/api/admin/school-admins',
  mainAdmin,
  async (req, res) => {

    try {

      const admins =
        await q(`
          SELECT
            sa.id,
            sa.school_id,
            sa.full_name,
            sa.email,
            sa.active,
            sa.created_at,
            sa.updated_at,
            s.name AS school_name
          FROM school_admins sa
          LEFT JOIN schools s
            ON s.id=sa.school_id
          ORDER BY sa.id DESC
        `);

      res.json({
        success: true,
        admins
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN SCHOOL ADMIN - SINGLE
========================================================= */

app.get(
  '/api/admin/school-admins/:id',
  mainAdmin,
  async (req, res) => {

    try {

      const admin =
        (
          await q(`
            SELECT
              sa.id,
              sa.school_id,
              sa.full_name,
              sa.email,
              sa.active,
              sa.created_at,
              sa.updated_at,
              s.name AS school_name
            FROM school_admins sa
            LEFT JOIN schools s
              ON s.id=sa.school_id
            WHERE sa.id=$1
          `, [
            req.params.id
          ])
        )[0];

      if (!admin) {

        return res.status(404).json({
          success: false,
          message:
            'Admin wa shule haipo.'
        });
      }

      res.json({
        success: true,
        admin
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN SCHOOL ADMIN - CREATE
========================================================= */

app.post(
  '/api/admin/school-admins',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const fullName =
        cleanText(
          b.full_name,
          255
        );

      const email =
        String(
          b.email || ''
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          b.password || ''
        );

      const schoolId =
        Number(
          b.school_id
        );

      const active =
        b.active !== undefined
          ? toBoolean(
              b.active
            )
          : (
              String(
                b.status || 'active'
              ).toLowerCase() !==
              'inactive'
            );

      if (
        !fullName ||
        !email ||
        !password ||
        !schoolId
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Jaza taarifa zote za Admin wa Shule.'
        });
      }

      if (
        !isValidEmail(email)
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Email si sahihi.'
        });
      }

      if (password.length < 6) {

        return res.status(400).json({
          success: false,
          message:
            'Password lazima iwe na angalau characters 6.'
        });
      }

      const school =
        (
          await q(`
            SELECT id,name
            FROM schools
            WHERE id=$1
          `, [
            schoolId
          ])
        )[0];

      if (!school) {

        return res.status(404).json({
          success: false,
          message:
            'Shule uliyochagua haipo.'
        });
      }

      const existing =
        (
          await q(`
            SELECT id
            FROM school_admins
            WHERE LOWER(email)=LOWER($1)
          `, [
            email
          ])
        )[0];

      if (existing) {

        return res.status(409).json({
          success: false,
          message:
            'Email hiyo tayari imetumika kwa Admin mwingine.'
        });
      }

      const admin =
        (
          await q(`
            INSERT INTO school_admins
            (
              school_id,
              full_name,
              email,
              password_hash,
              active
            )
            VALUES
            ($1,$2,$3,$4,$5)
            RETURNING
              id,
              school_id,
              full_name,
              email,
              active,
              created_at
          `, [

            schoolId,

            fullName,

            email,

            hashPassword(
              password
            ),

            active
          ])
        )[0];

      res.status(201).json({
        success: true,
        message:
          'Admin wa shule ameundwa.',
        admin
      });

    } catch (e) {

      if (e.code === '23505') {

        return res.status(409).json({
          success: false,
          message:
            'Email hiyo tayari ipo.'
        });
      }

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN SCHOOL ADMIN - UPDATE
========================================================= */

app.put(
  '/api/admin/school-admins/:id',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const fullName =
        b.full_name !== undefined
          ? cleanText(
              b.full_name,
              255
            )
          : null;

      const email =
        b.email !== undefined
          ? String(
              b.email || ''
            )
              .trim()
              .toLowerCase()
          : null;

      const schoolId =
        b.school_id !== undefined
          ? Number(
              b.school_id
            )
          : null;

      const active =
        b.active !== undefined
          ? toBoolean(
              b.active
            )
          : (
              b.status !== undefined
                ? String(
                    b.status
                  ).toLowerCase() !==
                  'inactive'
                : null
            );

      if (
        email &&
        !isValidEmail(email)
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Email si sahihi.'
        });
      }

      if (
        schoolId !== null
      ) {

        const school =
          (
            await q(`
              SELECT id
              FROM schools
              WHERE id=$1
            `, [
              schoolId
            ])
          )[0];

        if (!school) {

          return res.status(404).json({
            success: false,
            message:
              'Shule uliyochagua haipo.'
          });
        }
      }

      if (email) {

        const duplicate =
          (
            await q(`
              SELECT id
              FROM school_admins
              WHERE
                LOWER(email)=LOWER($1)
                AND id<>$2
            `, [
              email,
              req.params.id
            ])
          )[0];

        if (duplicate) {

          return res.status(409).json({
            success: false,
            message:
              'Email hiyo tayari imetumika.'
          });
        }
      }

      const admin =
        (
          await q(`
            UPDATE school_admins
            SET
              full_name=
                COALESCE($1,full_name),

              email=
                COALESCE($2,email),

              school_id=
                COALESCE($3,school_id),

              active=
                COALESCE($4,active),

              updated_at=NOW()

            WHERE id=$5

            RETURNING
              id,
              school_id,
              full_name,
              email,
              active,
              created_at,
              updated_at
          `, [

            fullName,

            email,

            schoolId,

            active,

            req.params.id
          ])
        )[0];

      if (!admin) {

        return res.status(404).json({
          success: false,
          message:
            'Admin wa shule haipo.'
        });
      }

      /*
        Kama Admin amezimwa,
        sessions zake zinaondolewa.
      */

      if (admin.active === false) {

        for (
          const [
            token,
            session
          ] of sessions.entries()
        ) {

          if (
            session.role ===
              'school_admin' &&
            Number(
              session.adminId
            ) === Number(
              admin.id
            )
          ) {

            sessions.delete(
              token
            );
          }
        }
      }

      res.json({
        success: true,
        message:
          'Taarifa za Admin zimebadilishwa.',
        admin
      });

    } catch (e) {

      if (e.code === '23505') {

        return res.status(409).json({
          success: false,
          message:
            'Email hiyo tayari ipo.'
        });
      }

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN SCHOOL ADMIN - STATUS
========================================================= */

app.put(
  '/api/admin/school-admins/:id/status',
  mainAdmin,
  async (req, res) => {

    try {

      const active =
        toBoolean(
          req.body.active,
          true
        );

      const admin =
        (
          await q(`
            UPDATE school_admins
            SET
              active=$1,
              updated_at=NOW()
            WHERE id=$2
            RETURNING
              id,
              school_id,
              full_name,
              email,
              active
          `, [

            active,

            req.params.id
          ])
        )[0];

      if (!admin) {

        return res.status(404).json({
          success: false,
          message:
            'Admin wa shule haipo.'
        });
      }

      /*
        Akizimwa, token zake zote
        zinaondolewa mara moja.
      */

      if (!active) {

        for (
          const [
            token,
            session
          ] of sessions.entries()
        ) {

          if (
            session.role ===
              'school_admin' &&
            Number(
              session.adminId
            ) === Number(
              admin.id
            )
          ) {

            sessions.delete(
              token
            );
          }
        }
      }

      res.json({
        success: true,
        message:
          active
            ? 'Admin amewezeshwa.'
            : 'Admin amezimwa.',
        admin
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN SCHOOL ADMIN - RESET PASSWORD
========================================================= */

app.put(
  '/api/admin/school-admins/:id/reset-password',
  mainAdmin,
  async (req, res) => {

    try {

      const password =
        String(
          req.body.password || ''
        );

      if (
        password.length < 6
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Password mpya lazima iwe na angalau characters 6.'
        });
      }

      const admin =
        (
          await q(`
            UPDATE school_admins
            SET
              password_hash=$1,
              updated_at=NOW()
            WHERE id=$2
            RETURNING
              id,
              school_id,
              full_name,
              email,
              active
          `, [

            hashPassword(
              password
            ),

            req.params.id
          ])
        )[0];

      if (!admin) {

        return res.status(404).json({
          success: false,
          message:
            'Admin wa shule haipo.'
        });
      }

      /*
        Logout sessions zote za admin huyo
        baada ya password kubadilishwa.
      */

      for (
        const [
          token,
          session
        ] of sessions.entries()
      ) {

        if (
          session.role ===
            'school_admin' &&
          Number(
            session.adminId
          ) === Number(
            admin.id
          )
        ) {

          sessions.delete(
            token
          );
        }
      }

      res.json({
        success: true,
        message:
          'Password imebadilishwa. Admin atumie password mpya.',
        admin
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN SCHOOL ADMIN - DELETE
========================================================= */

app.delete(
  '/api/admin/school-admins/:id',
  mainAdmin,
  async (req, res) => {

    try {

      /*
        Kwanza toa sessions zake.
      */

      for (
        const [
          token,
          session
        ] of sessions.entries()
      ) {

        if (
          session.role ===
            'school_admin' &&
          Number(
            session.adminId
          ) === Number(
            req.params.id
          )
        ) {

          sessions.delete(
            token
          );
        }
      }

      const admin =
        (
          await q(`
            DELETE FROM school_admins
            WHERE id=$1
            RETURNING
              id,
              school_id,
              full_name,
              email
          `, [
            req.params.id
          ])
        )[0];

      if (!admin) {

        return res.status(404).json({
          success: false,
          message:
            'Admin wa shule haipo.'
        });
      }

      res.json({
        success: true,
        message:
          'Admin wa shule amefutwa.',
        admin
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   MAIN ADMIN PAYMENTS
========================================================= */

app.get(
  '/api/admin/payments',
  mainAdmin,
  async (req, res) => {

    try {

      const payments =
        await q(`
          SELECT
            p.*,
            s.name AS school_name
          FROM payments p
          LEFT JOIN schools s
            ON s.id=p.school_id
          ORDER BY p.id DESC
        `);

      res.json({
        success: true,
        payments
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   ADMIN - SCHOOL FORM PDF INFO
========================================================= */

app.get(
  '/api/admin/schools/:schoolId/form-pdf',
  mainAdmin,
  async (req, res) => {

    try {

      const pdf =
        (
          await q(`
            SELECT
              id,
              school_id,
              file_name,
              mime_type,
              file_size,
              active,
              uploaded_at,
              updated_at
            FROM school_form_pdfs
            WHERE
              school_id=$1
              AND active=true
            ORDER BY id DESC
            LIMIT 1
          `, [
            req.params.schoolId
          ])
        )[0];

      res.json({
        success: true,
        pdf: pdf || null
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHEMA - APPLICATION
========================================================= */

app.get(
  '/api/application-schema',
  async (req, res) => {

    try {

      const columns =
        await q(`
          SELECT
            column_name,
            data_type
          FROM information_schema.columns
          WHERE
            table_schema='public'
            AND table_name='applications'
          ORDER BY ordinal_position
        `);

      res.json({
        success: true,
        columns
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHEMA - PAYMENTS
========================================================= */

app.get(
  '/api/payment-schema',
  async (req, res) => {

    try {

      const columns =
        await q(`
          SELECT
            column_name,
            data_type
          FROM information_schema.columns
          WHERE
            table_schema='public'
            AND table_name='payments'
          ORDER BY ordinal_position
        `);

      res.json({
        success: true,
        columns
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   SCHEMA - SCHOOL FORM PDF
========================================================= */

app.get(
  '/api/form-pdf-schema',
  mainAdmin,
  async (req, res) => {

    try {

      const columns =
        await q(`
          SELECT
            column_name,
            data_type
          FROM information_schema.columns
          WHERE
            table_schema='public'
            AND table_name='school_form_pdfs'
          ORDER BY ordinal_position
        `);

      res.json({
        success: true,
        columns
      });

    } catch (e) {

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/* =========================================================
   404 API
========================================================= */

app.use('/api', (req, res) => {

  res.status(404).json({
    success: false,
    message:
      'API route haipo.'
  });
});

/* =========================================================
   GENERAL ERROR
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(
      'SERVER ERROR:',
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    res.status(500).json({
      success: false,
      message:
        'Server error.',
      error:
        err.message
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {

  try {

    await initializeDatabase();

    app.listen(
      PORT,
      '0.0.0.0',
      () => {

        console.log(
          `Shule Portal Tanzania running on port ${PORT}`
        );
      }
    );

  } catch (error) {

    console.error(
      'DATABASE/SERVER STARTUP ERROR:',
      error
    );

    process.exit(1);
  }
}

startServer();