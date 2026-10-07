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

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

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
  return crypto.randomBytes(bytes).toString('hex').toUpperCase();
}

function generateApplicationNumber() {
  return `SPT-${new Date().getFullYear()}-${Date.now()}-${randomHex(2)}`;
}

function generatePaymentReference() {
  return `PAY-${new Date().getFullYear()}-${Date.now()}-${randomHex(2)}`;
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function toBoolean(value, defaultValue = false) {
  if (value === undefined || value === null || value === '') {
    return defaultValue;
  }

  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'string') {
    const v = value.trim().toLowerCase();

    if (['true', '1', 'yes', 'on'].includes(v)) {
      return true;
    }

    if (['false', '0', 'no', 'off'].includes(v)) {
      return false;
    }
  }

  return Boolean(value);
}

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
          label: String(item.label ?? item.value ?? '').trim()
        };
      }

      return {
        value: String(item ?? '').trim(),
        label: String(item ?? '').trim()
      };
    })
    .filter(item => item.value && item.label)
    .slice(0, 100);
}

async function q(text, params = []) {
  const result = await pool.query(text, params);
  return result.rows;
}

function getBearerToken(req) {
  return String(req.headers.authorization || '')
    .replace(/^Bearer\s+/i, '')
    .trim();
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function schoolAdmin(req, res, next) {
  const token = getBearerToken(req);
  const session = sessions.get(token);

  if (!session || session.role !== 'school_admin') {
    return res.status(401).json({
      success: false,
      message: 'Login ya Admin wa Shule inahitajika'
    });
  }

  req.auth = session;
  next();
}

function mainAdmin(req, res, next) {
  const token = getBearerToken(req);
  const session = sessions.get(token);

  if (!session || session.role !== 'main_admin') {
    return res.status(401).json({
      success: false,
      message: 'Login ya Admin Mkuu inahitajika'
    });
  }

  req.auth = session;
  next();
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {

  /*
    MUHIMU:
    CREATE TABLE IF NOT EXISTS HAIIFUTI table iliyopo.

    ALTER TABLE hapa chini inaongeza columns zinazokosekana
    bila kufuta data.
  */

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
     SAFE SCHOOL MIGRATIONS
  ======================================================= */

  const schoolMigrations = [

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS custom_data
     JSONB NOT NULL DEFAULT '{}'::jsonb`,

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS payment_provider TEXT`,

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS payment_account_id TEXT`,

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS payment_account_status
     TEXT DEFAULT 'pending'`,

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS commission_type
     TEXT DEFAULT 'percent'`,

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS commission_value
     NUMERIC(12,2) DEFAULT 0`,

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS application_start DATE`,

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS application_end DATE`,

    `ALTER TABLE schools
     ADD COLUMN IF NOT EXISTS updated_at
     TIMESTAMPTZ DEFAULT NOW()`
  ];

  for (const sql of schoolMigrations) {
    await q(sql);
  }

  /* =======================================================
     APPLICATION MIGRATIONS

     HAPA NDIPO TUNAREKEBISHA SCHEMA YAKO HALISI.
     HATUFUTI APPLICATIONS ZILIZOPO.
  ======================================================= */

  const applicationMigrations = [

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS form_id INT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS applicant_name TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS applicant_gender TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS applicant_date_of_birth DATE`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS parent_name TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS parent_phone TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS parent_email TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS address TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS status
     TEXT DEFAULT 'Inasubiri'`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS payment_status
     TEXT DEFAULT 'pending'`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS created_at
     TIMESTAMPTZ DEFAULT NOW()`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS updated_at
     TIMESTAMPTZ DEFAULT NOW()`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS student_name TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS gender TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS date_of_birth DATE`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS class_level TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS phone TEXT`,

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS email TEXT`,

    /*
      HII NDIYO COLUMN MPYA MUHIMU
      KWA DYNAMIC FORM BUILDER
    */
    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS custom_data
     JSONB NOT NULL DEFAULT '{}'::jsonb`
  ];

  for (const sql of applicationMigrations) {
    await q(sql);
  }

  /* =======================================================
     PAYMENT MIGRATIONS
  ======================================================= */

  const paymentMigrations = [

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS application_number TEXT`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS amount
     NUMERIC(12,2) DEFAULT 0`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS status
     TEXT DEFAULT 'pending'`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS payment_method TEXT`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS transaction_reference TEXT`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS provider TEXT`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS school_id INT`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS provider_account_id TEXT`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS commission_amount
     NUMERIC(12,2) DEFAULT 0`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS school_amount
     NUMERIC(12,2) DEFAULT 0`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS webhook_event_id TEXT`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS created_at
     TIMESTAMPTZ DEFAULT NOW()`,

    `ALTER TABLE payments
     ADD COLUMN IF NOT EXISTS updated_at
     TIMESTAMPTZ DEFAULT NOW()`
  ];

  for (const sql of paymentMigrations) {
    await q(sql);
  }

  /* =======================================================
     CUSTOM FIELD BUILDER TABLE
  ======================================================= */

  await q(`
    CREATE TABLE IF NOT EXISTS school_custom_fields (
      id BIGSERIAL PRIMARY KEY,

      school_id INTEGER NOT NULL
        REFERENCES schools(id)
        ON DELETE CASCADE,

      field_key VARCHAR(100) NOT NULL,
      field_label VARCHAR(255) NOT NULL,

      field_type VARCHAR(50)
        NOT NULL DEFAULT 'text',

      placeholder TEXT,

      options JSONB
        NOT NULL DEFAULT '[]'::jsonb,

      is_required BOOLEAN
        NOT NULL DEFAULT FALSE,

      is_visible BOOLEAN
        NOT NULL DEFAULT TRUE,

      show_on_public BOOLEAN
        NOT NULL DEFAULT TRUE,

      sort_order INTEGER
        NOT NULL DEFAULT 0,

      created_at TIMESTAMP
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMP
        NOT NULL DEFAULT NOW(),

      CONSTRAINT unique_school_custom_field_key
        UNIQUE (school_id, field_key)
    )
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_school_custom_fields_school
    ON school_custom_fields(school_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_school_custom_fields_order
    ON school_custom_fields(school_id, sort_order)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_school_custom_fields_options
    ON school_custom_fields
    USING GIN(options)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_applications_school
    ON applications(school_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_applications_number
    ON applications(application_number)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_payments_school
    ON payments(school_id)
  `);

  await q(`
    CREATE INDEX IF NOT EXISTS
    idx_payments_application
    ON payments(application_id)
  `);

  /* =======================================================
     BACKFILL LEGACY / NEW COLUMNS
     
     Hii inasaidia records zako za zamani.
  ======================================================= */

  await q(`
    UPDATE applications
    SET
      student_name =
        COALESCE(student_name, applicant_name),

      applicant_name =
        COALESCE(applicant_name, student_name),

      gender =
        COALESCE(gender, applicant_gender),

      applicant_gender =
        COALESCE(applicant_gender, gender),

      date_of_birth =
        COALESCE(date_of_birth, applicant_date_of_birth),

      applicant_date_of_birth =
        COALESCE(applicant_date_of_birth, date_of_birth),

      status =
        COALESCE(status, 'Inasubiri'),

      payment_status =
        COALESCE(payment_status, 'pending'),

      updated_at =
        COALESCE(updated_at, NOW())

    WHERE
      student_name IS NULL
      OR applicant_name IS NULL
      OR gender IS NULL
      OR applicant_gender IS NULL
      OR date_of_birth IS NULL
      OR applicant_date_of_birth IS NULL
      OR status IS NULL
      OR payment_status IS NULL
  `);

  /* =======================================================
     DEMO DATA ONLY IF DATABASE IS EMPTY
  ======================================================= */

  const schoolCount = Number(
    (await q(`
      SELECT COUNT(*)::int AS count
      FROM schools
    `))[0].count
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

  const adminCount = Number(
    (await q(`
      SELECT COUNT(*)::int AS count
      FROM school_admins
    `))[0].count
  );

  if (adminCount === 0) {

    const school =
      (await q(`
        SELECT id
        FROM schools
        ORDER BY id
        LIMIT 1
      `))[0];

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
   CUSTOM FIELD HELPERS
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

    if (!safeKey) {
      continue;
    }

    if (typeof value === 'string') {
      result[safeKey] = value.trim();

    } else if (Array.isArray(value)) {
      result[safeKey] =
        value.map(v => String(v));

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

function validateCustomData(fields, rawData) {

  const data = cleanCustomData(rawData);
  const errors = [];

  for (const field of fields) {

    const key = field.field_key;
    const value = data[key];

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

    if (empty) {
      continue;
    }

    if (
      ['dropdown', 'radio']
        .includes(field.field_type)
    ) {

      const allowed =
        new Set(
          (
            Array.isArray(field.options)
              ? field.options
              : []
          ).map(
            o => String(
              o.value ?? o
            )
          )
        );

      if (
        !allowed.has(String(value))
      ) {

        errors.push(
          `Chaguo si sahihi kwa: ${field.field_label}`
        );
      }
    }

    if (
      field.field_type === 'checkbox' &&
      !Array.isArray(value) &&
      typeof value !== 'boolean'
    ) {

      errors.push(
        `Taarifa si sahihi kwa: ${field.field_label}`
      );
    }
  }

  return {
    data,
    errors
  };
}

/* =========================================================
   BASIC API
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

    const rows = await q(`
      SELECT *
      FROM schools
      WHERE status='active'
      ORDER BY id DESC
    `);

    res.json({
      success: true,
      schools: rows
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

    const rows = await q(`
      SELECT *
      FROM schools
      WHERE id=$1
    `, [req.params.id]);

    if (!rows[0]) {

      return res.status(404).json({
        success: false,
        message: 'Shule haipo'
      });
    }

    res.json({
      success: true,
      school: rows[0]
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

      const school =
        (await q(`
          SELECT id,status
          FROM schools
          WHERE id=$1
        `, [req.params.id]))[0];

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
      String(b.student_name || '').trim();

    const gender =
      String(b.gender || '').trim() || null;

    const dateOfBirth =
      b.date_of_birth || null;

    const classApplied =
      String(
        b.class_applied || ''
      ).trim() || null;

    const parentName =
      String(
        b.parent_name || ''
      ).trim();

    const parentPhone =
      String(
        b.parent_phone || ''
      ).trim();

    const parentEmail =
      String(
        b.parent_email || ''
      ).trim() || null;

    const address =
      String(
        b.address || ''
      ).trim() || null;

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

    const fieldResult =
      await client.query(`
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
          sort_order
        FROM school_custom_fields
        WHERE school_id=$1
        AND is_visible=true
        AND show_on_public=true
        ORDER BY sort_order ASC,id ASC
      `, [schoolId]);

    const validation =
      validateCustomData(
        fieldResult.rows,
        b.custom_data
      );

    if (validation.errors.length) {

      await client.query('ROLLBACK');

      return res.status(400).json({
        success: false,
        message:
          validation.errors.join(' | '),
        errors:
          validation.errors
      });
    }

    const applicationNumber =
      generateApplicationNumber();

    const paymentReference =
      generatePaymentReference();

    const amount =
      Number(school.form_price || 0);

    /*
      HAPA TUNAHIFADHI:
      - applicant_name
      - applicant_gender
      - applicant_date_of_birth
      - class_level
      - student_name
      - gender
      - date_of_birth
      - parent_name
      - parent_phone
      - parent_email
      - phone
      - email
      - custom_data

      Kwa hiyo old pages na new pages
      zote zinaweza kusoma data.
    */

    const insertSql = `

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

        custom_data,

        created_at,
        updated_at
      )

      VALUES
      (
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

        'Inasubiri',
        'pending',

        $4,
        $5,
        $6,
        $11,
        $8,
        $9,

        $12,

        NOW(),
        NOW()
      )

      RETURNING *
    `;

    const applicationResult =
      await client.query(
        insertSql,
        [
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

          JSON.stringify(
            validation.data
          )
        ]
      );

    const application =
      applicationResult.rows[0];

    /* =====================================================
       COMMISSION
    ===================================================== */

    const commissionType =
      String(
        school.commission_type ||
        'percent'
      ).toLowerCase();

    const commissionValue =
      Number(
        school.commission_value || 0
      );

    let commissionAmount = 0;

    if (
      commissionType === 'fixed'
    ) {

      commissionAmount =
        commissionValue;

    } else {

      commissionAmount =
        amount *
        commissionValue /
        100;
    }

    commissionAmount =
      Math.max(
        0,
        Math.min(
          amount,
          commissionAmount
        )
      );

    const schoolAmount =
      Math.max(
        0,
        amount - commissionAmount
      );

    /* =====================================================
       CREATE PAYMENT
    ===================================================== */

    await client.query(`
      INSERT INTO payments
      (
        application_id,
        application_number,
        payment_reference,
        amount,

        status,
        payment_method,
        provider,

        school_id,
        provider_account_id,

        commission_amount,
        school_amount,

        created_at,
        updated_at
      )

      VALUES
      (
        $1,
        $2,
        $3,
        $4,

        'pending',
        'pending',
        $5,

        $6,
        $7,

        $8,
        $9,

        NOW(),
        NOW()
      )
    `, [
      application.id,
      applicationNumber,
      paymentReference,
      amount,

      school.payment_provider ||
        'TEST',

      schoolId,

      school.payment_account_id ||
        null,

      commissionAmount,
      schoolAmount
    ]);

    await client.query('COMMIT');

    res.status(201).json({

      success: true,

      message:
        'Maombi yamepokelewa. Sasa unaweza kuendelea na malipo.',

      application: {
        ...application,
        custom_data:
          validation.data
      },

      payment: {
        payment_reference:
          paymentReference,

        amount,

        status:
          'pending',

        provider:
          school.payment_provider ||
          'TEST'
      }
    });

  } catch (e) {

    try {
      await client.query('ROLLBACK');
    } catch (_) {}

    console.error(
      'POST /api/applications:',
      e
    );

    res.status(500).json({
      success: false,
      message: e.message
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

      const rows = await q(`
        SELECT

          a.*,

          s.name AS school_name,
          s.region,
          s.district,
          s.form_price,

          p.payment_reference,

          p.amount AS payment_amount,

          p.status AS payment_record_status,

          p.payment_method,

          p.transaction_reference,

          p.provider

        FROM applications a

        JOIN schools s
          ON s.id=a.school_id

        LEFT JOIN LATERAL
        (
          SELECT *
          FROM payments

          WHERE application_id=a.id

          ORDER BY id DESC

          LIMIT 1
        ) p ON TRUE

        WHERE
          a.application_number=$1

        LIMIT 1
      `, [
        req.params.applicationNumber
      ]);

      if (!rows[0]) {

        return res.status(404).json({
          success: false,
          message:
            'Application haijapatikana'
        });
      }

      res.json({
        success: true,
        application: rows[0]
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
  '/api/payments/:ref',
  async (req, res) => {

    try {

      const rows = await q(`
        SELECT
          p.*,
          s.name AS school_name

        FROM payments p

        LEFT JOIN schools s
          ON s.id=p.school_id

        WHERE
          p.payment_reference=$1
      `, [
        req.params.ref
      ]);

      if (!rows[0]) {

        return res.status(404).json({
          success: false,
          message: 'Payment haipo'
        });
      }

      res.json({
        success: true,
        payment: rows[0]
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
  '/api/payments/:ref/confirm',
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      await client.query(
        'BEGIN'
      );

      const paymentResult =
        await client.query(`
          SELECT *
          FROM payments
          WHERE payment_reference=$1
          FOR UPDATE
        `, [
          req.params.ref
        ]);

      const payment =
        paymentResult.rows[0];

      if (!payment) {

        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          success: false,
          message:
            'Payment haipo'
        });
      }

      const transactionReference =
        String(
          req.body.transaction_reference ||
          `TEST-${Date.now()}`
        ).trim();

      await client.query(`
        UPDATE payments

        SET
          status='confirmed',
          transaction_reference=$1,
          updated_at=NOW()

        WHERE id=$2
      `, [
        transactionReference,
        payment.id
      ]);

      if (payment.application_id) {

        await client.query(`
          UPDATE applications

          SET
            payment_status='confirmed',
            updated_at=NOW()

          WHERE id=$1
        `, [
          payment.application_id
        ]);
      }

      await client.query(
        'COMMIT'
      );

      res.json({

        success: true,

        mode: 'TEST',

        message:
          'Malipo ya majaribio yamethibitishwa',

        payment_reference:
          payment.payment_reference,

        transaction_reference:
          transactionReference,

        application_id:
          payment.application_id
      });

    } catch (e) {

      try {
        await client.query(
          'ROLLBACK'
        );
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
   LIVE PAYMENT WEBHOOK PLACEHOLDER
========================================================= */

app.post(
  '/api/payments/webhook',
  async (req, res) => {

    res.status(501).json({

      success: false,

      message:
        'LIVE payment webhook bado haijawezeshwa. Hii endpoint ni placeholder ya integration.'
    });
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
        ).trim().toLowerCase();

      const password =
        String(
          req.body.password || ''
        );

      const admin =
        (
          await q(`
            SELECT *
            FROM school_admins

            WHERE
              LOWER(email)=LOWER($1)
              AND active=true
          `, [
            email
          ])
        )[0];

      if (
        !admin ||
        admin.password_hash !==
          hashPassword(password)
      ) {

        return res.status(401).json({
          success: false,
          message:
            'Email au password si sahihi'
        });
      }

      const token =
        generateToken();

      sessions.set(
        token,
        {
          role: 'school_admin',
          adminId: admin.id,
          schoolId: admin.school_id,
          email: admin.email,
          fullName: admin.full_name,
          createdAt: Date.now()
        }
      );

      res.json({

        success: true,

        token,

        admin: {
          id: admin.id,
          full_name:
            admin.full_name,
          email:
            admin.email,
          school_id:
            admin.school_id
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
  (req, res) => {

    res.json({
      success: true,
      admin: req.auth
    });
  }
);

app.post(
  '/api/school-admin/logout',
  schoolAdmin,
  (req, res) => {

    sessions.delete(
      getBearerToken(req)
    );

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
            'Shule haipo'
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
              name=$1,
              region=$2,
              district=$3,
              school_type=$4,
              type=$5,
              form_price=$6,
              phone=$7,
              email=$8,
              address=$9,
              application_start=$10,
              application_end=$11,

              payment_provider=
                COALESCE(
                  $12,
                  payment_provider
                ),

              payment_account_id=
                COALESCE(
                  $13,
                  payment_account_id
                ),

              updated_at=NOW()

            WHERE id=$14

            RETURNING *
          `, [

            String(
              b.name || ''
            ).trim(),

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

            b.email || null,

            b.address || null,

            b.application_start ||
              null,

            b.application_end ||
              null,

            b.payment_provider ||
              null,

            b.payment_account_id ||
              null,

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
   SCHOOL ADMIN PUBLISH / UNPUBLISH
========================================================= */

app.put(
  '/api/school-admin/publish',
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

app.put(
  '/api/school-admin/unpublish',
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

            p.amount AS payment_amount,

            p.status AS payment_record_status,

            p.transaction_reference,

            p.payment_method,

            p.provider

          FROM applications a

          LEFT JOIN LATERAL
          (
            SELECT *
            FROM payments

            WHERE
              application_id=a.id

            ORDER BY id DESC

            LIMIT 1

          ) p ON TRUE

          WHERE
            a.school_id=$1

          ORDER BY
            a.id DESC
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

      const allowed = [
        'Inasubiri',
        'Imepokelewa',
        'Inachakatwa',
        'Imekubaliwa',
        'Imekataliwa',
        'Completed',
        'Pending',
        'Approved',
        'Rejected'
      ];

      const status =
        String(
          req.body.status || ''
        ).trim();

      if (!allowed.includes(status)) {

        return res.status(400).json({
          success: false,
          message:
            'Status si sahihi'
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
            'Application haipo'
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

          WHERE
            school_id=$1

          ORDER BY
            id DESC
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
   SCHOOL ADMIN CUSTOM FIELDS
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
   MAIN ADMIN LOGIN
========================================================= */

app.post(
  '/api/main-admin/login',
  async (req, res) => {

    const email =
      String(
        req.body.email || ''
      ).trim().toLowerCase();

    const password =
      String(
        req.body.password || ''
      );

    const adminEmail =
      String(
        process.env.MAIN_ADMIN_EMAIL ||
        'admin@shuleportal.co.tz'
      ).toLowerCase();

    const adminPassword =
      String(
        process.env.MAIN_ADMIN_PASSWORD ||
        'Admin@123'
      );

    if (
      email === adminEmail &&
      password === adminPassword
    ) {

      const token =
        generateToken();

      sessions.set(
        token,
        {
          role: 'main_admin',
          email,
          createdAt: Date.now()
        }
      );

      return res.json({

        success: true,

        token,

        admin: {
          email
        }
      });
    }

    res.status(401).json({
      success: false,
      message:
        'Login ya Admin Mkuu si sahihi'
    });
  }
);

app.get(
  '/api/admin/me',
  mainAdmin,
  (req, res) => {

    res.json({
      success: true,
      admin: req.auth
    });
  }
);

app.post(
  '/api/main-admin/logout',
  mainAdmin,
  (req, res) => {

    sessions.delete(
      getBearerToken(req)
    );

    res.json({
      success: true
    });
  }
);

/* =========================================================
   ADMIN SCHOOLS
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

            COALESCE(
              ac.applicant_count,
              0
            )::int AS applicant_count

          FROM schools s

          LEFT JOIN
          (
            SELECT
              school_id,
              COUNT(*) AS applicant_count

            FROM applications

            GROUP BY
              school_id

          ) ac
          ON ac.school_id=s.id

          ORDER BY
            s.id DESC
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

/* =========================================================
   ADMIN CREATE SCHOOL
========================================================= */

app.post(
  '/api/admin/schools',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      if (
        !String(
          b.name || ''
        ).trim()
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Jina la shule linahitajika'
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
              application_start,
              application_end,
              status,
              payment_provider,
              payment_account_id,
              payment_account_status,
              commission_type,
              commission_value,
              updated_at
            )

            VALUES
            (
              $1,$2,$3,$4,$5,$6,$7,$8,$9,
              $10,$11,$12,$13,$14,'pending',
              $15,$16,NOW()
            )

            RETURNING *
          `, [

            String(
              b.name
            ).trim(),

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

            b.application_start ||
              null,

            b.application_end ||
              null,

            b.status ||
              'inactive',

            b.payment_provider ||
              null,

            b.payment_account_id ||
              null,

            b.commission_type ||
              'percent',

            Number(
              b.commission_value || 0
            )
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

/* =========================================================
   ADMIN UPDATE SCHOOL
========================================================= */

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

              name=
                COALESCE(
                  $1,
                  name
                ),

              region=$2,

              district=$3,

              school_type=$4,

              type=$5,

              form_price=$6,

              phone=$7,

              address=$8,

              email=$9,

              application_start=$10,

              application_end=$11,

              status=
                COALESCE(
                  $12,
                  status
                ),

              payment_provider=$13,

              payment_account_id=$14,

              payment_account_status=
                COALESCE(
                  $15,
                  payment_account_status
                ),

              commission_type=
                COALESCE(
                  $16,
                  commission_type
                ),

              commission_value=
                COALESCE(
                  $17,
                  commission_value
                ),

              updated_at=NOW()

            WHERE id=$18

            RETURNING *
          `, [

            b.name
              ? String(
                  b.name
                ).trim()
              : null,

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

            b.application_start ||
              null,

            b.application_end ||
              null,

            b.status || null,

            b.payment_provider ||
              null,

            b.payment_account_id ||
              null,

            b.payment_account_status ||
              null,

            b.commission_type ||
              null,

            b.commission_value !==
            undefined
              ? Number(
                  b.commission_value
                )
              : null,

            req.params.id
          ])
        )[0];

      if (!school) {

        return res.status(404).json({
          success: false,
          message:
            'Shule haipo'
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
   ADMIN DELETE SCHOOL
   NON-DESTRUCTIVE
========================================================= */

app.delete(
  '/api/admin/schools/:id',
  mainAdmin,
  async (req, res) => {

    try {

      /*
        HATUFUTI SHULE KIMWILI.

        Tunaweka inactive ili applications
        zake zibaki salama.
      */

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
            'Shule haipo'
        });
      }

      res.json({

        success: true,

        message:
          'Shule imeondolewa kwenye public portal bila kufuta records.',

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
   ADMIN DASHBOARD STATS
========================================================= */

app.get(
  '/api/admin/dashboard-stats',
  mainAdmin,
  async (req, res) => {

    try {

      const schoolStats =
        (
          await q(`
            SELECT

              COUNT(*)::int
                AS total_schools,

              COUNT(*)
                FILTER(
                  WHERE status='active'
                )::int
                AS active_schools

            FROM schools
          `)
        )[0];

      const applicationStats =
        (
          await q(`
            SELECT
              COUNT(*)::int
              AS total_applications

            FROM applications
          `)
        )[0];

      const paymentStats =
        (
          await q(`
            SELECT

              COUNT(*)
              FILTER(
                WHERE status='confirmed'
              )::int
              AS confirmed_payments,

              COALESCE(
                SUM(amount)
                FILTER(
                  WHERE status='confirmed'
                ),
                0
              )
              AS confirmed_amount

            FROM payments
          `)
        )[0];

      res.json({

        success: true,

        stats: {

          total_schools:
            schoolStats.total_schools,

          active_schools:
            schoolStats.active_schools,

          total_applications:
            applicationStats.total_applications,

          confirmed_payments:
            paymentStats.confirmed_payments,

          confirmed_amount:
            paymentStats.confirmed_amount
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
   ADMIN SCHOOL ADMINS
========================================================= */

app.get(
  '/api/admin/school-admins',
  mainAdmin,
  async (req, res) => {

    try {

      const admins =
        await q(`
          SELECT

            a.id,
            a.full_name,
            a.email,
            a.active,
            a.school_id,

            s.name AS school_name,

            a.created_at

          FROM school_admins a

          LEFT JOIN schools s
            ON s.id=a.school_id

          ORDER BY
            a.id DESC
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
   CREATE SCHOOL ADMIN
========================================================= */

app.post(
  '/api/admin/school-admins',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const schoolId =
        Number(
          b.school_id
        );

      const fullName =
        String(
          b.full_name || ''
        ).trim();

      const email =
        String(
          b.email || ''
        ).trim().toLowerCase();

      const password =
        String(
          b.password || ''
        );

      if (
        !schoolId ||
        !fullName ||
        !email ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Jaza school_id, jina, email na password.'
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
              active,
              updated_at
            )

            VALUES
            (
              $1,$2,$3,$4,true,NOW()
            )

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
            )
          ])
        )[0];

      res.status(201).json({
        success: true,
        admin
      });

    } catch (e) {

      if (
        e.code === '23505'
      ) {

        return res.status(409).json({
          success: false,
          message:
            'Email hii tayari inatumika.'
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
   UPDATE SCHOOL ADMIN
========================================================= */

app.put(
  '/api/admin/school-admins/:id',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const passwordHash =
        b.password
          ? hashPassword(
              b.password
            )
          : null;

      const admin =
        (
          await q(`
            UPDATE school_admins

            SET

              school_id=
                COALESCE(
                  $1,
                  school_id
                ),

              full_name=
                COALESCE(
                  $2,
                  full_name
                ),

              email=
                COALESCE(
                  $3,
                  email
                ),

              password_hash=
                COALESCE(
                  $4,
                  password_hash
                ),

              active=
                COALESCE(
                  $5,
                  active
                ),

              updated_at=NOW()

            WHERE id=$6

            RETURNING
              id,
              school_id,
              full_name,
              email,
              active,
              created_at
          `, [

            b.school_id
              ? Number(
                  b.school_id
                )
              : null,

            b.full_name
              ? String(
                  b.full_name
                ).trim()
              : null,

            b.email
              ? String(
                  b.email
                ).trim().toLowerCase()
              : null,

            passwordHash,

            b.active === undefined
              ? null
              : toBoolean(
                  b.active
                ),

            req.params.id
          ])
        )[0];

      if (!admin) {

        return res.status(404).json({
          success: false,
          message:
            'Admin wa shule haipo'
        });
      }

      res.json({
        success: true,
        admin
      });

    } catch (e) {

      if (
        e.code === '23505'
      ) {

        return res.status(409).json({
          success: false,
          message:
            'Email hii tayari inatumika.'
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
   DISABLE SCHOOL ADMIN
========================================================= */

app.delete(
  '/api/admin/school-admins/:id',
  mainAdmin,
  async (req, res) => {

    try {

      const admin =
        (
          await q(`
            UPDATE school_admins

            SET
              active=false,
              updated_at=NOW()

            WHERE id=$1

            RETURNING
              id,
              school_id,
              full_name,
              email,
              active
          `, [
            req.params.id
          ])
        )[0];

      if (!admin) {

        return res.status(404).json({
          success: false,
          message:
            'Admin haipo'
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
   ADMIN PAYMENTS
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

          ORDER BY
            p.id DESC
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
   CUSTOM FIELD BUILDER
========================================================= */

/*
  GET FIELDS
*/

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

/*
  CREATE FIELD
*/

app.post(
  '/api/admin/schools/:schoolId/custom-fields',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const schoolId =
        Number(
          req.params.schoolId
        );

      const fieldLabel =
        String(
          b.field_label ||
          b.label ||
          ''
        ).trim();

      const fieldKey =
        normalizeFieldKey(
          b.field_key ||
          b.key ||
          fieldLabel
        );

      const fieldType =
        String(
          b.field_type ||
          b.type ||
          'text'
        )
          .trim()
          .toLowerCase();

      const options =
        normalizeOptions(
          b.options
        );

      if (
        !schoolId ||
        !fieldLabel ||
        !fieldKey
      ) {

        return res.status(400).json({
          success: false,
          message:
            'field_label na field_key vinahitajika.'
        });
      }

      if (
        !ALLOWED_CUSTOM_FIELD_TYPES
          .includes(fieldType)
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Aina ya field si sahihi.'
        });
      }

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
            'Shule haipo'
        });
      }

      const field =
        (
          await q(`
            INSERT INTO
            school_custom_fields

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
              sort_order,
              updated_at
            )

            VALUES
            (
              $1,$2,$3,$4,$5,$6,
              $7,$8,$9,$10,NOW()
            )

            RETURNING *
          `, [

            schoolId,

            fieldKey,

            fieldLabel,

            fieldType,

            b.placeholder ||
              null,

            JSON.stringify(
              options
            ),

            toBoolean(
              b.is_required ??
              b.required,
              false
            ),

            toBoolean(
              b.is_visible ??
              b.visible,
              true
            ),

            toBoolean(
              b.show_on_public ??
              b.public,
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

      if (
        e.code === '23505'
      ) {

        return res.status(409).json({
          success: false,
          message:
            'Field key hii tayari ipo kwenye shule hii.'
        });
      }

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/*
  UPDATE FIELD
*/

app.put(
  '/api/admin/schools/:schoolId/custom-fields/:fieldId',
  mainAdmin,
  async (req, res) => {

    try {

      const b =
        req.body || {};

      const fieldId =
        Number(
          req.params.fieldId
        );

      const schoolId =
        Number(
          req.params.schoolId
        );

      const fieldLabel =
        String(
          b.field_label ||
          b.label ||
          ''
        ).trim();

      const fieldKey =
        normalizeFieldKey(
          b.field_key ||
          b.key ||
          fieldLabel
        );

      const fieldType =
        String(
          b.field_type ||
          b.type ||
          'text'
        )
          .trim()
          .toLowerCase();

      const options =
        normalizeOptions(
          b.options
        );

      if (
        !fieldLabel ||
        !fieldKey ||
        !ALLOWED_CUSTOM_FIELD_TYPES
          .includes(fieldType)
      ) {

        return res.status(400).json({
          success: false,
          message:
            'Taarifa za field si sahihi.'
        });
      }

      const field =
        (
          await q(`
            UPDATE school_custom_fields

            SET

              field_key=$1,
              field_label=$2,
              field_type=$3,
              placeholder=$4,
              options=$5,
              is_required=$6,
              is_visible=$7,
              show_on_public=$8,
              sort_order=$9,
              updated_at=NOW()

            WHERE
              id=$10
              AND school_id=$11

            RETURNING *
          `, [

            fieldKey,

            fieldLabel,

            fieldType,

            b.placeholder ||
              null,

            JSON.stringify(
              options
            ),

            toBoolean(
              b.is_required ??
              b.required,
              false
            ),

            toBoolean(
              b.is_visible ??
              b.visible,
              true
            ),

            toBoolean(
              b.show_on_public ??
              b.public,
              true
            ),

            Number(
              b.sort_order || 0
            ),

            fieldId,

            schoolId
          ])
        )[0];

      if (!field) {

        return res.status(404).json({
          success: false,
          message:
            'Field haipo'
        });
      }

      res.json({
        success: true,
        field
      });

    } catch (e) {

      if (
        e.code === '23505'
      ) {

        return res.status(409).json({
          success: false,
          message:
            'Field key hii tayari ipo.'
        });
      }

      res.status(500).json({
        success: false,
        message: e.message
      });
    }
  }
);

/*
  DELETE FIELD
*/

app.delete(
  '/api/admin/schools/:schoolId/custom-fields/:fieldId',
  mainAdmin,
  async (req, res) => {

    try {

      const field =
        (
          await q(`
            DELETE FROM
              school_custom_fields

            WHERE
              id=$1
              AND school_id=$2

            RETURNING *
          `, [
            req.params.fieldId,
            req.params.schoolId
          ])
        )[0];

      if (!field) {

        return res.status(404).json({
          success: false,
          message:
            'Field haipo'
        });
      }

      res.json({
        success: true,
        field
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
   SCHEMA CHECK
========================================================= */

app.get(
  '/api/application-schema',
  async (req, res) => {

    try {

      const columns =
        await q(`
          SELECT

            column_name,
            data_type,
            is_nullable,
            column_default

          FROM information_schema.columns

          WHERE
            table_schema='public'
            AND table_name='applications'

          ORDER BY
            ordinal_position
        `);

      res.json({
        success: true,
        table: 'applications',
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

app.get(
  '/api/payment-schema',
  async (req, res) => {

    try {

      const columns =
        await q(`
          SELECT

            column_name,
            data_type,
            is_nullable,
            column_default

          FROM information_schema.columns

          WHERE
            table_schema='public'
            AND table_name='payments'

          ORDER BY
            ordinal_position
        `);

      res.json({
        success: true,
        table: 'payments',
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
   404
========================================================= */

app.use((req, res) => {

  if (
    req.path.startsWith('/api/')
  ) {

    return res.status(404).json({
      success: false,
      message:
        'API endpoint haipo'
    });
  }

  res.status(404).send(
    'Page haipo'
  );
});

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (err, req, res, next) => {

    console.error(err);

    if (res.headersSent) {
      return next(err);
    }

    res.status(500).json({
      success: false,
      message:
        err.message ||
        'Server error'
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function start() {

  try {

    await initializeDatabase();

    app.listen(
      PORT,
      () => {

        console.log(
          `Shule Portal Tanzania running on port ${PORT}`
        );
      }
    );

  } catch (error) {

    console.error(
      'DATABASE/STARTUP ERROR:',
      error
    );

    process.exit(1);
  }
}

/* =========================================================
   SHUTDOWN
========================================================= */

process.on(
  'SIGTERM',
  async () => {

    await pool.end();

    process.exit(0);
  }
);

process.on(
  'SIGINT',
  async () => {

    await pool.end();

    process.exit(0);
  }
);

start();