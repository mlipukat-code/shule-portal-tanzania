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

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

/* =========================================================
   STATIC WEBSITE FILES
========================================================= */

/*
  Kwanza tunaserve files zilizo ndani ya /public
*/
app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

/*
  MUHIMU:
  HTML files ambazo ziko ROOT ya project pia zitaonekana.

  Mfano:
    /application-form.html
    /schools-public.html
    /school-details.html
    /admin-schools.html

  Hii ndiyo sehemu inayorekebisha tatizo la
  "Page haipo" kwa application-form.html.
*/

app.get('/:file.html', (req, res, next) => {

  const fileName =
    String(req.params.file || '').trim();

  /*
    Ruhusu majina salama ya HTML tu.
  */
  if (!/^[a-zA-Z0-9_-]+$/.test(fileName)) {
    return next();
  }

  const rootFile = path.join(
    __dirname,
    `${fileName}.html`
  );

  res.sendFile(
    rootFile,
    err => {
      if (err) {
        return next();
      }
    }
  );
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
  return `SPT-${new Date().getFullYear()}-${Date.now()}-${randomHex(2)}`;
}

function generatePaymentReference() {
  return `PAY-${new Date().getFullYear()}-${Date.now()}-${randomHex(2)}`;
}

function generateToken() {
  return crypto
    .randomBytes(32)
    .toString('hex');
}

function toBoolean(
  value,
  defaultValue = false
) {

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

  if (typeof value === 'string') {

    const v =
      value.trim().toLowerCase();

    if (
      ['true', '1', 'yes', 'on']
        .includes(v)
    ) {
      return true;
    }

    if (
      ['false', '0', 'no', 'off']
        .includes(v)
    ) {
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

      if (
        item &&
        typeof item === 'object'
      ) {

        return {
          value:
            String(
              item.value ?? ''
            ).trim(),

          label:
            String(
              item.label ??
              item.value ??
              ''
            ).trim()
        };
      }

      return {
        value:
          String(item ?? '').trim(),

        label:
          String(item ?? '').trim()
      };
    })
    .filter(
      item =>
        item.value &&
        item.label
    )
    .slice(0, 100);
}

async function q(
  text,
  params = []
) {

  const result =
    await pool.query(
      text,
      params
    );

  return result.rows;
}

function getBearerToken(req) {

  return String(
    req.headers.authorization || ''
  )
    .replace(
      /^Bearer\s+/i,
      ''
    )
    .trim();
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function schoolAdmin(
  req,
  res,
  next
) {

  const token =
    getBearerToken(req);

  const session =
    sessions.get(token);

  if (
    !session ||
    session.role !== 'school_admin'
  ) {

    return res.status(401).json({
      success: false,
      message:
        'Login ya Admin wa Shule inahitajika'
    });
  }

  req.auth = session;

  next();
}

function mainAdmin(
  req,
  res,
  next
) {

  const token =
    getBearerToken(req);

  const session =
    sessions.get(token);

  if (
    !session ||
    session.role !== 'main_admin'
  ) {

    return res.status(401).json({
      success: false,
      message:
        'Login ya Admin Mkuu inahitajika'
    });
  }

  req.auth = session;

  next();
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {

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
     SCHOOL MIGRATIONS
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

  for (
    const sql of schoolMigrations
  ) {
    await q(sql);
  }

  /* =======================================================
     APPLICATION MIGRATIONS
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

    `ALTER TABLE applications
     ADD COLUMN IF NOT EXISTS custom_data
     JSONB NOT NULL DEFAULT '{}'::jsonb`
  ];

  for (
    const sql of applicationMigrations
  ) {
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

  for (
    const sql of paymentMigrations
  ) {
    await q(sql);
  }

  /* =======================================================
     CUSTOM FIELD BUILDER
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
    ON school_custom_fields(
      school_id,
      sort_order
    )
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
     BACKFILL
  ======================================================= */

  await q(`
    UPDATE applications
    SET
      student_name =
        COALESCE(
          student_name,
          applicant_name
        ),

      applicant_name =
        COALESCE(
          applicant_name,
          student_name
        ),

      gender =
        COALESCE(
          gender,
          applicant_gender
        ),

      applicant_gender =
        COALESCE(
          applicant_gender,
          gender
        ),

      date_of_birth =
        COALESCE(
          date_of_birth,
          applicant_date_of_birth
        ),

      applicant_date_of_birth =
        COALESCE(
          applicant_date_of_birth,
          date_of_birth
        ),

      status =
        COALESCE(
          status,
          'Inasubiri'
        ),

      payment_status =
        COALESCE(
          payment_status,
          'pending'
        ),

      updated_at =
        COALESCE(
          updated_at,
          NOW()
        )

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
     DEMO SCHOOLS ONLY IF EMPTY
  ======================================================= */

  const schoolCount =
    Number(
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

  const adminCount =
    Number(
      (
        await q(`
          SELECT COUNT(*)::int AS count
          FROM school_admins
        `)
      )[0].count
    );

  if (adminCount === 0) {

    const school =
      (
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
   CUSTOM FIELD HELPERS
========================================================= */

async function getSchoolCustomFields(
  schoolId,
  publicOnly = false
) {

  const where =
    publicOnly
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

    ORDER BY
      sort_order ASC,
      id ASC
  `, [
    schoolId
  ]);
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

  for (
    const [key, value]
    of Object.entries(raw)
  ) {

    const safeKey =
      normalizeFieldKey(key);

    if (!safeKey) {
      continue;
    }

    if (
      typeof value === 'string'
    ) {

      result[safeKey] =
        value.trim();

    } else if (
      Array.isArray(value)
    ) {

      result[safeKey] =
        value.map(v =>
          String(v)
        );

    } else if (
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      value === null
    ) {

      result[safeKey] =
        value;
    }
  }

  return result;
}

function validateCustomData(
  fields,
  rawData
) {

  const data =
    cleanCustomData(rawData);

  const errors = [];

  for (
    const field of fields
  ) {

    const key =
      field.field_key;

    const value =
      data[key];

    const empty =
      value === undefined ||
      value === null ||
      value === '' ||
      (
        Array.isArray(value) &&
        value.length === 0
      );

    if (
      field.is_required &&
      empty
    ) {

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
        .includes(
          field.field_type
        )
    ) {

      const allowed =
        new Set(
          (
            Array.isArray(
              field.options
            )
              ? field.options
              : []
          ).map(
            o =>
              String(
                o.value ?? o
              )
          )
        );

      if (
        !allowed.has(
          String(value)
        )
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

app.get(
  '/api/status',
  (req, res) => {

    res.json({
      success: true,
      app: 'Shule Portal Tanzania',
      status: 'online',
      time:
        new Date().toISOString()
    });
  }
);

app.get(
  '/api/database-check',
  async (req, res) => {

    try {

      await q(
        'SELECT 1'
      );

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
  }
);

/* =========================================================
   PUBLIC SCHOOLS
========================================================= */

app.get(
  '/api/schools',
  async (req, res) => {

    try {

      const rows =
        await q(`
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
  }
);

app.get(
  '/api/schools/:id',
  async (req, res) => {

    try {

      const rows =
        await q(`
          SELECT *
          FROM schools
          WHERE id=$1
        `, [
          req.params.id
        ]);

      if (!rows[0]) {

        return res.status(404).json({
          success: false,
          message:
            'Shule haipo'
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
  }
);

/* =========================================================
   PUBLIC CUSTOM FIELDS
========================================================= */

app.get(
  '/api/schools/:id/custom-fields',
  async (req, res) => {

    try {

      const school =
        (
          await q(`
            SELECT id,status
            FROM schools
            WHERE id=$1
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

app.post(
  '/api/applications',
  async (req, res) => {

    const client =
      await pool.connect();

    try {

      const b =
        req.body || {};

      const schoolId =
        Number(
          b.school_id
        );

      const studentName =
        String(
          b.student_name || ''
        ).trim();

      const gender =
        String(
          b.gender || ''
        ).trim() || null;

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

      await client.query(
        'BEGIN'
      );

      const schoolResult =
        await client.query(`
          SELECT *
          FROM schools
          WHERE id=$1
          AND status='active'
          FOR SHARE
        `, [
          schoolId
        ]);

      const school =
        schoolResult.rows[0];

      if (!school) {

        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          success: false,
          message:
            'Shule haipatikani au haijawa live.'
        });
      }

      const fieldResult =
        await client