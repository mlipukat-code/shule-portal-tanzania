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

  if (
    !storedHash ||
    !storedHash.includes(":")
  ) {
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

  // ---------------------------------------------------
  // SCHOOLS
  // ---------------------------------------------------

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


  // ---------------------------------------------------
  // SCHOOL ADMINS
  // ---------------------------------------------------

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


  // ---------------------------------------------------
  // SCHOOL FORMS
  // ---------------------------------------------------

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


  // ---------------------------------------------------
  // APPLICATIONS
  // ---------------------------------------------------

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


  // ---------------------------------------------------
  // PAYMENTS
  // ---------------------------------------------------

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


  // ---------------------------------------------------
  // ADMIN USERS
  // ---------------------------------------------------

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


  // ---------------------------------------------------
  // ADMIN SESSIONS
  // ---------------------------------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_sessions (

      id SERIAL PRIMARY KEY,

      admin_id INTEGER NOT NULL,

      session_token TEXT NOT NULL UNIQUE,

      expires_at TIMESTAMP NOT NULL,

      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

      CONSTRAINT fk_admin_session_admin
        FOREIGN KEY (admin_id)