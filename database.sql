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
);-- ==========================================
-- APPLICATIONS
-- ==========================================

CREATE TABLE IF NOT EXISTS applications (
    id SERIAL PRIMARY KEY,

    school_id INTEGER NOT NULL
        REFERENCES schools(id),

    student_name VARCHAR(255) NOT NULL,
    gender VARCHAR(50),
    date_of_birth DATE,
    class_level VARCHAR(100),

    parent_name VARCHAR(255),
    phone VARCHAR(50),
    email VARCHAR(255),
    address TEXT,

    application_number VARCHAR(100) UNIQUE,

    status VARCHAR(30) DEFAULT 'pending',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- ==========================================
-- PAYMENTS
-- ==========================================

CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,

    application_id INTEGER NOT NULL
        REFERENCES applications(id),

    amount NUMERIC(12,2) NOT NULL,

    payment_reference VARCHAR(150) UNIQUE,

    provider_reference VARCHAR(150),

    status VARCHAR(30) DEFAULT 'pending',

    paid_at TIMESTAMP NULL,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);