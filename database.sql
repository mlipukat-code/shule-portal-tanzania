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