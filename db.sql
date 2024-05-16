CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    full_name VARCHAR(255),
    dob DATE,
    gender VARCHAR(50),
    address VARCHAR(255),
    phone VARCHAR(50),
    insurance_details VARCHAR(255),
    medical_history TEXT,
    dental_history TEXT,
    language_preference VARCHAR(50),
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE doctors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNIQUE,
    specialization VARCHAR(255),
    consultation_hours VARCHAR(255),
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TYPE status_types AS ENUM ('scheduled', 'completed', 'cancelled');

CREATE TABLE appointments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    doctor_id INT,
    scheduled_time DATETIME,
    status status_types,
    notes VARCHAR(255),
    FOREIGN KEY(patient_id) REFERENCES patients(id),
    FOREIGN KEY(doctor_id) REFERENCES users(id)
);

CREATE TABLE bills (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    amount_due FLOAT,
    due_date DATETIME,
    status VARCHAR(255) DEFAULT 'unpaid',
    FOREIGN KEY(patient_id) REFERENCES patients(id)
);

CREATE TABLE payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bill_id INT,
    amount FLOAT,
    payment_method VARCHAR(255),
    FOREIGN KEY(bill_id) REFERENCES bills(id)
);
