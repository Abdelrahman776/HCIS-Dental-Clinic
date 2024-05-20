-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    role VARCHAR(50),
    email VARCHAR(255) UNIQUE
);

-- Patients Table
CREATE TABLE IF NOT EXISTS patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    full_name VARCHAR(255),
    dob DATE,
    gender VARCHAR(50),
    address VARCHAR(255),
    phone VARCHAR(50),
    insurance_details VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Doctors Table
CREATE TABLE IF NOT EXISTS doctors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNIQUE,
    full_name VARCHAR(255),
    dob DATE,
    gender VARCHAR(50),
    address VARCHAR(255),
    phone VARCHAR(50),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Appointments Table
CREATE TABLE IF NOT EXISTS appointments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    doctor_id INT,
    scheduled_time DATETIME,
    status ENUM('scheduled', 'completed', 'cancelled'),
    notes VARCHAR(255), -- Changed from TEXT to VARCHAR(255)
    FOREIGN KEY (patient_id) REFERENCES patients(id),
    FOREIGN KEY (doctor_id) REFERENCES doctors(id)
);

-- Bills Table
CREATE TABLE IF NOT EXISTS bills (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    amount_due FLOAT,
    due_date DATETIME,
    status VARCHAR(255) DEFAULT 'unpaid',
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);

-- Payments Table
CREATE TABLE IF NOT EXISTS payments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bill_id INT,
    amount FLOAT,
    payment_method VARCHAR(255),
    FOREIGN KEY (bill_id) REFERENCES bills(id)
);

-- Medical History Table
CREATE TABLE IF NOT EXISTS medical_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT,
    allergies TEXT,
    medications TEXT,
    diagnosis TEXT,
    lab_results TEXT,
    imaging_results TEXT,
    consultation_notes TEXT,
    FOREIGN KEY (patient_id) REFERENCES patients(id)
);
-- Alter Doctors Table
ALTER TABLE doctors
    ADD COLUMN full_name VARCHAR(255),
    ADD COLUMN dob DATE,
    ADD COLUMN gender VARCHAR(50),
    ADD COLUMN address VARCHAR(255),
    ADD COLUMN phone VARCHAR(50),
    DROP COLUMN specialization,
    DROP COLUMN consultation_hours;

-- Drop Medical History Column from Patients Table
ALTER TABLE patients
    DROP COLUMN medical_history;
INSERT INTO doctors (id, username, email, role)
VALUES 
(1, 'drjohnsmith', 'john.smith@example.com', 'doctor'),
(2, 'drjanedoe', 'jane.doe@example.com', 'doctor'),
(3, 'drjamesbrown', 'james.brown@example.com', 'doctor'),
(4, 'drpatriciajohnson', 'patricia.johnson@example.com', 'doctor'),
(5, 'drrobertdavis', 'robert.davis@example.com', 'doctor'),
(6, 'drmarymiller', 'mary.miller@example.com', 'doctor'),
(7, 'drwilliamwilson', 'william.wilson@example.com', 'doctor'),
(8, 'drlindataylor', 'linda.taylor@example.com', 'doctor'),
(9, 'drmichaelanderson', 'michael.anderson@example.com', 'doctor'),
(10, 'drbarbarathomas', 'barbara.thomas@example.com', 'doctor'),
(11, 'drdavidmoore', 'david.moore@example.com', 'doctor'),
(12, 'drjenniferjackson', 'jennifer.jackson@example.com', 'doctor'),
(13, 'drcharleswhite', 'charles.white@example.com', 'doctor'),
(14, 'drsusanmartin', 'susan.martin@example.com', 'doctor'),
(15, 'drstephenlee', 'stephen.lee@example.com', 'doctor');


SELECT * FROM doctors