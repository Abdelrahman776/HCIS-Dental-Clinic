ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT FALSE;
CREATE DATABASE IF NOT EXISTS dentalhcis;
USE dentalhcis;
CREATE TABLE `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(255) UNIQUE NOT NULL,
    `email` VARCHAR(255) UNIQUE NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `role` VARCHAR(50) NOT NULL
);
CREATE TABLE `patients` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT,
    `full_name` VARCHAR(255) NOT NULL,
    `dob` DATE,
    `gender` VARCHAR(50),
    `address` VARCHAR(255),
    `phone` VARCHAR(50),
    `insurance_details` VARCHAR(255),
    `medical_history` TEXT,
    `dental_history` TEXT,
    `language_preference` VARCHAR(50),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
);
