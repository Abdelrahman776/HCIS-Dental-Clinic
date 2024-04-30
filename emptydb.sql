CREATE TABLE `patients` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `user_id` int,
  `full_name` varchar(255),
  `dob` date,
  `gender` varchar(255),
  `address` varchar(255),
  `phone` varchar(255),
  `email` varchar(255),
  `insurance_details` varchar(255),
  `medical_history` text,
  `dental_history` text,
  `language_preference` varchar(255)
);

CREATE TABLE `appointments` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `patient_id` int,
  `staff_id` int,
  `datetime` datetime,
  `purpose` varchar(255),
  `status` varchar(255) COMMENT 'scheduled, completed, canceled'
);

CREATE TABLE `staff` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `user_id` int,
  `name` varchar(255),
  `specialization` varchar(255),
  `contact_info` varchar(255),
  `qualifications` text,
  `working_hours` text
);

CREATE TABLE `treatments` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `appointment_id` int,
  `description` varchar(255),
  `cost` decimal,
  `duration` int COMMENT 'Duration in minutes'
);

CREATE TABLE `billing_records` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `appointment_id` int,
  `patient_id` int,
  `date` date,
  `total_cost` decimal,
  `payment_status` varchar(255) COMMENT 'paid, pending, overdue'
);

CREATE TABLE `users` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `username` varchar(255),
  `email` varchar(255) UNIQUE,  -- Ensure the email column is defined and set as UNIQUE
  `password_hash` varchar(255),
  `role` varchar(255) COMMENT 'admin, staff, patient'
);


CREATE TABLE `reports` (
  `id` int PRIMARY KEY AUTO_INCREMENT,
  `generated_by` int,
  `report_type` varchar(255),
  `created_at` datetime,
  `description` text
);

ALTER TABLE `patients` ADD FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

ALTER TABLE `appointments` ADD FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`);

ALTER TABLE `appointments` ADD FOREIGN KEY (`staff_id`) REFERENCES `staff` (`id`);

ALTER TABLE `staff` ADD FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

ALTER TABLE `treatments` ADD FOREIGN KEY (`appointment_id`) REFERENCES `appointments` (`id`);

ALTER TABLE `billing_records` ADD FOREIGN KEY (`appointment_id`) REFERENCES `appointments` (`id`);

ALTER TABLE `billing_records` ADD FOREIGN KEY (`patient_id`) REFERENCES `patients` (`id`);

ALTER TABLE `reports` ADD FOREIGN KEY (`generated_by`) REFERENCES `users` (`id`);

ALTER TABLE `users`
ADD COLUMN `email` VARCHAR(255) NOT NULL UNIQUE;
