-- Existing tables
DROP TABLE IF EXISTS users_eid;
DROP TABLE IF EXISTS users_it_account;
DROP TABLE IF EXISTS enrollment;
DROP TABLE IF EXISTS bank_accounts;
DROP TABLE IF EXISTS payroll;
DROP TABLE IF EXISTS courses;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS transcripts;
DROP TABLE IF EXISTS admin_users;

CREATE TABLE admin_users (
    username TEXT PRIMARY KEY,
    password TEXT,
    firstName TEXT,
    lastName TEXT,
    email TEXT
);

CREATE TABLE users_eid (
    eid TEXT PRIMARY KEY,
    password TEXT,
    firstName TEXT,
    lastName TEXT,
    email TEXT
);

CREATE TABLE users_it_account (
    username TEXT PRIMARY KEY, 
    password TEXT,
    firstName TEXT,
    lastName TEXT,
    email TEXT
);

CREATE TABLE courses (
    courseCode TEXT,
    courseName TEXT,
    professor TEXT,
    semester TEXT,
    PRIMARY KEY (courseCode, semester)
);

CREATE TABLE enrollment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    semester TEXT,
    courseCode TEXT,
    FOREIGN KEY (username) REFERENCES users_it_account(username),
    FOREIGN KEY (courseCode, semester) REFERENCES courses(courseCode, semester)
);

CREATE TABLE bank_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    bankName TEXT NOT NULL,
    accountNumber TEXT NOT NULL,
    routingNumber TEXT NOT NULL,
    accountType TEXT NOT NULL,
    isActive BOOLEAN DEFAULT 1,
    FOREIGN KEY (username) REFERENCES users_it_account(username)
);

CREATE TABLE payroll (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    payDate TEXT,
    amount REAL,
    description TEXT,
    bankAccountId INTEGER,
    FOREIGN KEY (username) REFERENCES users_it_account(username),
    FOREIGN KEY (bankAccountId) REFERENCES bank_accounts(id)
);

CREATE TABLE applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    eid TEXT,
    applicationDate TEXT,
    program TEXT,
    status TEXT DEFAULT 'Pending', -- Pending, Approved or Rejected status of the application
    gpa REAL,
    previousDegree TEXT,
    university TEXT,
    graduationYear TEXT,
    remarks TEXT,
    updatedBy TEXT,
    FOREIGN KEY (eid) REFERENCES users_eid(eid),
    FOREIGN KEY (updatedBy) REFERENCES admin_users(username)
);

CREATE TABLE transcripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    eid TEXT,
    courseCode TEXT,
    courseName TEXT,
    grade TEXT,
    creditHours INTEGER,
    semester TEXT,
    FOREIGN KEY (eid) REFERENCES users_eid(eid)
);

-- insert admin
INSERT INTO admin_users (username, password, firstName, lastName, email) VALUES
('admin', 'admin123', 'System', 'Administrator', 'admin@ucalgary.ca');

-- insert dummy users data
INSERT INTO users_eid (eid, password, firstName, lastName, email) VALUES
('30048251', 'pass123', 'Kulsoom', 'Malik', 'kulsoom.malik@ucalgary.ca'),
('30048252', 'pass456', 'John', 'Doe', 'john.doe@ucalgary.ca'),
('30048253', 'pass789', 'Alice', 'Brown', 'alice.brown@ucalgary.ca'),
('30048254', 'pass789', 'Kamron', 'Kam', 'kamron.kam@ucalgary.ca');

INSERT INTO users_it_account (username, password, firstName, lastName, email) VALUES
('asmith', 'secure123', 'Alex', 'Smith', 'alex.smith@ucalgary.ca'),
('ebob', 'secure456', 'Emma', 'Bob', 'emma.bob@ucalgary.ca'),
('mbrown', 'secure789', 'Mike', 'Brown', 'mike.brown@ucalgary.ca');

-- insert dummy courses
INSERT INTO courses (courseCode, courseName, professor, semester) VALUES
('CPSC457', 'Operating Systems', 'Dr. Smith', 'Fall2024'),
('CPSC441', 'Computer Networks', 'Dr. Johnson', 'Fall2024'),
('CPSC471', 'Database Management Systems', 'Dr. Brown', 'Fall2024'),
('CPSC559', 'Advanced Software Engineering', 'Dr. Davis', 'Fall2024'),
('CPSC571', 'Design of Distributed Systems', 'Dr. Wilson', 'Fall2024'),
('CPSC525', 'Advanced Database Systems', 'Dr. Anderson', 'Winter2025'),
('CPSC535', 'Advanced Systems', 'Dr. Taylor', 'Winter2025'),
('CPSC559', 'Advanced Software Engineering', 'Dr. Davis', 'Winter2025'),
('CPSC567', 'Parallel Computing', 'Dr. White', 'Spring2025'),
('CPSC598', 'Cloud Computing', 'Dr. Black', 'Summer2025');

-- insert dummy enrollment
INSERT INTO enrollment (username, courseCode, semester) VALUES
('asmith', 'CPSC457', 'Fall2024'),
('asmith', 'CPSC441', 'Fall2024'),
('ebob', 'CPSC559', 'Winter2025'),
('ebob', 'CPSC571', 'Fall2024');

-- insert dummy payroll data
INSERT INTO bank_accounts (username, bankName, accountNumber, routingNumber, accountType) VALUES
('asmith', 'Royal Bank', '1234567890', '001122334', 'Checking'),
('ebob', 'TD Bank', '0987654321', '998877665', 'Savings');

INSERT INTO payroll (username, payDate, amount, description, bankAccountId) VALUES
('asmith', '2024-01-15', 1500.00, 'Monthly Payment - 1/2024', 1),
('asmith', '2024-02-15', 1500.00, 'Monthly Payment - 2/2024', 1),
('ebob', '2024-01-15', 1500.00, 'Monthly Payment - 1/2024', 2),
('ebob', '2024-02-15', 1500.00, 'Monthly Payment - 2/2024', 2);

-- insert dummy data for Eid account options
INSERT INTO applications (eid, applicationDate, program, status, gpa, previousDegree, university, graduationYear) VALUES
('30048251', '2024-02-15', 'Masters in Computer Science', 'Pending', 3.8, 'BS Computer Science', 'University of Calgary', '2023'),
('30048252', '2024-03-23', 'Masters in Electrical Eng.', 'Approved', 3.21, 'BS Computer Science', 'Windsor University', '2021'),
('30048253', '2024-04-05', 'Masters in Computer Science', 'Rejected', 2.9, 'BS Computer Science', 'Laurier Universiry', '2020');

INSERT INTO transcripts (eid, courseCode, courseName, grade, creditHours, semester) VALUES
('30048251', 'CPSC 441', 'Computer Networks', 'A', 3, 'Fall 2023'),
('30048251', 'CPSC 457', 'Operating Systems', 'A-', 3, 'Fall 2023'),
('30048251', 'CPSC 471', 'Database Management Systems', 'B+', 3, 'Winter 2024'),
('30048252', 'CPSC 471', 'Database Management Systems', 'B-', 3, 'Winter 2024');