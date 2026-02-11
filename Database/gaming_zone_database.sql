-- Table Creation
CREATE TABLE Customer (
    CustomerID SERIAL PRIMARY KEY,
    FirstName VARCHAR(50),
    Surname VARCHAR(50),
    Address VARCHAR(100),
    MembershipType VARCHAR(20),
    MembershipFee DECIMAL(10,2),
    JoinDate DATE,
    DateOfBirth DATE
);

CREATE TABLE Session (
    SessionID SERIAL PRIMARY KEY,
    SessionDay VARCHAR(10),
    StartTime TIME,
    EndTime TIME,
    SessionType VARCHAR(50),
    Floor INT,
    Price DECIMAL(10,2)
);

CREATE TABLE Staff (
    StaffID SERIAL PRIMARY KEY,
    StaffName VARCHAR(50),
    Role VARCHAR(50)
);

CREATE TABLE Booking (
    BookingID SERIAL PRIMARY KEY,
    CustomerID INT REFERENCES Customer(CustomerID),
    SessionID INT REFERENCES Session(SessionID),
    Date DATE,
    Member BOOLEAN,
    Fee DECIMAL(10,2),
    Prepaid BOOLEAN
);

CREATE TABLE Machine (
    MachineID SERIAL PRIMARY KEY,
    Game VARCHAR(50),
    Year INT,
    Floor INT
);

CREATE TABLE Console (
    ConsoleID SERIAL PRIMARY KEY,
    Name VARCHAR(50),
    PEGI VARCHAR(10),
    ConsoleType VARCHAR(50)
);

CREATE TABLE SessionConsole (
    SessionConsoleID SERIAL PRIMARY KEY,
    SessionID INT REFERENCES Session(SessionID),
    ConsoleID INT REFERENCES Console(ConsoleID),
    Quantity INT
);

-- Data Insertion
INSERT INTO Customer (FirstName, Surname, Address, MembershipType, MembershipFee, JoinDate, DateOfBirth)
VALUES 
('Saroj', 'Upadhyay', 'Dillibazar, Kathmandu', 'Standard', 1000.00, '2023-09-01', '1998-02-01'),
('Shyam', 'Sharma', 'Thamel, Kathmandu', 'Premium', 1500.00, '2023-07-15', '1995-05-12'),
('Ravi', 'Singh', 'Patan, Lalitpur', 'Standard', 1000.00, '2023-08-10', '1992-03-22'),
('Anita', 'KC', 'Baneshwor, Kathmandu', 'Premium', 1500.00, '2023-06-25', '1999-11-10'),
('Ram', 'Thapa', 'Balaju, Kathmandu', 'Standard', 1000.00, '2023-09-05', '2000-01-15');

INSERT INTO Session (SessionDay, StartTime, EndTime, SessionType, Floor, Price)
VALUES 
('Monday', '10:00:00', '12:00:00', 'Arcade', 1, 200.00),
('Tuesday', '14:00:00', '16:00:00', 'Console', 2, 300.00),
('Wednesday', '16:00:00', '18:00:00', 'Arcade', 1, 200.00),
('Thursday', '10:00:00', '12:00:00', 'Console', 2, 300.00),
('Friday', '18:00:00', '20:00:00', 'Arcade', 1, 250.00);

INSERT INTO Staff (StaffName, Role)
VALUES 
('Ajay', 'Counter'),
('Sunita', 'Manager'),
('Kiran', 'Technician'),
('Gopal', 'Counter'),
('Sita', 'Technician');

INSERT INTO Booking (CustomerID, SessionID, Date, Member, Fee, Prepaid)
VALUES 
(1, 1, '2023-09-01', TRUE, 100.00, FALSE),
(2, 2, '2023-07-15', TRUE, 150.00, TRUE),
(3, 3, '2023-08-10', TRUE, 200.00, FALSE),
(4, 4, '2023-06-25', TRUE, 150.00, TRUE),
(5, 5, '2023-09-05', TRUE, 250.00, FALSE);

INSERT INTO Machine (Game, Year, Floor)
VALUES 
('Pac-Man', 1980, 1),
('Street Fighter', 1991, 1),
('Donkey Kong', 1981, 2),
('Grand Theft Auto', 2001, 1),
('Super Mario', 1985, 2);

INSERT INTO Console (Name, PEGI, ConsoleType)
VALUES 
('PlayStation 2', '18+', 'PS2'),
('Xbox', '16+', 'Xbox'),
('Nintendo Switch', '12+', 'Switch'),
('PlayStation 4', '18+', 'PS4'),
('PlayStation 5', '18+', 'PS5');

INSERT INTO SessionConsole (SessionID, ConsoleID, Quantity)
VALUES 
(1, 1, 10),
(2, 2, 5),
(3, 3, 8),
(4, 4, 7),
(5, 5, 6);

-- Create indexes for performance optimization
CREATE INDEX idx_customer_id ON Booking(CustomerID);
CREATE INDEX idx_session_id ON Booking(SessionID);
CREATE INDEX idx_machine_floor ON Machine(Floor);
CREATE INDEX idx_console_type ON Console(ConsoleType);

-- Queries
SELECT C.FirstName, C.Surname
FROM Booking B
JOIN Customer C ON B.CustomerID = C.CustomerID
WHERE B.SessionID = 1 AND B.Prepaid = FALSE;

SELECT *
FROM Machine
WHERE Floor = 2
ORDER BY Year DESC;

SELECT COUNT(*) AS PS2_Game_Count
FROM Console
WHERE ConsoleType = 'PS2';

-- FIXED: Corrected the staff query (Staff works with sessions, not directly with session consoles)
SELECT DISTINCT S.StaffName
FROM Staff S
WHERE S.Role = 'Counter'
LIMIT 5;

-- FIXED: Corrected the game name
UPDATE Machine
SET Floor = 2
WHERE Game = 'Grand Theft Auto';

-- FIXED: Use SAFE delete with proper identifier
DELETE FROM Machine
WHERE Game = 'Super Mario' AND Year = 1985;
