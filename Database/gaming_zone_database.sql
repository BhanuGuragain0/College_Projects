-- ============================================================================
-- Gaming Arcade Database Schema - Cleaned & Corrected Version
-- ============================================================================
-- Fixed Issues:
-- 1. Added Staff-Session relationship (staff assignments)
-- 2. Added proper constraints (NOT NULL, CHECK, UNIQUE)
-- 3. Added foreign key cascade rules
-- 4. Corrected queries with proper JOINs
-- 5. Added strategic indexes
-- 6. Added data validation
-- 7. Enhanced with views and utility functions
-- ============================================================================

-- Drop existing tables if they exist (for clean setup)
DROP TABLE IF EXISTS SessionStaff CASCADE;
DROP TABLE IF EXISTS SessionConsole CASCADE;
DROP TABLE IF EXISTS Booking CASCADE;
DROP TABLE IF EXISTS Machine CASCADE;
DROP TABLE IF EXISTS Console CASCADE;
DROP TABLE IF EXISTS Session CASCADE;
DROP TABLE IF EXISTS Staff CASCADE;
DROP TABLE IF EXISTS Customer CASCADE;

-- ============================================================================
-- TABLE CREATION WITH PROPER CONSTRAINTS
-- ============================================================================

-- Customer Table
CREATE TABLE Customer (
    CustomerID SERIAL PRIMARY KEY,
    FirstName VARCHAR(50) NOT NULL,
    Surname VARCHAR(50) NOT NULL,
    Address VARCHAR(100) NOT NULL,
    MembershipType VARCHAR(20) NOT NULL CHECK (MembershipType IN ('Standard', 'Premium', 'VIP')),
    MembershipFee DECIMAL(10,2) NOT NULL CHECK (MembershipFee >= 0),
    JoinDate DATE NOT NULL DEFAULT CURRENT_DATE,
    DateOfBirth DATE NOT NULL,
    Email VARCHAR(100) UNIQUE,
    Phone VARCHAR(15),
    IsActive BOOLEAN DEFAULT TRUE,
    CONSTRAINT check_age CHECK (DateOfBirth < CURRENT_DATE),
    CONSTRAINT check_join_date CHECK (JoinDate <= CURRENT_DATE)
);

-- Session Table
CREATE TABLE Session (
    SessionID SERIAL PRIMARY KEY,
    SessionDay VARCHAR(10) NOT NULL CHECK (SessionDay IN ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')),
    StartTime TIME NOT NULL,
    EndTime TIME NOT NULL,
    SessionType VARCHAR(50) NOT NULL CHECK (SessionType IN ('Arcade', 'Console', 'VR', 'Mixed')),
    Floor INT NOT NULL CHECK (Floor BETWEEN 1 AND 5),
    Price DECIMAL(10,2) NOT NULL CHECK (Price > 0),
    MaxCapacity INT DEFAULT 20 CHECK (MaxCapacity > 0),
    CONSTRAINT check_time_order CHECK (EndTime > StartTime)
);

-- Staff Table
CREATE TABLE Staff (
    StaffID SERIAL PRIMARY KEY,
    StaffName VARCHAR(50) NOT NULL,
    Role VARCHAR(50) NOT NULL CHECK (Role IN ('Counter', 'Manager', 'Technician', 'Supervisor')),
    Email VARCHAR(100) UNIQUE,
    Phone VARCHAR(15),
    HireDate DATE DEFAULT CURRENT_DATE,
    Salary DECIMAL(10,2) CHECK (Salary > 0),
    IsActive BOOLEAN DEFAULT TRUE
);

-- NEW: Staff-Session Assignment Table (Many-to-Many relationship)
CREATE TABLE SessionStaff (
    SessionStaffID SERIAL PRIMARY KEY,
    SessionID INT NOT NULL REFERENCES Session(SessionID) ON DELETE CASCADE,
    StaffID INT NOT NULL REFERENCES Staff(StaffID) ON DELETE CASCADE,
    AssignmentDate DATE DEFAULT CURRENT_DATE,
    UNIQUE(SessionID, StaffID)  -- Prevent duplicate assignments
);

-- Booking Table (Enhanced with proper constraints)
CREATE TABLE Booking (
    BookingID SERIAL PRIMARY KEY,
    CustomerID INT NOT NULL REFERENCES Customer(CustomerID) ON DELETE CASCADE,
    SessionID INT NOT NULL REFERENCES Session(SessionID) ON DELETE RESTRICT,
    Date DATE NOT NULL DEFAULT CURRENT_DATE,
    Member BOOLEAN NOT NULL DEFAULT FALSE,
    Fee DECIMAL(10,2) NOT NULL CHECK (Fee >= 0),
    Prepaid BOOLEAN DEFAULT FALSE,
    Status VARCHAR(20) DEFAULT 'Confirmed' CHECK (Status IN ('Confirmed', 'Cancelled', 'Completed', 'No-Show')),
    BookingTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT check_booking_date CHECK (Date >= CURRENT_DATE - INTERVAL '30 days')
);

-- Machine Table (Arcade Machines)
CREATE TABLE Machine (
    MachineID SERIAL PRIMARY KEY,
    Game VARCHAR(50) NOT NULL,
    Year INT NOT NULL CHECK (Year BETWEEN 1970 AND EXTRACT(YEAR FROM CURRENT_DATE)),
    Floor INT NOT NULL CHECK (Floor BETWEEN 1 AND 5),
    Manufacturer VARCHAR(50),
    IsOperational BOOLEAN DEFAULT TRUE,
    LastMaintenance DATE,
    UNIQUE(Game, Year)  -- Same game from same year is duplicate
);

-- Console Table
CREATE TABLE Console (
    ConsoleID SERIAL PRIMARY KEY,
    Name VARCHAR(50) NOT NULL UNIQUE,
    PEGI VARCHAR(10) CHECK (PEGI IN ('3+', '7+', '12+', '16+', '18+')),
    ConsoleType VARCHAR(50) NOT NULL,
    Manufacturer VARCHAR(50),
    ReleaseYear INT CHECK (ReleaseYear BETWEEN 1970 AND EXTRACT(YEAR FROM CURRENT_DATE)),
    IsAvailable BOOLEAN DEFAULT TRUE
);

-- Session Console Assignment (Many-to-Many)
CREATE TABLE SessionConsole (
    SessionConsoleID SERIAL PRIMARY KEY,
    SessionID INT NOT NULL REFERENCES Session(SessionID) ON DELETE CASCADE,
    ConsoleID INT NOT NULL REFERENCES Console(ConsoleID) ON DELETE CASCADE,
    Quantity INT NOT NULL CHECK (Quantity > 0),
    UNIQUE(SessionID, ConsoleID)
);

-- ============================================================================
-- CREATE STRATEGIC INDEXES FOR PERFORMANCE
-- ============================================================================

-- Customer indexes
CREATE INDEX idx_customer_membership ON Customer(MembershipType);
CREATE INDEX idx_customer_join_date ON Customer(JoinDate);
CREATE INDEX idx_customer_active ON Customer(IsActive);
CREATE INDEX idx_customer_name ON Customer(FirstName, Surname);

-- Booking indexes
CREATE INDEX idx_booking_customer ON Booking(CustomerID);
CREATE INDEX idx_booking_session ON Booking(SessionID);
CREATE INDEX idx_booking_date ON Booking(Date);
CREATE INDEX idx_booking_status ON Booking(Status);
CREATE INDEX idx_booking_prepaid ON Booking(Prepaid);
-- Composite index for common query pattern
CREATE INDEX idx_booking_customer_date ON Booking(CustomerID, Date);

-- Session indexes
CREATE INDEX idx_session_day ON Session(SessionDay);
CREATE INDEX idx_session_type ON Session(SessionType);
CREATE INDEX idx_session_floor ON Session(Floor);
CREATE INDEX idx_session_time ON Session(StartTime, EndTime);

-- Machine indexes
CREATE INDEX idx_machine_floor ON Machine(Floor);
CREATE INDEX idx_machine_year ON Machine(Year);
CREATE INDEX idx_machine_operational ON Machine(IsOperational);
CREATE INDEX idx_machine_game ON Machine(Game);

-- Console indexes
CREATE INDEX idx_console_type ON Console(ConsoleType);
CREATE INDEX idx_console_pegi ON Console(PEGI);
CREATE INDEX idx_console_available ON Console(IsAvailable);

-- Staff indexes
CREATE INDEX idx_staff_role ON Staff(Role);
CREATE INDEX idx_staff_active ON Staff(IsActive);

-- SessionStaff indexes
CREATE INDEX idx_session_staff_session ON SessionStaff(SessionID);
CREATE INDEX idx_session_staff_staff ON SessionStaff(StaffID);

-- ============================================================================
-- INSERT SAMPLE DATA
-- ============================================================================

-- Insert Customers
INSERT INTO Customer (FirstName, Surname, Address, MembershipType, MembershipFee, JoinDate, DateOfBirth, Email, Phone)
VALUES 
('Saroj', 'Upadhyay', 'Dillibazar, Kathmandu', 'Standard', 1000.00, '2023-09-01', '1998-02-01', 'saroj.upadhyay@email.com', '9841234567'),
('Shyam', 'Sharma', 'Thamel, Kathmandu', 'Premium', 1500.00, '2023-07-15', '1995-05-12', 'shyam.sharma@email.com', '9851234568'),
('Ravi', 'Singh', 'Patan, Lalitpur', 'Standard', 1000.00, '2023-08-10', '1992-03-22', 'ravi.singh@email.com', '9861234569'),
('Anita', 'KC', 'Baneshwor, Kathmandu', 'Premium', 1500.00, '2023-06-25', '1999-11-10', 'anita.kc@email.com', '9871234570'),
('Ram', 'Thapa', 'Balaju, Kathmandu', 'Standard', 1000.00, '2023-09-05', '2000-01-15', 'ram.thapa@email.com', '9881234571'),
('Sita', 'Gurung', 'Bhaktapur', 'VIP', 2000.00, '2023-05-20', '1997-07-08', 'sita.gurung@email.com', '9891234572'),
('Krishna', 'Rai', 'Pokhara', 'Premium', 1500.00, '2023-08-01', '1996-09-14', 'krishna.rai@email.com', '9801234573'),
('Maya', 'Tamang', 'Kirtipur, Kathmandu', 'Standard', 1000.00, '2023-09-10', '2001-04-25', 'maya.tamang@email.com', '9811234574');

-- Insert Sessions
INSERT INTO Session (SessionDay, StartTime, EndTime, SessionType, Floor, Price, MaxCapacity)
VALUES 
('Monday', '10:00:00', '12:00:00', 'Arcade', 1, 200.00, 25),
('Monday', '14:00:00', '16:00:00', 'Console', 2, 300.00, 15),
('Tuesday', '14:00:00', '16:00:00', 'Console', 2, 300.00, 15),
('Wednesday', '16:00:00', '18:00:00', 'Arcade', 1, 200.00, 25),
('Thursday', '10:00:00', '12:00:00', 'Console', 2, 300.00, 15),
('Friday', '18:00:00', '20:00:00', 'Arcade', 1, 250.00, 30),
('Saturday', '10:00:00', '12:00:00', 'VR', 3, 400.00, 10),
('Saturday', '14:00:00', '18:00:00', 'Mixed', 1, 350.00, 35),
('Sunday', '12:00:00', '16:00:00', 'Console', 2, 320.00, 20);

-- Insert Staff
INSERT INTO Staff (StaffName, Role, Email, Phone, HireDate, Salary)
VALUES 
('Ajay Kumar', 'Counter', 'ajay.kumar@arcade.com', '9841111111', '2023-01-15', 30000.00),
('Sunita Devi', 'Manager', 'sunita.devi@arcade.com', '9841111112', '2022-06-01', 50000.00),
('Kiran Shrestha', 'Technician', 'kiran.shrestha@arcade.com', '9841111113', '2023-03-10', 35000.00),
('Gopal Sharma', 'Counter', 'gopal.sharma@arcade.com', '9841111114', '2023-05-20', 30000.00),
('Sita Rai', 'Technician', 'sita.rai@arcade.com', '9841111115', '2023-02-28', 35000.00),
('Binod Adhikari', 'Supervisor', 'binod.adhikari@arcade.com', '9841111116', '2022-12-01', 45000.00),
('Laxmi Thapa', 'Counter', 'laxmi.thapa@arcade.com', '9841111117', '2023-07-01', 30000.00);

-- Insert Staff-Session Assignments
INSERT INTO SessionStaff (SessionID, StaffID)
VALUES 
-- Monday sessions
(1, 1),  -- Ajay on Monday morning Arcade
(1, 3),  -- Kiran (technician) on Monday morning
(2, 2),  -- Sunita (manager) on Monday afternoon Console
-- Tuesday
(3, 4),  -- Gopal on Tuesday Console
(3, 5),  -- Sita (technician) on Tuesday
-- Wednesday
(4, 1),  -- Ajay on Wednesday Arcade
(4, 3),  -- Kiran on Wednesday
-- Thursday
(5, 7),  -- Laxmi on Thursday Console
(5, 5),  -- Sita on Thursday
-- Friday
(6, 4),  -- Gopal on Friday Arcade
(6, 6),  -- Binod (supervisor) on Friday
-- Saturday
(7, 2),  -- Sunita on Saturday VR
(7, 3),  -- Kiran on Saturday VR
(8, 1),  -- Ajay on Saturday Mixed
(8, 6),  -- Binod on Saturday Mixed
-- Sunday
(9, 7),  -- Laxmi on Sunday Console
(9, 5);  -- Sita on Sunday Console

-- Insert Bookings
INSERT INTO Booking (CustomerID, SessionID, Date, Member, Fee, Prepaid, Status)
VALUES 
(1, 1, '2023-09-01', TRUE, 100.00, FALSE, 'Completed'),
(2, 2, '2023-09-01', TRUE, 150.00, TRUE, 'Completed'),
(3, 3, '2023-09-05', TRUE, 150.00, FALSE, 'Completed'),
(4, 4, '2023-09-06', TRUE, 100.00, TRUE, 'Completed'),
(5, 5, '2023-09-07', TRUE, 150.00, FALSE, 'Confirmed'),
(6, 6, '2023-09-08', TRUE, 125.00, TRUE, 'Confirmed'),
(7, 7, '2023-09-09', TRUE, 200.00, FALSE, 'Confirmed'),
(8, 8, '2023-09-09', TRUE, 175.00, TRUE, 'Confirmed'),
(1, 6, '2023-09-15', TRUE, 125.00, FALSE, 'Confirmed'),
(2, 4, '2023-09-13', TRUE, 100.00, TRUE, 'Completed'),
(3, 7, '2023-09-16', TRUE, 200.00, FALSE, 'Confirmed'),
(4, 1, '2023-09-04', TRUE, 100.00, FALSE, 'No-Show');

-- Insert Machines
INSERT INTO Machine (Game, Year, Floor, Manufacturer, IsOperational, LastMaintenance)
VALUES 
('Pac-Man', 1980, 1, 'Namco', TRUE, '2023-08-15'),
('Street Fighter II', 1991, 1, 'Capcom', TRUE, '2023-08-20'),
('Donkey Kong', 1981, 2, 'Nintendo', TRUE, '2023-07-10'),
('Grand Theft Auto', 2001, 1, 'Rockstar', TRUE, '2023-08-25'),
('Super Mario Bros', 1985, 2, 'Nintendo', FALSE, '2023-06-30'),
('Mortal Kombat', 1992, 1, 'Midway', TRUE, '2023-08-18'),
('Tekken 3', 1997, 2, 'Namco', TRUE, '2023-08-22'),
('Dance Dance Revolution', 1998, 1, 'Konami', TRUE, '2023-08-05'),
('Time Crisis', 1995, 2, 'Namco', TRUE, '2023-07-28'),
('House of the Dead', 1996, 1, 'Sega', TRUE, '2023-08-12');

-- Insert Consoles
INSERT INTO Console (Name, PEGI, ConsoleType, Manufacturer, ReleaseYear, IsAvailable)
VALUES 
('PlayStation 2', '18+', 'PS2', 'Sony', 2000, TRUE),
('Xbox', '16+', 'Xbox', 'Microsoft', 2001, TRUE),
('Nintendo Switch', '12+', 'Switch', 'Nintendo', 2017, TRUE),
('PlayStation 4', '18+', 'PS4', 'Sony', 2013, TRUE),
('PlayStation 5', '18+', 'PS5', 'Sony', 2020, TRUE),
('Xbox Series X', '18+', 'Xbox', 'Microsoft', 2020, TRUE),
('Nintendo Wii', '7+', 'Wii', 'Nintendo', 2006, TRUE),
('PlayStation 3', '18+', 'PS3', 'Sony', 2006, TRUE);

-- Insert Session-Console Assignments
INSERT INTO SessionConsole (SessionID, ConsoleID, Quantity)
VALUES 
(1, 1, 10),  -- Monday Arcade: PS2
(2, 4, 5),   -- Monday Console: PS4
(2, 5, 3),   -- Monday Console: PS5
(3, 2, 5),   -- Tuesday Console: Xbox
(3, 6, 4),   -- Tuesday Console: Xbox Series X
(4, 3, 8),   -- Wednesday Arcade: Switch
(5, 4, 7),   -- Thursday Console: PS4
(5, 8, 5),   -- Thursday Console: PS3
(6, 5, 6),   -- Friday Arcade: PS5
(7, 3, 4),   -- Saturday VR: Switch
(7, 7, 3),   -- Saturday VR: Wii
(8, 1, 8),   -- Saturday Mixed: PS2
(8, 4, 6),   -- Saturday Mixed: PS4
(9, 5, 5),   -- Sunday Console: PS5
(9, 6, 4);   -- Sunday Console: Xbox Series X

-- ============================================================================
-- CREATE USEFUL VIEWS
-- ============================================================================

-- View: Complete Booking Information
CREATE OR REPLACE VIEW vw_BookingDetails AS
SELECT 
    B.BookingID,
    C.FirstName || ' ' || C.Surname AS CustomerName,
    C.MembershipType,
    S.SessionDay,
    S.StartTime,
    S.EndTime,
    S.SessionType,
    S.Floor,
    B.Date AS BookingDate,
    B.Fee,
    B.Prepaid,
    B.Status,
    B.BookingTime
FROM Booking B
JOIN Customer C ON B.CustomerID = C.CustomerID
JOIN Session S ON B.SessionID = S.SessionID;

-- View: Session with Staff Assignments
CREATE OR REPLACE VIEW vw_SessionStaffing AS
SELECT 
    S.SessionID,
    S.SessionDay,
    S.StartTime,
    S.EndTime,
    S.SessionType,
    S.Floor,
    ST.StaffName,
    ST.Role
FROM Session S
LEFT JOIN SessionStaff SS ON S.SessionID = SS.SessionID
LEFT JOIN Staff ST ON SS.StaffID = ST.StaffID
ORDER BY S.SessionID, ST.Role;

-- View: Revenue Summary
CREATE OR REPLACE VIEW vw_RevenueBySession AS
SELECT 
    S.SessionID,
    S.SessionDay,
    S.SessionType,
    COUNT(B.BookingID) AS TotalBookings,
    SUM(B.Fee) AS TotalRevenue,
    AVG(B.Fee) AS AverageRevenue
FROM Session S
LEFT JOIN Booking B ON S.SessionID = B.SessionID
WHERE B.Status IN ('Confirmed', 'Completed')
GROUP BY S.SessionID, S.SessionDay, S.SessionType;

-- View: Machine Inventory by Floor
CREATE OR REPLACE VIEW vw_MachineInventory AS
SELECT 
    Floor,
    COUNT(*) AS TotalMachines,
    SUM(CASE WHEN IsOperational THEN 1 ELSE 0 END) AS OperationalMachines,
    SUM(CASE WHEN NOT IsOperational THEN 1 ELSE 0 END) AS NonOperationalMachines
FROM Machine
GROUP BY Floor
ORDER BY Floor;

-- ============================================================================
-- CORRECTED QUERIES WITH PROPER JOINS
-- ============================================================================

-- Query 1: Find customers who booked session 1 but haven't prepaid
-- FIXED: Added proper column aliases and better formatting
SELECT 
    C.FirstName,
    C.Surname,
    C.Email,
    B.Fee,
    B.Date AS BookingDate
FROM Booking B
INNER JOIN Customer C ON B.CustomerID = C.CustomerID
WHERE B.SessionID = 1 
  AND B.Prepaid = FALSE;

-- Query 2: Get all machines on floor 2, ordered by year (newest first)
-- FIXED: Added more useful columns
SELECT 
    MachineID,
    Game,
    Year,
    Manufacturer,
    IsOperational,
    LastMaintenance
FROM Machine
WHERE Floor = 2
ORDER BY Year DESC;

-- Query 3: Count PS2 consoles
-- FIXED: Better naming and additional info
SELECT 
    ConsoleType,
    COUNT(*) AS ConsoleCount,
    SUM(CASE WHEN IsAvailable THEN 1 ELSE 0 END) AS AvailableCount
FROM Console
WHERE ConsoleType = 'PS2'
GROUP BY ConsoleType;

-- Query 4: Get all counter staff assigned to sessions
-- FIXED: Now properly shows staff assignments with session details
SELECT DISTINCT
    ST.StaffID,
    ST.StaffName,
    ST.Role,
    S.SessionID,
    S.SessionDay,
    S.StartTime,
    S.EndTime,
    S.SessionType
FROM Staff ST
INNER JOIN SessionStaff SS ON ST.StaffID = SS.StaffID
INNER JOIN Session S ON SS.SessionID = S.SessionID
WHERE ST.Role = 'Counter'
ORDER BY S.SessionDay, S.StartTime;

-- Query 5: Revenue by membership type
SELECT 
    C.MembershipType,
    COUNT(B.BookingID) AS TotalBookings,
    SUM(B.Fee) AS TotalRevenue,
    AVG(B.Fee) AS AverageBookingFee
FROM Booking B
INNER JOIN Customer C ON B.CustomerID = C.CustomerID
WHERE B.Status IN ('Confirmed', 'Completed')
GROUP BY C.MembershipType
ORDER BY TotalRevenue DESC;

-- Query 6: Most popular session types
SELECT 
    S.SessionType,
    COUNT(B.BookingID) AS BookingCount,
    SUM(B.Fee) AS Revenue
FROM Session S
LEFT JOIN Booking B ON S.SessionID = B.SessionID
WHERE B.Status IN ('Confirmed', 'Completed')
GROUP BY S.SessionType
ORDER BY BookingCount DESC;

-- Query 7: Customers with multiple bookings
SELECT 
    C.CustomerID,
    C.FirstName,
    C.Surname,
    C.MembershipType,
    COUNT(B.BookingID) AS TotalBookings,
    SUM(B.Fee) AS TotalSpent
FROM Customer C
INNER JOIN Booking B ON C.CustomerID = B.CustomerID
GROUP BY C.CustomerID, C.FirstName, C.Surname, C.MembershipType
HAVING COUNT(B.BookingID) > 1
ORDER BY TotalBookings DESC;

-- Query 8: Sessions with available capacity
SELECT 
    S.SessionID,
    S.SessionDay,
    S.StartTime,
    S.EndTime,
    S.SessionType,
    S.MaxCapacity,
    COUNT(B.BookingID) AS CurrentBookings,
    S.MaxCapacity - COUNT(B.BookingID) AS AvailableSpots
FROM Session S
LEFT JOIN Booking B ON S.SessionID = B.SessionID 
    AND B.Status IN ('Confirmed')
GROUP BY S.SessionID, S.SessionDay, S.StartTime, S.EndTime, S.SessionType, S.MaxCapacity
HAVING S.MaxCapacity > COUNT(B.BookingID)
ORDER BY S.SessionDay, S.StartTime;

-- Query 9: Staff workload (number of sessions assigned)
SELECT 
    ST.StaffID,
    ST.StaffName,
    ST.Role,
    COUNT(SS.SessionID) AS SessionsAssigned
FROM Staff ST
LEFT JOIN SessionStaff SS ON ST.StaffID = SS.StaffID
WHERE ST.IsActive = TRUE
GROUP BY ST.StaffID, ST.StaffName, ST.Role
ORDER BY SessionsAssigned DESC;

-- Query 10: Consoles usage across sessions
SELECT 
    C.Name AS ConsoleName,
    C.ConsoleType,
    COUNT(DISTINCT SC.SessionID) AS SessionsUsed,
    SUM(SC.Quantity) AS TotalUnits
FROM Console C
LEFT JOIN SessionConsole SC ON C.ConsoleID = SC.ConsoleID
GROUP BY C.ConsoleID, C.Name, C.ConsoleType
ORDER BY SessionsUsed DESC, TotalUnits DESC;

-- ============================================================================
-- DATA MODIFICATION QUERIES (UPDATES & DELETES)
-- ============================================================================

-- Update 1: Move Grand Theft Auto machine to floor 2
-- FIXED: Use specific identifier to avoid affecting multiple rows
UPDATE Machine
SET Floor = 2
WHERE Game = 'Grand Theft Auto' 
  AND Year = 2001;

-- Update 2: Mark Super Mario machine as operational after maintenance
UPDATE Machine
SET IsOperational = TRUE,
    LastMaintenance = CURRENT_DATE
WHERE Game = 'Super Mario Bros' 
  AND Year = 1985;

-- Update 3: Update customer membership
UPDATE Customer
SET MembershipType = 'Premium',
    MembershipFee = 1500.00
WHERE CustomerID = 1;

-- Delete 1: Remove cancelled bookings older than 30 days
-- SAFE: Uses date constraint
DELETE FROM Booking
WHERE Status = 'Cancelled'
  AND Date < CURRENT_DATE - INTERVAL '30 days';

-- Delete 2: Remove specific machine (safe with proper identifiers)
-- FIXED: Use multiple identifiers to ensure correct row
DELETE FROM Machine
WHERE Game = 'Super Mario Bros' 
  AND Year = 1985
  AND MachineID = (
      SELECT MachineID 
      FROM Machine 
      WHERE Game = 'Super Mario Bros' AND Year = 1985 
      LIMIT 1
  );

-- ============================================================================
-- UTILITY FUNCTIONS
-- ============================================================================

-- Function: Calculate customer age
CREATE OR REPLACE FUNCTION calculate_age(birth_date DATE)
RETURNS INT AS $$
BEGIN
    RETURN EXTRACT(YEAR FROM AGE(birth_date));
END;
$$ LANGUAGE plpgsql;

-- Function: Check session availability
CREATE OR REPLACE FUNCTION check_session_availability(session_id INT)
RETURNS TABLE(
    SessionID INT,
    MaxCapacity INT,
    CurrentBookings BIGINT,
    AvailableSpots BIGINT,
    IsAvailable BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        S.SessionID,
        S.MaxCapacity,
        COUNT(B.BookingID) AS CurrentBookings,
        S.MaxCapacity - COUNT(B.BookingID) AS AvailableSpots,
        (S.MaxCapacity > COUNT(B.BookingID)) AS IsAvailable
    FROM Session S
    LEFT JOIN Booking B ON S.SessionID = B.SessionID 
        AND B.Status = 'Confirmed'
    WHERE S.SessionID = session_id
    GROUP BY S.SessionID, S.MaxCapacity;
END;
$$ LANGUAGE plpgsql;

-- Function: Calculate booking fee based on membership
CREATE OR REPLACE FUNCTION calculate_booking_fee(
    session_id INT,
    customer_id INT
) RETURNS DECIMAL(10,2) AS $$
DECLARE
    base_price DECIMAL(10,2);
    membership_type VARCHAR(20);
    discount_rate DECIMAL(3,2);
BEGIN
    -- Get session price
    SELECT Price INTO base_price
    FROM Session
    WHERE SessionID = session_id;
    
    -- Get customer membership
    SELECT MembershipType INTO membership_type
    FROM Customer
    WHERE CustomerID = customer_id;
    
    -- Apply discount based on membership
    discount_rate := CASE membership_type
        WHEN 'Standard' THEN 0.50  -- 50% off
        WHEN 'Premium' THEN 0.60   -- 40% off
        WHEN 'VIP' THEN 0.70       -- 30% off
        ELSE 1.00                   -- No discount
    END;
    
    RETURN base_price * discount_rate;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- EXAMPLE USAGE OF FUNCTIONS
-- ============================================================================

-- Get ages of all customers
SELECT 
    CustomerID,
    FirstName,
    Surname,
    DateOfBirth,
    calculate_age(DateOfBirth) AS Age
FROM Customer;

-- Check availability for a specific session
SELECT * FROM check_session_availability(1);

-- Calculate booking fee for a customer
SELECT calculate_booking_fee(1, 1) AS CalculatedFee;

-- ============================================================================
-- ADVANCED ANALYTICAL QUERIES
-- ============================================================================

-- Top spending customers
SELECT 
    C.CustomerID,
    C.FirstName || ' ' || C.Surname AS CustomerName,
    C.MembershipType,
    COUNT(B.BookingID) AS TotalBookings,
    SUM(B.Fee) AS TotalSpent,
    AVG(B.Fee) AS AvgSpendingPerBooking
FROM Customer C
INNER JOIN Booking B ON C.CustomerID = B.CustomerID
WHERE B.Status IN ('Confirmed', 'Completed')
GROUP BY C.CustomerID, CustomerName, C.MembershipType
ORDER BY TotalSpent DESC
LIMIT 10;

-- Session performance by day of week
SELECT 
    S.SessionDay,
    COUNT(DISTINCT S.SessionID) AS TotalSessions,
    COUNT(B.BookingID) AS TotalBookings,
    SUM(B.Fee) AS Revenue,
    AVG(B.Fee) AS AvgBookingValue
FROM Session S
LEFT JOIN Booking B ON S.SessionID = B.SessionID
WHERE B.Status IN ('Confirmed', 'Completed')
GROUP BY S.SessionDay
ORDER BY Revenue DESC;

-- Machines needing maintenance (not serviced in 30 days)
SELECT 
    MachineID,
    Game,
    Year,
    Floor,
    LastMaintenance,
    CURRENT_DATE - LastMaintenance AS DaysSinceLastMaintenance
FROM Machine
WHERE LastMaintenance < CURRENT_DATE - INTERVAL '30 days'
   OR LastMaintenance IS NULL
ORDER BY DaysSinceLastMaintenance DESC NULLS FIRST;

-- ============================================================================
-- COMMENTS & DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE Customer IS 'Stores customer information and membership details';
COMMENT ON TABLE Session IS 'Defines gaming sessions with scheduling and pricing';
COMMENT ON TABLE Staff IS 'Employee information and roles';
COMMENT ON TABLE SessionStaff IS 'Associates staff members with specific sessions';
COMMENT ON TABLE Booking IS 'Customer bookings for gaming sessions';
COMMENT ON TABLE Machine IS 'Arcade machine inventory';
COMMENT ON TABLE Console IS 'Gaming console inventory';
COMMENT ON TABLE SessionConsole IS 'Console allocation to sessions';

COMMENT ON COLUMN Customer.MembershipType IS 'Type: Standard, Premium, or VIP';
COMMENT ON COLUMN Booking.Fee IS 'Actual fee charged (may include discounts)';
COMMENT ON COLUMN Session.MaxCapacity IS 'Maximum number of customers per session';
COMMENT ON COLUMN Machine.IsOperational IS 'Whether machine is currently working';

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================

-- Verification queries to check data integrity
SELECT 'Total Customers:' AS Metric, COUNT(*) AS Count FROM Customer
UNION ALL
SELECT 'Total Sessions:', COUNT(*) FROM Session
UNION ALL
SELECT 'Total Bookings:', COUNT(*) FROM Booking
UNION ALL
SELECT 'Total Machines:', COUNT(*) FROM Machine
UNION ALL
SELECT 'Total Consoles:', COUNT(*) FROM Console
UNION ALL
SELECT 'Total Staff:', COUNT(*) FROM Staff
UNION ALL
SELECT 'Staff-Session Assignments:', COUNT(*) FROM SessionStaff;