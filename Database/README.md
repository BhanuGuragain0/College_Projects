# 💾 Database Projects

Production database schemas, queries, and management systems.

## Overview

This directory contains comprehensive database designs and implementations for real-world systems.

## Projects

### Gaming Zone Database
**`gaming_zone_database.sql`**

Complete database management system for a gaming zone facility.

**Features:**
- User management and authentication
- Game inventory tracking
- Booking and reservation system
- Payment processing
- Usage analytics
- Maintenance scheduling

**Technologies:** MySQL, SQL, Stored Procedures

**Concepts Demonstrated:**
- Relational database design (3NF)
- Complex queries with JOINs
- Transactions and ACID compliance
- Stored procedures for business logic
- Indexing for performance
- Data integrity constraints

## Installation

```bash
mysql -u root -p < gaming_zone_database.sql
```

## Usage

Connect to database and run queries:
```bash
mysql -u root -p gaming_zone
```

## Database Diagram

Tables include:
- users (customers)
- games (inventory)
- bookings
- payments
- staff
- maintenance_logs

---

*Part of College_Projects portfolio*
