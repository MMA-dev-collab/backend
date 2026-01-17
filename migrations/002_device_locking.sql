-- ============================================
-- Device Locking Migration
-- ============================================
-- Version: 002
-- Description: Add dual device tracking with fingerprinting and token versioning
-- Created: 2026-01-17
-- 
-- IMPORTANT: Review this SQL before executing
-- Backup your database first: mysqldump -u user -p database > backup.sql
-- ============================================

-- Start transaction
START TRANSACTION;

-- ============================================
-- Step 1: Add Device Tracking Columns
-- ============================================

ALTER TABLE users
  -- Device 1 (first registered device)
  ADD COLUMN device1_ip VARCHAR(45) NULL 
    COMMENT 'IP address of first registered device',
  
  ADD COLUMN device1_fingerprint VARCHAR(255) NULL 
    COMMENT 'Device fingerprint hash (User-Agent based)',
  
  ADD COLUMN device1_last_seen TIMESTAMP NULL 
    COMMENT 'Last activity timestamp for device 1',
  
  -- Device 2 (second registered device)
  ADD COLUMN device2_ip VARCHAR(45) NULL 
    COMMENT 'IP address of second registered device',
  
  ADD COLUMN device2_fingerprint VARCHAR(255) NULL 
    COMMENT 'Device fingerprint hash (User-Agent based)',
  
  ADD COLUMN device2_last_seen TIMESTAMP NULL 
    COMMENT 'Last activity timestamp for device 2',
  
  -- Lock control
  ADD COLUMN device_locked BOOLEAN NOT NULL DEFAULT FALSE 
    COMMENT 'Enable device restriction (TRUE = locked, FALSE = disabled)',
  
  -- Token versioning for invalidation
  ADD COLUMN token_version INT NOT NULL DEFAULT 1 
    COMMENT 'JWT version number - incremented on device reset';

-- ============================================
-- Step 2: Create Performance Indexes
-- ============================================

-- Index for token version lookups (used in middleware)
CREATE INDEX idx_token_version ON users(token_version);

-- Index for device lock status filtering
CREATE INDEX idx_device_locked ON users(device_locked);

-- Composite index for admin queries
CREATE INDEX idx_device_status ON users(device_locked, token_version);

-- ============================================
-- Step 3: Ensure Phone Uniqueness (if not exists)
-- ============================================

-- Check if index exists, if not create it
-- Note: This may fail if index already exists - that's OK
ALTER TABLE users 
  ADD UNIQUE INDEX idx_phone_unique (phone);

-- ============================================
-- Step 4: Set Initial Values for Existing Users
-- ============================================

-- Set device_locked to FALSE for all existing users (graceful rollout)
-- This prevents immediate lockouts after migration
UPDATE users 
SET device_locked = FALSE,
    token_version = 1
WHERE device_locked IS NULL OR token_version IS NULL;

-- ============================================
-- Step 5: Verify Migration
-- ============================================

-- Show new columns
SELECT 
  COLUMN_NAME,
  COLUMN_TYPE,
  IS_NULLABLE,
  COLUMN_DEFAULT,
  COLUMN_COMMENT
FROM INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'users' 
  AND COLUMN_NAME IN (
    'device1_ip', 'device1_fingerprint', 'device1_last_seen',
    'device2_ip', 'device2_fingerprint', 'device2_last_seen',
    'device_locked', 'token_version'
  )
ORDER BY ORDINAL_POSITION;

-- Show indexes
SHOW INDEX FROM users WHERE Key_name LIKE 'idx_%';

-- Show sample data (verify existing users have NULL devices)
SELECT 
  id,
  email,
  device1_ip,
  device2_ip,
  device_locked,
  token_version
FROM users 
LIMIT 5;

-- Commit transaction
COMMIT;

-- ============================================
-- Rollback Instructions (if needed)
-- ============================================
-- If something goes wrong, run this to rollback:
-- 
-- START TRANSACTION;
-- 
-- ALTER TABLE users
--   DROP COLUMN device1_ip,
--   DROP COLUMN device1_fingerprint,
--   DROP COLUMN device1_last_seen,
--   DROP COLUMN device2_ip,
--   DROP COLUMN device2_fingerprint,
--   DROP COLUMN device2_last_seen,
--   DROP COLUMN device_locked,
--   DROP COLUMN token_version;
-- 
-- DROP INDEX idx_token_version ON users;
-- DROP INDEX idx_device_locked ON users;
-- DROP INDEX idx_device_status ON users;
-- 
-- COMMIT;
-- ============================================
