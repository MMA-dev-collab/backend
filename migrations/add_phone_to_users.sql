-- Add phone column to users table if it doesn't exist
-- Also add unique constraint for phone number

ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(20);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone);
