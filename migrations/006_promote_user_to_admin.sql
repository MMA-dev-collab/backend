-- =====================================================
-- Promote User to Admin Role
-- Run this to make a user an admin
-- =====================================================

-- Step 1: Check current user roles
SELECT id, email, role, name FROM users ORDER BY id;

-- Step 2: Update user to admin (REPLACE EMAIL WITH YOUR ACTUAL EMAIL)
-- Option A: Update by email
UPDATE users SET role = 'admin' WHERE email = 'your-email@example.com';

-- Option B: Update by ID (if you know the user ID)
-- UPDATE users SET role = 'admin' WHERE id = 1;

-- Step 3: Verify the update
SELECT id, email, role, name FROM users WHERE role = 'admin';

-- Step 4: Check all admin users
SELECT id, email, role, name, createdAt FROM users WHERE role = 'admin';

-- =====================================================
-- NOTES:
-- =====================================================
-- 1. After updating the role, the user MUST log out and log in again
--    to get a new JWT token with the admin role.
--
-- 2. Old JWT tokens will still have the old role (e.g., 'student')
--    and will not work for admin endpoints.
--
-- 3. The login endpoint already includes role in JWT (no code changes needed).
--
-- 4. If you see 404 instead of 403, check:
--    - Browser Network tab for actual HTTP status code
--    - Server logs for authMiddleware debug output
--    - Token payload (decode JWT to see role)
--
-- =====================================================
