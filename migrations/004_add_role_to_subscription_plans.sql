-- =====================================================
-- Add role column to subscription_plans table
-- This migration refactors the subscription system to use role-based access
-- =====================================================

-- Add role column
ALTER TABLE subscription_plans 
  ADD COLUMN role ENUM('normal', 'premium', 'custom') NOT NULL DEFAULT 'custom' 
  AFTER name;

-- Update existing plans based on name
UPDATE subscription_plans SET role = 'normal' WHERE name = 'Normal';
UPDATE subscription_plans SET role = 'premium' WHERE name = 'Premium';

-- Make role NOT NULL (remove default after setting values)
ALTER TABLE subscription_plans 
  MODIFY COLUMN role ENUM('normal', 'premium', 'custom') NOT NULL;

-- Change maxFreeCases to allow NULL for unlimited access
ALTER TABLE subscription_plans 
  MODIFY COLUMN maxFreeCases INT NULL 
  COMMENT 'NULL means unlimited access';

-- Update Premium plan to have NULL maxFreeCases (unlimited)
UPDATE subscription_plans 
  SET maxFreeCases = NULL 
  WHERE role = 'premium';

-- Add index on role for faster queries
CREATE INDEX idx_role ON subscription_plans(role);

-- Verify the changes
SELECT id, name, role, price, durationDays, maxFreeCases, isActive 
FROM subscription_plans 
ORDER BY role, name;
