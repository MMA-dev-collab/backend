-- =====================================================
-- Flexible Duration and Case Access Control Migration
-- Adds flexible duration fields and plan-based case access
-- =====================================================

-- Step 1: Add flexible duration fields to subscription_plans
ALTER TABLE subscription_plans 
  ADD COLUMN duration_value INT NOT NULL DEFAULT 30 COMMENT 'Numeric duration value',
  ADD COLUMN duration_unit ENUM('hour', 'day', 'year') NOT NULL DEFAULT 'day' COMMENT 'Duration unit (hour, day, year)';

-- Step 2: Migrate existing durationDays to new format
UPDATE subscription_plans 
SET 
  duration_value = durationDays,
  duration_unit = 'day'
WHERE duration_value = 30; -- Only update if still at default

-- Step 3: Add requiredPlanId to cases table for access control
ALTER TABLE cases 
  ADD COLUMN requiredPlanId INT NULL COMMENT 'Required subscription plan ID for access (NULL = free for all)',
  ADD CONSTRAINT fk_cases_required_plan 
    FOREIGN KEY (requiredPlanId) REFERENCES subscription_plans(id) ON DELETE SET NULL;

-- Add index for performance
CREATE INDEX idx_cases_required_plan ON cases(requiredPlanId);

-- Step 4: Migrate existing access control data
-- Cases that were premium-only should require Premium plan
UPDATE cases c
SET c.requiredPlanId = (
  SELECT id FROM subscription_plans WHERE role = 'premium' LIMIT 1
)
WHERE (c.isPremiumOnly = 1 OR c.accessLevel = 'premium' OR c.accessType = 'plans')
  AND c.requiredPlanId IS NULL;

-- Step 5: Add helper view for user membership derivation
CREATE OR REPLACE VIEW user_current_membership AS
SELECT 
  u.id AS userId,
  u.email,
  u.name,
  COALESCE(sp.name, 'Free') AS membershipType,
  s.endDate AS membershipExpiresAt,
  sp.id AS activePlanId,
  sp.role AS planRole,
  CASE 
    WHEN s.endDate IS NULL THEN 'Free'
    WHEN s.endDate < CURDATE() THEN 'Free'
    WHEN s.status != 'active' THEN 'Free'
    ELSE sp.name
  END AS effectiveMembership
FROM users u
LEFT JOIN subscriptions s ON u.id = s.userId AND s.status = 'active' AND s.endDate >= CURDATE()
LEFT JOIN subscription_plans sp ON s.planId = sp.id
WHERE u.role = 'student'
ORDER BY sp.price DESC, s.endDate DESC;

-- Step 6: Verify migration
SELECT 
  'Migration completed' AS status,
  (SELECT COUNT(*) FROM subscription_plans WHERE duration_value IS NOT NULL) AS plans_with_flexible_duration,
  (SELECT COUNT(*) FROM cases WHERE requiredPlanId IS NOT NULL) AS cases_with_required_plan,
  (SELECT COUNT(*) FROM user_current_membership) AS users_with_membership;

-- Step 7: Display sample data
SELECT 'Subscription Plans with Flexible Duration' AS info;
SELECT id, name, duration_value, duration_unit, durationDays, role FROM subscription_plans LIMIT 5;

SELECT 'Cases with Required Plans' AS info;
SELECT c.id, c.title, c.requiredPlanId, sp.name AS requiredPlanName 
FROM cases c 
LEFT JOIN subscription_plans sp ON c.requiredPlanId = sp.id 
LIMIT 5;

SELECT 'User Membership Derivation' AS info;
SELECT userId, email, membershipType, effectiveMembership, membershipExpiresAt 
FROM user_current_membership 
LIMIT 5;
