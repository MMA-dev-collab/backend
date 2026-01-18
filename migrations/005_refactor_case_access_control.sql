-- =====================================================
-- Refactor Case Access Control System
-- Moves from legacy boolean flags to plan-based access control
-- =====================================================

-- Step 1: Add new accessType column to cases table
ALTER TABLE cases 
  ADD COLUMN accessType ENUM('free', 'plans') DEFAULT 'free' 
  COMMENT 'free = accessible to all, plans = requires specific subscription plans'
  AFTER categoryId;

-- Step 2: Create case_allowed_plans junction table
CREATE TABLE IF NOT EXISTS case_allowed_plans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  caseId INT NOT NULL,
  planId INT NOT NULL,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (caseId) REFERENCES cases(id) ON DELETE CASCADE,
  FOREIGN KEY (planId) REFERENCES subscription_plans(id) ON DELETE CASCADE,
  UNIQUE KEY unique_case_plan (caseId, planId),
  INDEX idx_caseId (caseId),
  INDEX idx_planId (planId)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Step 3: Migrate existing data
-- Cases that were free or 'all' -> accessType = 'free'
UPDATE cases 
SET accessType = 'free'
WHERE (isFree = 1 OR accessLevel = 'free' OR accessLevel = 'all')
  AND accessType IS NULL;

-- Cases that were premium-only -> accessType = 'plans' + assign to premium plan
UPDATE cases 
SET accessType = 'plans'
WHERE (isPremiumOnly = 1 OR accessLevel = 'premium')
  AND accessType IS NULL;

-- Insert premium plan access for premium-only cases
INSERT INTO case_allowed_plans (caseId, planId)
SELECT 
  c.id,
  sp.id
FROM cases c
CROSS JOIN subscription_plans sp
WHERE c.accessType = 'plans'
  AND sp.role = 'premium'
  AND NOT EXISTS (
    SELECT 1 FROM case_allowed_plans cap 
    WHERE cap.caseId = c.id AND cap.planId = sp.id
  );

-- Step 4: Remove old columns (drop them)
-- WARNING: This permanently removes the old columns
-- Comment out if you want to keep them for backward compatibility during migration
-- ALTER TABLE cases DROP COLUMN isFree;
-- ALTER TABLE cases DROP COLUMN isPremiumOnly;
-- ALTER TABLE cases DROP COLUMN accessLevel;

-- Step 5: Verify migration
SELECT 
  'Migration completed' AS status,
  COUNT(*) AS total_cases,
  SUM(CASE WHEN accessType = 'free' THEN 1 ELSE 0 END) AS free_cases,
  SUM(CASE WHEN accessType = 'plans' THEN 1 ELSE 0 END) AS plan_based_cases
FROM cases;

SELECT 
  'Case-plan assignments' AS info,
  COUNT(*) AS total_assignments,
  COUNT(DISTINCT caseId) AS cases_with_plans,
  COUNT(DISTINCT planId) AS unique_plans_used
FROM case_allowed_plans;
