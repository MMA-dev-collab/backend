-- =====================================================
-- Subscription Management System - Database Schema
-- =====================================================

-- 1. Create subscription_plans table
CREATE TABLE IF NOT EXISTS subscription_plans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(50) NOT NULL UNIQUE,
  price DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
  durationDays INT NOT NULL,
  maxFreeCases INT NOT NULL DEFAULT 0,
  description TEXT,
  features JSON,
  isActive BOOLEAN DEFAULT 1,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_name (name),
  INDEX idx_active (isActive)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Create subscriptions table
CREATE TABLE IF NOT EXISTS subscriptions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  userId INT NOT NULL,
  planId INT NOT NULL,
  status ENUM('active', 'expired', 'cancelled') DEFAULT 'active',
  startDate DATE NOT NULL,
  endDate DATE NOT NULL,
  autoRenew BOOLEAN DEFAULT 0,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (planId) REFERENCES subscription_plans(id) ON DELETE RESTRICT,
  INDEX idx_userId (userId),
  INDEX idx_status (status),
  INDEX idx_endDate (endDate),
  INDEX idx_userId_status (userId, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. Modify cases table - Add access control columns
-- Note: Run these ALTER statements manually if columns already exist, or wrap in try-catch in application code
ALTER TABLE cases 
  ADD COLUMN isFree BOOLEAN DEFAULT 1 COMMENT 'Available to all users including free tier',
  ADD COLUMN isPremiumOnly BOOLEAN DEFAULT 0 COMMENT 'Requires premium subscription',
  ADD COLUMN accessLevel ENUM('free', 'premium', 'all') DEFAULT 'free' COMMENT 'Simplified access control';

-- Add indexes
CREATE INDEX idx_accessLevel ON cases(accessLevel);
CREATE INDEX idx_isFree ON cases(isFree);
CREATE INDEX idx_isPremiumOnly ON cases(isPremiumOnly);

-- 4. Create subscription_history table for audit logging
CREATE TABLE IF NOT EXISTS subscription_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  subscriptionId INT NOT NULL,
  userId INT NOT NULL,
  action ENUM('created', 'extended', 'cancelled', 'expired', 'upgraded', 'downgraded') NOT NULL,
  oldPlanId INT,
  newPlanId INT,
  oldEndDate DATE,
  newEndDate DATE,
  performedBy INT COMMENT 'Admin user ID who performed the action',
  notes TEXT,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (subscriptionId) REFERENCES subscriptions(id) ON DELETE CASCADE,
  FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_subscriptionId (subscriptionId),
  INDEX idx_userId (userId),
  INDEX idx_action (action),
  INDEX idx_createdAt (createdAt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Insert default subscription plans
INSERT INTO subscription_plans (name, price, durationDays, maxFreeCases, description, features) VALUES
('Normal', 0.00, 365, 3, 'Free plan with limited access to cases', 
 JSON_ARRAY('Access to 3 free cases', 'Basic support', 'Community access')),
('Premium', 9.99, 30, 999999, 'Premium plan with unlimited access', 
 JSON_ARRAY('Unlimited case access', 'Priority support', 'Advanced analytics', 'Exclusive content', 'No advertisements'))
ON DUPLICATE KEY UPDATE 
  price = VALUES(price),
  durationDays = VALUES(durationDays),
  maxFreeCases = VALUES(maxFreeCases),
  description = VALUES(description),
  features = VALUES(features);

-- 6. Create default Normal subscriptions for existing users
-- This ensures all existing users have a Normal plan subscription
INSERT INTO subscriptions (userId, planId, status, startDate, endDate)
SELECT 
  u.id,
  (SELECT id FROM subscription_plans WHERE name = 'Normal' LIMIT 1),
  'active',
  CURDATE(),
  DATE_ADD(CURDATE(), INTERVAL 365 DAY)
FROM users u
WHERE u.role = 'student'
  AND NOT EXISTS (
    SELECT 1 FROM subscriptions s WHERE s.userId = u.id
  );

-- 7. Update existing cases to be "free" by default
UPDATE cases 
SET 
  isFree = 1,
  isPremiumOnly = 0,
  accessLevel = 'free'
WHERE isFree IS NULL OR isPremiumOnly IS NULL;

-- 8. Create view for active subscriptions with plan details
CREATE OR REPLACE VIEW active_user_subscriptions AS
SELECT 
  s.id AS subscriptionId,
  s.userId,
  u.email,
  u.name,
  s.planId,
  sp.name AS planName,
  sp.price,
  sp.maxFreeCases,
  s.status,
  s.startDate,
  s.endDate,
  DATEDIFF(s.endDate, CURDATE()) AS daysRemaining,
  CASE 
    WHEN s.endDate < CURDATE() THEN 'expired'
    WHEN DATEDIFF(s.endDate, CURDATE()) <= 7 THEN 'expiring_soon'
    ELSE 'active'
  END AS subscriptionHealth,
  s.createdAt,
  s.updatedAt
FROM subscriptions s
JOIN users u ON s.userId = u.id
JOIN subscription_plans sp ON s.planId = sp.id
WHERE s.status = 'active'
ORDER BY s.endDate ASC;

-- 9. Create stored procedure to check and expire subscriptions
DELIMITER $$

CREATE PROCEDURE IF NOT EXISTS expire_subscriptions()
BEGIN
  -- Update expired subscriptions
  UPDATE subscriptions
  SET status = 'expired'
  WHERE status = 'active' 
    AND endDate < CURDATE();
  
  -- Log expiration actions
  INSERT INTO subscription_history (subscriptionId, userId, action, oldPlanId, newPlanId, oldEndDate, newEndDate, notes)
  SELECT 
    s.id,
    s.userId,
    'expired',
    s.planId,
    (SELECT id FROM subscription_plans WHERE name = 'Normal' LIMIT 1),
    s.endDate,
    DATE_ADD(CURDATE(), INTERVAL 365 DAY),
    'Automatically expired and downgraded to Normal plan'
  FROM subscriptions s
  WHERE s.status = 'expired'
    AND NOT EXISTS (
      SELECT 1 FROM subscription_history sh 
      WHERE sh.subscriptionId = s.id 
        AND sh.action = 'expired' 
        AND DATE(sh.createdAt) = CURDATE()
    );
  
  -- Create new Normal subscriptions for users whose Premium expired
  INSERT INTO subscriptions (userId, planId, status, startDate, endDate)
  SELECT 
    s.userId,
    (SELECT id FROM subscription_plans WHERE name = 'Normal' LIMIT 1),
    'active',
    CURDATE(),
    DATE_ADD(CURDATE(), INTERVAL 365 DAY)
  FROM subscriptions s
  WHERE s.status = 'expired'
    AND s.planId != (SELECT id FROM subscription_plans WHERE name = 'Normal' LIMIT 1)
    AND NOT EXISTS (
      SELECT 1 FROM subscriptions s2 
      WHERE s2.userId = s.userId 
        AND s2.status = 'active'
    );
    
  SELECT ROW_COUNT() AS subscriptions_expired;
END$$

DELIMITER ;

-- 10. Verify installation
SELECT 'Subscription system tables created successfully' AS status;
SELECT COUNT(*) AS total_plans FROM subscription_plans;
SELECT COUNT(*) AS total_subscriptions FROM subscriptions;
SELECT COUNT(*) AS cases_with_access_control FROM cases WHERE accessLevel IS NOT NULL;
