-- Insert default subscription plans (Normal and Premium)
-- This script works with the basic subscription_plans table structure

-- Insert Normal plan (Free plan)
INSERT INTO subscription_plans (name, price, durationDays, maxFreeCases, isActive)
VALUES ('Normal', 0.00, 365, 3, 1)
ON DUPLICATE KEY UPDATE 
  price = VALUES(price),
  durationDays = VALUES(durationDays),
  maxFreeCases = VALUES(maxFreeCases),
  isActive = VALUES(isActive);

-- Insert Premium plan
INSERT INTO subscription_plans (name, price, durationDays, maxFreeCases, isActive)
VALUES ('Premium', 9.99, 30, 999999, 1)
ON DUPLICATE KEY UPDATE 
  price = VALUES(price),
  durationDays = VALUES(durationDays),
  maxFreeCases = VALUES(maxFreeCases),
  isActive = VALUES(isActive);

-- Verify plans were created
SELECT 'Plans created successfully' AS status;
SELECT id, name, price, durationDays, maxFreeCases, isActive FROM subscription_plans;
