-- Quick fix: Insert default subscription plans if they don't exist
-- Run this if the Plans tab shows no plans

-- Insert Normal plan
INSERT INTO subscription_plans (name, price, durationDays, maxFreeCases, description, features, isActive)
VALUES (
  'Normal',
  0.00,
  365,
  3,
  'Free plan with limited access to cases',
  JSON_ARRAY('Access to 3 free cases', 'Basic support', 'Community access'),
  1
)
ON DUPLICATE KEY UPDATE 
  price = VALUES(price),
  durationDays = VALUES(durationDays),
  maxFreeCases = VALUES(maxFreeCases),
  description = VALUES(description),
  features = VALUES(features),
  isActive = VALUES(isActive);

-- Insert Premium plan
INSERT INTO subscription_plans (name, price, durationDays, maxFreeCases, description, features, isActive)
VALUES (
  'Premium',
  9.99,
  30,
  999999,
  'Premium plan with unlimited access',
  JSON_ARRAY('Unlimited case access', 'Priority support', 'Advanced analytics', 'Exclusive content', 'No advertisements'),
  1
)
ON DUPLICATE KEY UPDATE 
  price = VALUES(price),
  durationDays = VALUES(durationDays),
  maxFreeCases = VALUES(maxFreeCases),
  description = VALUES(description),
  features = VALUES(features),
  isActive = VALUES(isActive);

-- Verify
SELECT 'Default plans inserted successfully' AS status;
SELECT * FROM subscription_plans;
