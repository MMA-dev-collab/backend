-- Clear all subscription data to start fresh
-- This will delete all subscriptions and subscription history

-- Step 1: Delete all subscription history records
DELETE FROM subscription_history;

-- Step 2: Delete all subscriptions
DELETE FROM subscriptions;

-- Step 3: Reset auto-increment IDs (optional, for clean start)
ALTER TABLE subscriptions AUTO_INCREMENT = 1;
ALTER TABLE subscription_history AUTO_INCREMENT = 1;

-- Step 4: Verify cleanup
SELECT 'Subscriptions cleared' as status;
SELECT COUNT(*) as remaining_subscriptions FROM subscriptions;
SELECT COUNT(*) as remaining_history FROM subscription_history;

-- Step 5: Show current subscription plans (these are kept)
SELECT 'Available Subscription Plans' as info;
SELECT id, name, price, durationDays FROM subscription_plans WHERE isActive = 1;
