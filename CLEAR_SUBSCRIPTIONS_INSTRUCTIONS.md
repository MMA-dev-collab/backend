# Clear All Subscriptions - Instructions

## Option 1: Using MySQL Command Line

Open your MySQL command line or phpMyAdmin and run these commands:

```sql
-- Clear all subscription data
DELETE FROM subscription_history;
DELETE FROM subscriptions;

-- Reset auto-increment IDs
ALTER TABLE subscriptions AUTO_INCREMENT = 1;
ALTER TABLE subscription_history AUTO_INCREMENT = 1;

-- Verify cleanup
SELECT COUNT(*) as total_subscriptions FROM subscriptions;
SELECT COUNT(*) as total_history FROM subscription_history;
```

## Option 2: Using the Admin Dashboard

1. Go to Admin Dashboard > Subscriptions
2. The table should now be empty
3. You can start creating fresh subscriptions

## What This Does:

- ✅ Deletes ALL subscription records
- ✅ Deletes ALL subscription history
- ✅ Resets ID counters to start from 1
- ✅ Keeps subscription plans (Normal, Premium, Ultra, etc.)
- ✅ Keeps user accounts

## After Clearing:

Your subscription management table will be completely empty and ready for fresh subscriptions. All users will show as "Free" membership until you assign them new subscriptions.
