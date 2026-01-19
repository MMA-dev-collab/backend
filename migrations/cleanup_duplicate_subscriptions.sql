-- Cleanup script for duplicate cancelled subscriptions
-- This script removes duplicate cancelled subscriptions and keeps only the active one

-- Step 1: Find users with multiple subscriptions
SELECT userId, COUNT(*) as subscription_count
FROM subscriptions
GROUP BY userId
HAVING COUNT(*) > 1;

-- Step 2: For each user with duplicates, keep only the active subscription
-- Delete cancelled subscriptions if there's an active one
DELETE s1 FROM subscriptions s1
INNER JOIN subscriptions s2 ON s1.userId = s2.userId
WHERE s1.status = 'cancelled' 
  AND s2.status = 'active'
  AND s1.id < s2.id;

-- Step 3: Verify cleanup
SELECT userId, COUNT(*) as subscription_count, GROUP_CONCAT(status) as statuses
FROM subscriptions
GROUP BY userId
HAVING COUNT(*) > 1;

-- If there are still duplicates (multiple active or multiple cancelled), 
-- you may need to manually review them
