# Complete Access Control Refactor - Implementation Guide

## 🎯 Goal
Remove ALL legacy access control fields (`isFree`, `isPremiumOnly`, `accessLevel`) and replace with clean plan-based system using `accessType` and `case_allowed_plans` table.

## 📋 Migration Steps

### Step 1: Run Database Migration
```bash
# Run the migration to create new schema
mysql -u [user] -p [database] < backend/migrations/005_refactor_case_access_control.sql
```

### Step 2: Refactor `canUserAccessCase` Function

**Location:** `backend/server.js` lines 146-238

**Replace with:**
```javascript
/**
 * Check if user can access a case based on subscription
 * SINGLE SOURCE OF TRUTH for case access control
 * 
 * Logic:
 * 1. If accessType === 'free' → allow access to everyone
 * 2. If accessType === 'plans' → check if user's active subscription planId 
 *    exists in case_allowed_plans for this case
 * 3. For free cases, also check subscription limits (maxFreeCases)
 */
async function canUserAccessCase(userId, caseId) {
  if (!pool) return { canAccess: false, reason: 'Database unavailable' };
  
  try {
    // Get case access type
    const [caseRows] = await pool.query(`
      SELECT accessType 
      FROM cases 
      WHERE id = ?
    `, [caseId]);
    
    if (!caseRows.length) {
      return { canAccess: false, reason: 'Case not found' };
    }
    
    const caseData = caseRows[0];
    const accessType = caseData.accessType || 'free'; // Default to 'free' if NULL
    
    // Step 1: Free cases - accessible to everyone
    if (accessType === 'free') {
      // Still check subscription limits for free cases
      const subscription = await getUserSubscription(userId);
      
      // Get user's completed cases count
      const [progressRows] = await pool.query(`
        SELECT COUNT(DISTINCT caseId) as casesUsed
        FROM progress
        WHERE userId = ? AND isCompleted = 1
      `, [userId]);
      
      const casesUsed = progressRows[0]?.casesUsed || 0;
      
      if (!subscription) {
        // No subscription - default free limit (3 cases)
        const defaultFreeLimit = 3;
        if (casesUsed >= defaultFreeLimit) {
          return { 
            canAccess: false, 
            reason: 'Free case limit reached. Upgrade to Premium for unlimited access.',
            freeCasesUsed: casesUsed,
            freeCasesLimit: defaultFreeLimit
          };
        }
        return { canAccess: true, freeCasesUsed: casesUsed, freeCasesLimit: defaultFreeLimit };
      }
      
      // Check if user has unlimited access (maxFreeCases is NULL)
      if (subscription.maxFreeCases === null) {
        return { canAccess: true, freeCasesUsed: casesUsed, freeCasesLimit: 'unlimited' };
      }
      
      // Normal or custom plan with limited cases
      if (casesUsed >= subscription.maxFreeCases) {
        return { 
          canAccess: false, 
          reason: `Free case limit reached (${subscription.maxFreeCases} cases). Upgrade to Premium for unlimited access.`,
          freeCasesUsed: casesUsed,
          freeCasesLimit: subscription.maxFreeCases
        };
      }
      
      return { 
        canAccess: true, 
        freeCasesUsed: casesUsed, 
        freeCasesLimit: subscription.maxFreeCases 
      };
    }
    
    // Step 2: Plan-based cases - check if user's plan is in allowed plans
    if (accessType === 'plans') {
      // Get user's active subscription
      const subscription = await getUserSubscription(userId);
      
      if (!subscription) {
        return { 
          canAccess: false, 
          reason: 'Active subscription required to access this case',
          requiresSubscription: true
        };
      }
      
      // Check if (caseId, planId) exists in case_allowed_plans
      const [allowedRows] = await pool.query(`
        SELECT id 
        FROM case_allowed_plans 
        WHERE caseId = ? AND planId = ?
        LIMIT 1
      `, [caseId, subscription.planId]);
      
      if (!allowedRows.length) {
        return { 
          canAccess: false, 
          reason: 'Your subscription plan does not have access to this case',
          requiresSubscription: true
        };
      }
      
      // Access granted
      return { canAccess: true };
    }
    
    // Default: deny access (safety fallback)
    return { canAccess: false, reason: 'Unknown access type' };
  } catch (err) {
    console.error('Error checking case access:', err);
    return { canAccess: false, reason: 'Error checking access' };
  }
}
```

### Step 3: Update GET /api/cases Endpoint

**Location:** `backend/server.js` around line 762

**Remove these lines from the response mapping:**
```javascript
isFree: !!row.isFree,
isPremiumOnly: !!row.isPremiumOnly,
accessLevel: row.accessLevel || 'all'
```

**Replace with:**
```javascript
accessType: row.accessType || 'free'
```

### Step 4: Create PUT /api/admin/cases/:id/access Endpoint

**Add this new endpoint** (after existing admin case endpoints):

```javascript
// Admin: Update case access control (plan-based)
app.put('/api/admin/cases/:id/access', authMiddleware('admin'), async (req, res) => {
  try {
    const { id } = req.params;
    const { accessType, planIds } = req.body;
    
    if (!accessType || !['free', 'plans'].includes(accessType)) {
      return res.status(400).json({ message: 'accessType must be "free" or "plans"' });
    }
    
    if (accessType === 'plans' && (!planIds || !Array.isArray(planIds) || planIds.length === 0)) {
      return res.status(400).json({ message: 'planIds array is required when accessType is "plans"' });
    }
    
    // Check if case exists
    const [caseRows] = await pool.query(`SELECT id FROM cases WHERE id = ?`, [id]);
    if (!caseRows.length) {
      return res.status(404).json({ message: 'Case not found' });
    }
    
    // Update case accessType
    await pool.query(`
      UPDATE cases 
      SET accessType = ?
      WHERE id = ?
    `, [accessType, id]);
    
    // Remove all existing plan assignments
    await pool.query(`DELETE FROM case_allowed_plans WHERE caseId = ?`, [id]);
    
    // Add new plan assignments if accessType is 'plans'
    if (accessType === 'plans') {
      // Validate planIds exist
      const placeholders = planIds.map(() => '?').join(',');
      const [validPlans] = await pool.query(`
        SELECT id FROM subscription_plans WHERE id IN (${placeholders}) AND isActive = 1
      `, planIds);
      
      if (validPlans.length !== planIds.length) {
        return res.status(400).json({ message: 'One or more planIds are invalid or inactive' });
      }
      
      // Insert plan assignments
      for (const planId of planIds) {
        await pool.query(`
          INSERT INTO case_allowed_plans (caseId, planId)
          VALUES (?, ?)
          ON DUPLICATE KEY UPDATE caseId = caseId
        `, [id, planId]);
      }
    }
    
    // Get updated case with plan assignments
    const [updatedCase] = await pool.query(`SELECT * FROM cases WHERE id = ?`, [id]);
    const [planAssignments] = await pool.query(`
      SELECT cap.planId, sp.name as planName, sp.role as planRole
      FROM case_allowed_plans cap
      JOIN subscription_plans sp ON cap.planId = sp.id
      WHERE cap.caseId = ?
    `, [id]);
    
    res.json({
      message: 'Case access updated successfully',
      case: {
        id: updatedCase[0].id,
        accessType: updatedCase[0].accessType,
        allowedPlans: planAssignments
      }
    });
  } catch (err) {
    console.error('Error updating case access:', err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});
```

### Step 5: Update Admin Case Endpoints

**Location:** `backend/server.js` around line 1067 (GET /api/admin/cases)

**Remove:**
```javascript
isFree: row.isFree !== undefined ? !!row.isFree : true,
isPremiumOnly: row.isPremiumOnly !== undefined ? !!row.isPremiumOnly : false,
accessLevel: row.accessLevel || 'free',
```

**Replace with:**
```javascript
accessType: row.accessType || 'free',
```

**Also add plan assignments:**
```javascript
// Get plan assignments for each case
const [planAssignments] = await pool.query(`
  SELECT cap.caseId, cap.planId, sp.name as planName, sp.role as planRole
  FROM case_allowed_plans cap
  JOIN subscription_plans sp ON cap.planId = sp.id
`);
const planMap = {};
planAssignments.forEach(pa => {
  if (!planMap[pa.caseId]) planMap[pa.caseId] = [];
  planMap[pa.caseId].push({ id: pa.planId, name: pa.planName, role: pa.planRole });
});

// Then in the cases map:
allowedPlans: planMap[row.id] || []
```

### Step 6: Update Case Creation Endpoint

**Location:** `backend/server.js` around line 1126 (POST /api/admin/cases)

**Remove from INSERT and response:**
- `isFree`
- `isPremiumOnly`
- `accessLevel`

**Add:**
- `accessType` (default 'free')

### Step 7: Update Case Update Endpoint

**Location:** `backend/server.js` around line 1174 (PUT /api/admin/cases/:id)

**Remove all the sync logic for isFree/isPremiumOnly/accessLevel**

**Replace with simple accessType handling:**
```javascript
app.put('/api/admin/cases/:id', authMiddleware('admin'), async (req, res) => {
  const { id } = req.params;
  let { title, specialty, category, categoryId, difficulty, isLocked, prerequisiteCaseId, metadata, thumbnailUrl, duration, accessType } = req.body;
  
  try {
    const [currentRows] = await pool.query(`SELECT * FROM cases WHERE id = ?`, [id]);
    if (!currentRows.length) {
      return res.status(404).json({ message: 'Case not found' });
    }
    
    const current = currentRows[0];
    
    // Use current values if not provided
    title = title || current.title;
    specialty = specialty !== undefined ? specialty : current.specialty;
    category = category !== undefined ? category : current.category;
    categoryId = categoryId !== undefined ? categoryId : current.categoryId;
    difficulty = difficulty !== undefined ? difficulty : current.difficulty;
    isLocked = isLocked !== undefined ? (isLocked ? 1 : 0) : (current.isLocked ? 1 : 0);
    prerequisiteCaseId = prerequisiteCaseId !== undefined ? prerequisiteCaseId : current.prerequisiteCaseId;
    metadata = metadata !== undefined ? (metadata ? JSON.stringify(metadata) : null) : current.metadata;
    thumbnailUrl = thumbnailUrl !== undefined ? thumbnailUrl : current.thumbnailUrl;
    duration = duration !== undefined ? duration : (current.duration || 10);
    accessType = accessType || current.accessType || 'free';
    
    await pool.query(`
      UPDATE cases
      SET title = ?, specialty = ?, category = ?, categoryId = ?, difficulty = ?, isLocked = ?, prerequisiteCaseId = ?, metadata = ?, thumbnailUrl = ?, duration = ?, accessType = ?
      WHERE id = ?
    `, [
      title,
      specialty || null,
      category || null,
      categoryId || null,
      difficulty || null,
      isLocked,
      prerequisiteCaseId || null,
      metadata || null,
      thumbnailUrl || null,
      duration,
      accessType,
      id,
    ]);
    
    const [updatedRows] = await pool.query(`SELECT * FROM cases WHERE id = ?`, [id]);
    const updated = updatedRows[0];
    
    res.json({ 
      message: 'Updated',
      case: {
        id: updated.id,
        title: updated.title,
        accessType: updated.accessType
      }
    });
  } catch (err) {
    console.error('Case update error:', err);
    res.status(500).json({ message: 'Database error', error: err.message });
  }
});
```

## ✅ Checklist

- [ ] Run migration 005_refactor_case_access_control.sql
- [ ] Replace `canUserAccessCase` function
- [ ] Update GET /api/cases to remove old fields
- [ ] Create PUT /api/admin/cases/:id/access endpoint
- [ ] Update GET /api/admin/cases to use accessType
- [ ] Update POST /api/admin/cases to use accessType
- [ ] Update PUT /api/admin/cases/:id to remove old field sync logic
- [ ] Test case access with different subscription plans
- [ ] Verify plan assignments work correctly

## 🧹 Cleanup

After refactor is complete and tested:

1. **Drop old columns** (uncomment in migration):
   ```sql
   ALTER TABLE cases DROP COLUMN isFree;
   ALTER TABLE cases DROP COLUMN isPremiumOnly;
   ALTER TABLE cases DROP COLUMN accessLevel;
   ```

2. **Remove indexes** (if they exist):
   ```sql
   DROP INDEX idx_accessLevel ON cases;
   DROP INDEX idx_isFree ON cases;
   DROP INDEX idx_isPremiumOnly ON cases;
   ```
