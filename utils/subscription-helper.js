/**
 * Subscription Helper Utilities
 * Provides functions for subscription management and access control
 */

/**
 * Calculate subscription end date based on flexible duration
 * @param {Date|string} startDate - Subscription start date
 * @param {number} durationValue - Numeric duration value
 * @param {string} durationUnit - Duration unit ('hour', 'day', 'year')
 * @returns {Date} Calculated end date
 */
function calculateEndDate(startDate, durationValue, durationUnit) {
    const start = new Date(startDate);
    const end = new Date(start);

    switch (durationUnit) {
        case 'hour':
            end.setHours(end.getHours() + durationValue);
            break;
        case 'day':
            end.setDate(end.getDate() + durationValue);
            break;
        case 'year':
            end.setFullYear(end.getFullYear() + durationValue);
            break;
        default:
            throw new Error(`Invalid duration unit: ${durationUnit}`);
    }

    return end;
}

/**
 * Convert flexible duration to days (for backward compatibility)
 * @param {number} durationValue - Numeric duration value
 * @param {string} durationUnit - Duration unit ('hour', 'day', 'year')
 * @returns {number} Duration in days
 */
function convertToDays(durationValue, durationUnit) {
    switch (durationUnit) {
        case 'hour':
            return Math.ceil(durationValue / 24);
        case 'day':
            return durationValue;
        case 'year':
            return durationValue * 365;
        default:
            throw new Error(`Invalid duration unit: ${durationUnit}`);
    }
}

/**
 * Get user's current membership from active subscription
 * @param {object} pool - Database connection pool
 * @param {number} userId - User ID
 * @returns {Promise<object>} Membership info { type, expiresAt, planId, planRole }
 */
async function getUserMembership(pool, userId) {
    try {
        const [rows] = await pool.query(
            `SELECT 
        COALESCE(sp.name, 'Free') AS membershipType,
        s.endDate AS membershipExpiresAt,
        sp.id AS activePlanId,
        sp.role AS planRole
      FROM users u
      LEFT JOIN subscriptions s ON u.id = s.userId 
        AND s.status = 'active' 
        AND (s.endDate >= CURDATE() OR s.endDate >= DATE_SUB(NOW(), INTERVAL 24 HOUR))
      LEFT JOIN subscription_plans sp ON s.planId = sp.id
      WHERE u.id = ?
      ORDER BY sp.price DESC, s.endDate DESC
      LIMIT 1`,
            [userId]
        );

        // DEBUG: Log membership lookup
        if (rows.length > 0 && rows[0].activePlanId) {
            console.log(`[SubscriptionHelper] User ${userId} has active plan: ${rows[0].membershipType} (Role: ${rows[0].planRole}) expires ${rows[0].membershipExpiresAt}`);
        } else {
            // console.log(`[SubscriptionHelper] User ${userId} has no active plan`);
        }

        if (rows.length === 0) {
            return {
                membershipType: 'Normal', // Default to Normal
                membershipExpiresAt: null,
                activePlanId: null,
                planRole: 'normal'
            };
        }

        return {
            membershipType: rows[0].membershipType || 'Free',
            membershipExpiresAt: rows[0].membershipExpiresAt,
            activePlanId: rows[0].activePlanId,
            planRole: rows[0].planRole
        };
    } catch (err) {
        console.error('Error getting user membership:', err);
        return {
            membershipType: 'Normal',
            membershipExpiresAt: null,
            activePlanId: null,
            planRole: 'normal'
        };
    }
}

/**
 * Check if user can access a specific case
 * @param {object} pool - Database connection pool
 * @param {number} userId - User ID
 * @param {number} caseId - Case ID
 * @returns {Promise<object>} Access info { hasAccess, reason, requiredPlan }
 */
async function checkCaseAccess(pool, userId, caseId) {
    try {
        // Get case required plan
        const [caseRows] = await pool.query(
            `SELECT c.id, c.title, c.requiredPlanId, sp.name AS requiredPlanName, sp.role AS requiredPlanRole
       FROM cases c
       LEFT JOIN subscription_plans sp ON c.requiredPlanId = sp.id
       WHERE c.id = ?`,
            [caseId]
        );

        if (caseRows.length === 0) {
            return { hasAccess: false, reason: 'Case not found', requiredPlan: null };
        }

        const caseData = caseRows[0];

        // If no required plan, case is free for all
        if (!caseData.requiredPlanId) {
            return { hasAccess: true, reason: 'Free access', requiredPlan: null };
        }

        // Get user's current membership
        const membership = await getUserMembership(pool, userId);

        // Default to Normal access if no active plan
        const hasActivePlan = !!membership.activePlanId;
        const userPlanRole = hasActivePlan ? membership.planRole : 'normal';

        // Check if user's plan matches or exceeds required plan
        const planHierarchy = getPlanHierarchy();
        const userPlanLevel = planHierarchy[userPlanRole] || 1; // Default to Normal (1)
        const requiredPlanLevel = planHierarchy[caseData.requiredPlanRole] || 1;

        if (userPlanLevel >= requiredPlanLevel) {
            return { hasAccess: true, reason: 'Plan access granted', requiredPlan: null };
        }

        return {
            hasAccess: false,
            reason: 'Insufficient plan level',
            requiredPlan: caseData.requiredPlanName
        };



    } catch (err) {
        console.error('Error checking case access:', err);
        return { hasAccess: false, reason: 'Error checking access', requiredPlan: null };
    }
}

/**
 * Get plan hierarchy for access comparison
 * Higher number = higher access level
 * @returns {object} Plan hierarchy mapping
 */
function getPlanHierarchy() {
    return {
        'normal': 1,
        'premium': 2,
        'ultra': 3,
        'custom': 1 // Default custom plans to normal level
    };
}

/**
 * Format duration for display
 * @param {number} durationValue - Numeric duration value
 * @param {string} durationUnit - Duration unit ('hour', 'day', 'year')
 * @returns {string} Formatted duration string
 */
function formatDuration(durationValue, durationUnit) {
    const pluralize = (value, unit) => {
        return `${value} ${unit}${value !== 1 ? 's' : ''}`;
    };

    switch (durationUnit) {
        case 'hour':
            return pluralize(durationValue, 'Hour');
        case 'day':
            return pluralize(durationValue, 'Day');
        case 'year':
            return pluralize(durationValue, 'Year');
        default:
            return `${durationValue} ${durationUnit}`;
    }
}

module.exports = {
    calculateEndDate,
    convertToDays,
    getUserMembership,
    checkCaseAccess,
    getPlanHierarchy,
    formatDuration
};
