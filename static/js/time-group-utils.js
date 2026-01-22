// Time Group Utilities for ACL, ABF, and Policer
const TimeGroupUtils = {
    // Load time groups and populate a select element
    loadTimeGroupsIntoSelect: function(selectElementId) {
        fetch('/api/time-groups')
            .then(r => r.json())
            .then(data => {
                const select = document.getElementById(selectElementId);
                if (!select) return;

                // Keep the first option (no time group)
                const firstOption = select.querySelector('option');
                select.innerHTML = '';
                
                if (firstOption) {
                    select.appendChild(firstOption);
                }

                // Add time groups
                if (data && Array.isArray(data)) {
                    data.forEach(tg => {
                        const option = document.createElement('option');
                        option.value = tg.id;
                        option.textContent = `${tg.name} (${tg.start_time} - ${tg.end_time})`;
                        select.appendChild(option);
                    });
                }
            })
            .catch(err => console.error('Error loading time groups:', err));
    },

    // Populate all time group selects on page
    initializeAllTimeGroupSelects: function() {
        // Find all selects with time group data
        const selects = document.querySelectorAll('[data-time-group-select]');
        selects.forEach(select => {
            this.loadTimeGroupsIntoSelect(select.id);
        });

        // Also load specific selects by ID pattern
        ['acl_time_group_id', 'abf_time_group_id', 'policer_time_group_id'].forEach(id => {
            const elem = document.getElementById(id);
            if (elem) {
                this.loadTimeGroupsIntoSelect(id);
            }
        });
    },

    // Assign a time group to a rule
    assignTimeGroupToRule: function(timeGroupId, ruleType, ruleId) {
        if (!timeGroupId) {
            console.log('No time group to assign');
            return Promise.resolve();
        }

        return fetch(`/api/time-groups/${timeGroupId}/assign`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rule_type: ruleType,
                rule_id: ruleId
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                console.error('Error assigning time group:', data.error);
                throw new Error(data.error);
            }
            return data;
        });
    },

    // Unassign a time group from a rule
    unassignTimeGroupFromRule: function(timeGroupId, ruleType, ruleId) {
        if (!timeGroupId) {
            return Promise.resolve();
        }

        return fetch(`/api/time-groups/${timeGroupId}/assign`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rule_type: ruleType,
                rule_id: ruleId
            })
        })
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                console.error('Error unassigning time group:', data.error);
                throw new Error(data.error);
            }
            return data;
        });
    },

    // Get time group status/active info for a rule
    getRuleStatus: function(ruleType, ruleId) {
        return fetch(`/api/time-groups/check-rule?rule_type=${ruleType}&rule_id=${ruleId}`)
            .then(r => r.json())
            .then(data => {
                return {
                    isActive: data.is_active,
                    message: data.message
                };
            })
            .catch(err => {
                console.error('Error checking rule status:', err);
                return {
                    isActive: true,
                    message: 'Vaqt cheklovi yo\'q'
                };
            });
    },

    // Get assigned time groups for a rule
    getRuleAssignments: function(ruleType, ruleId) {
        return fetch(`/api/time-groups/rule-assignments?rule_type=${ruleType}&rule_id=${ruleId}`)
            .then(r => r.json())
            .then(data => data || [])
            .catch(err => {
                console.error('Error getting rule assignments:', err);
                return [];
            });
    },

    // Display rule status in UI (badge)
    displayRuleStatus: function(containerId, ruleType, ruleId) {
        this.getRuleStatus(ruleType, ruleId).then(status => {
            const container = document.getElementById(containerId);
            if (!container) return;

            const badgeClass = status.isActive ? 'bg-success' : 'bg-warning';
            const badgeText = status.isActive ? '✅ Faol' : '⛔ O\'chirildi';
            
            container.innerHTML = `<span class="badge ${badgeClass}">${badgeText}</span> ${status.message}`;
        });
    }
};

// Initialize on document ready
document.addEventListener('DOMContentLoaded', () => {
    TimeGroupUtils.initializeAllTimeGroupSelects();
    
    // Refresh every 60 seconds for status updates
    setInterval(() => {
        TimeGroupUtils.initializeAllTimeGroupSelects();
    }, 60000);
});
