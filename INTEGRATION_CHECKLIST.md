# Integration Checklist - Adding Time Groups to ACL/ABF/Policer

This document outlines the remaining work to fully integrate time groups with your existing rule types.

---

## Phase: ACL Time Group Integration

### Backend Changes

- [ ] **Update ACL Types** (`internal/vpp/acl/types.go`)
  - [ ] Add `TimeGroupID string` field to `ACLDetail` struct
  - [ ] Add `TimeGroupID string` field to `WebInput` struct (for API requests)
  - [ ] Documentation: "Empty string or 'always' means rule applies always"

- [ ] **Update ACL Manager** (`internal/vpp/acl/manager.go`)
  - [ ] No VPP API changes needed - time management is backend-only
  - [ ] Consider adding helper method: `GetACLTimeStatus()` for checking active rules

- [ ] **Update ACL Handler** (`internal/web/acl_handler.go`)
  ```go
  // In CreateACL handler:
  var req struct {
    // ... existing fields ...
    TimeGroupID string `json:"time_group_id"` // NEW
  }
  
  // If TimeGroupID provided, assign it:
  if req.TimeGroupID != "" {
    h.VPP.TimeGroupManager.AssignTimeGroupToRule(
      c.Request.Context(), 
      "ACL", 
      fmt.Sprintf("%d", aclIndex), 
      req.TimeGroupID,
    )
  }
  ```
  
  - [ ] Update CreateACL to accept and store time_group_id
  - [ ] Update UpdateACL to modify time_group_id
  - [ ] Update ListACLs to return time_group_id for each ACL
  - [ ] Update DeleteACL to unassign time group

### Frontend Changes

- [ ] **Update ACL Modal** (`templates/acl/acl_modals.html`)
  - [ ] Add dropdown field in Create ACL modal:
    ```html
    <div class="mb-3">
      <label class="form-label fw-bold">Vaqt Guruhi (ixtiyoriy)</label>
      <select id="acl_time_group" class="form-select shadow-sm">
        <option value="">Har doim faol (Time Group yo'q)</option>
        <!-- Populated from /api/time-groups -->
      </select>
    </div>
    ```
  
  - [ ] Load time groups on modal open:
    ```javascript
    // In your existing ACL_LIST or similar
    function loadTimeGroupsIntoACLModal() {
      fetch('/api/time-groups')
        .then(r => r.json())
        .then(groups => {
          const select = $('#acl_time_group');
          groups.forEach(g => {
            select.append(`<option value="${g.id}">${g.name}</option>`);
          });
        });
    }
    ```
  
  - [ ] Add time group info to ACL list display:
    - Show assigned time group name next to ACL
    - Display badge with time group status (Active/Inactive)

---

## Phase: ABF Time Group Integration

### Backend Changes

- [ ] **Update ABF Types** (likely in `internal/web/abf_handler.go` or create `internal/vpp/abf_mgr/types.go`)
  - [ ] Add `TimeGroupID string` field to policy structures
  - [ ] Document time-based behavior

- [ ] **Update ABF Handler** (`internal/web/abf_handler.go`)
  - [ ] Similar changes to ACL handler
  - [ ] Accept `time_group_id` in CreatePolicy request
  - [ ] Assign/unassign when creating/updating policies

### Frontend Changes

- [ ] **Update ABF Templates** (check which file handles ABF creation)
  - [ ] Add time group dropdown in ABF policy creation form
  - [ ] Display assigned time groups in policy list
  - [ ] Show time window status

---

## Phase: Policer Time Group Integration

### Backend Changes

- [ ] **Update Policer Manager** (`internal/vpp/policer/manger.go`)
  - [ ] Consider adding time group association structure
  - [ ] Add helper method for time-based policer status

- [ ] **Update Policer Handler** (`internal/web/policer_handler.go`)
  - [ ] Accept `time_group_id` in CreatePolicer request
  - [ ] Assign/unassign when managing policers
  - [ ] Update ListPolicers to include time group info

### Frontend Changes

- [ ] **Update Policer Templates** (locate policer creation form)
  - [ ] Add time group dropdown in Policer modal
  - [ ] Display time window status in policer list
  - [ ] Show which time group each policer is bound to

---

## Enable/Disable Logic on VPP

### Rule Scheduler Enhancement

- [ ] **Modify Rule Scheduler** (`internal/vpp/rule_scheduler.go`)
  
  - [ ] Update `checkACLRules()`:
    ```go
    if !isActive {
      // Disable ACL: call v.ACLManager.DisableACLOnInterface()
      // OR remove from interface bindings
    } else {
      // Enable ACL: re-add if not already present
    }
    ```
  
  - [ ] Update `checkPolicerRules()`:
    ```go
    if !isActive {
      // Call v.PolicerManager.RemovePolicerFromInterface()
    } else {
      // Re-apply policer if needed
    }
    ```
  
  - [ ] Update `checkABFRules()`:
    ```go
    if !isActive {
      // Detach ABF policy from interface
    } else {
      // Re-attach if not active
    }
    ```

- [ ] **Add VPP API Methods** (as needed):
  - [ ] `ACLManager.DisableACLOnInterface(ctx, swIfIndex, aclIndex)`
  - [ ] `PolicerManager.RemovePolicerFromInterface(ctx, policerName)`
  - [ ] `AbfManager.DetachFromInterface(ctx, policyID, swIfIndex)`

---

## Testing Checklist

### Unit Tests
- [ ] Time group creation with various time ranges
- [ ] Rule assignment/unassignment
- [ ] Status checking at different times
- [ ] Weekday matching logic

### Integration Tests
- [ ] Create ACL with time group
- [ ] Verify time group assignment
- [ ] Check status via API
- [ ] Backup and restore with time groups
- [ ] Scheduler periodic checks

### Manual Testing
- [ ] Create working_hours time group (9-17, M-F)
- [ ] Create ACL rule
- [ ] Assign working_hours to it
- [ ] Check scheduler logs
- [ ] Verify rules enable/disable at boundaries
- [ ] Test weekend behavior

---

## Files to Modify

### Backend
1. `internal/web/acl_handler.go` - ✅ Add time_group_id handling
2. `internal/web/abf_handler.go` - ✅ Add time_group_id handling
3. `internal/web/policer_handler.go` - ✅ Add time_group_id handling
4. `internal/vpp/rule_scheduler.go` - ✅ Implement enable/disable logic
5. `internal/vpp/acl/types.go` - ✅ Add TimeGroupID field
6. `internal/vpp/acl/manager.go` - ✅ Optional helper methods

### Frontend
1. `templates/acl/acl_modals.html` - ✅ Add time group dropdown
2. `templates/*/abf*.html` (find ABF template) - ✅ Add time group dropdown
3. `templates/*/policer*.html` (find Policer template) - ✅ Add time group dropdown
4. `static/js/*.js` (or inline scripts) - ✅ Update JavaScript to handle new field

---

## Example: What Rules Should Look Like After Integration

### API Request (Create ACL with Time Group)
```json
{
  "tag": "office_traffic_acl",
  "time_group_id": "550e8400-e29b-41d4-a716-446655440000",
  "rules": [
    {
      "action": "permit",
      "source": "192.168.1.0/24",
      "destination": "any",
      "protocol": "tcp"
    }
  ]
}
```

### Database/Backup Representation
```json
{
  "acl_index": 1,
  "tag": "office_traffic_acl",
  "time_group_id": "550e8400-e29b-41d4-a716-446655440000",
  "rules": [...]
}
```

### Frontend Display
```
ACL: office_traffic_acl
├─ Time Group: working_hours (09:00-18:00, M-F)
├─ Status: ⏰ Active (within working hours)
├─ Rules: 5
└─ Actions: [Edit] [Delete] [Details]
```

---

## Estimated Effort

- **Backend**: 3-4 hours
  - Handler updates: 1 hour
  - Scheduler logic: 1.5-2 hours
  - Testing: 0.5-1 hour

- **Frontend**: 2-3 hours
  - UI updates: 1.5-2 hours
  - JavaScript: 0.5-1 hour

- **Testing**: 2-3 hours
  - Unit tests: 1 hour
  - Integration tests: 1 hour
  - Manual testing: 0.5-1 hour

- **Total**: ~8-10 hours

---

## Database Migration

Since you're using JSON files:
- [ ] Existing ACL, ABF, Policer configs remain valid
- [ ] Add `TimeGroupID: ""` to all existing records on first read (if field missing)
- [ ] Or write migration script to add field to backup file

---

## Rollback Plan

If something breaks:
1. Time group assignments stored separately - easy to remove
2. VPP state independent - scheduler just logs, doesn't force changes yet
3. Can disable scheduler without affecting rules
4. Delete `time_groups.json` to reset

---

## Notes

- Currently: Scheduler logs enable/disable decisions
- Next: Scheduler calls enable/disable on VPP
- Don't modify VPP rules directly - VPP persists state
- Always unassign before deleting rule
- Consider time zone handling (currently uses server local time)

---

## Questions to Consider

1. Should rules be **automatically disabled** when outside time window?
2. Or just **logged** for audit trail?
3. Should there be **notifications** when rules enable/disable?
4. Need **time zone support**? (currently local server time)
5. **Exception dates**? (holidays, special days)

