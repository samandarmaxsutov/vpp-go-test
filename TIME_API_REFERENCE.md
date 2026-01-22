# Time Management API Reference

## Overview
Complete REST API for managing time-based rules in your VPP system.

---

## Base URL
```
http://localhost:8000/api/time-groups
```

---

## Endpoints

### 1. Create Time Group
```http
POST /api/time-groups
Content-Type: application/json

{
  "name": "working_hours",
  "description": "Standard business hours",
  "start_time": "09:00",
  "end_time": "18:00",
  "weekdays": ["M", "T", "W", "TH", "F"],
  "is_active": true
}
```

**Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "working_hours",
  "description": "Standard business hours",
  "start_time": "09:00",
  "end_time": "18:00",
  "weekdays": ["M", "T", "W", "TH", "F"],
  "is_active": true,
  "created_at": "2026-01-22T10:00:00Z",
  "updated_at": "2026-01-22T10:00:00Z"
}
```

---

### 2. List All Time Groups
```http
GET /api/time-groups
```

**Response (200):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "working_hours",
    "description": "Standard business hours",
    "start_time": "09:00",
    "end_time": "18:00",
    "weekdays": ["M", "T", "W", "TH", "F"],
    "is_active": true,
    "created_at": "2026-01-22T10:00:00Z",
    "updated_at": "2026-01-22T10:00:00Z"
  },
  {
    "id": "660e8400-e29b-41d4-a716-446655440001",
    "name": "lunch_time",
    "description": "Lunch break",
    "start_time": "12:00",
    "end_time": "13:00",
    "weekdays": ["M", "T", "W", "TH", "F"],
    "is_active": true,
    "created_at": "2026-01-22T11:00:00Z",
    "updated_at": "2026-01-22T11:00:00Z"
  }
]
```

---

### 3. Get Single Time Group
```http
GET /api/time-groups/:id
```

**Example:**
```
GET /api/time-groups/550e8400-e29b-41d4-a716-446655440000
```

**Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "working_hours",
  "description": "Standard business hours",
  "start_time": "09:00",
  "end_time": "18:00",
  "weekdays": ["M", "T", "W", "TH", "F"],
  "is_active": true,
  "created_at": "2026-01-22T10:00:00Z",
  "updated_at": "2026-01-22T10:00:00Z"
}
```

**Error (404):**
```json
{
  "error": "vaqt grupp topilmadi: invalid-id"
}
```

---

### 4. Update Time Group
```http
PUT /api/time-groups/:id
Content-Type: application/json

{
  "name": "business_hours",
  "description": "Business hours (updated)",
  "start_time": "08:30",
  "end_time": "17:30",
  "weekdays": ["M", "T", "W", "TH", "F"],
  "is_active": true
}
```

**Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "business_hours",
  "description": "Business hours (updated)",
  "start_time": "08:30",
  "end_time": "17:30",
  "weekdays": ["M", "T", "W", "TH", "F"],
  "is_active": true,
  "created_at": "2026-01-22T10:00:00Z",
  "updated_at": "2026-01-22T10:30:00Z"
}
```

---

### 5. Delete Time Group
```http
DELETE /api/time-groups/:id
```

**Response (200):**
```json
{
  "message": "O'chirildi"
}
```

---

### 6. Get Time Group Status
Check if a time group is currently active (within time window).

```http
GET /api/time-groups/:id/status
```

**Response (200):**
```json
{
  "is_within_time_window": true,
  "current_time": "14:30",
  "current_day": "Monday",
  "message": "Faol: working_hours ichida (Monday 09:00-18:00)"
}
```

OR (if not in window):

```json
{
  "is_within_time_window": false,
  "current_time": "22:00",
  "current_day": "Monday",
  "message": "O'chirildi: working_hours ichida emas"
}
```

---

### 7. Assign Time Group to Rule
Associate a time group with an ACL, ABF, or Policer rule.

```http
POST /api/time-groups/:id/assign
Content-Type: application/json

{
  "rule_type": "ACL",
  "rule_id": "1"
}
```

**Parameters:**
- `rule_type`: `"ACL"`, `"ABF"`, or `"POLICER"`
- `rule_id`: The rule's identifier (index or name)

**Response (200):**
```json
{
  "message": "Tayinlandi"
}
```

---

### 8. Unassign Time Group from Rule
Remove association between time group and rule.

```http
DELETE /api/time-groups/:id/assign
Content-Type: application/json

{
  "rule_type": "ACL",
  "rule_id": "1"
}
```

**Response (200):**
```json
{
  "message": "Olib tashlandi"
}
```

---

### 9. Get Rule Assignments
List all time groups assigned to a specific rule.

```http
GET /api/time-groups/rule-assignments?rule_type=ACL&rule_id=1
```

**Response (200):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "working_hours",
    "description": "Standard business hours",
    "start_time": "09:00",
    "end_time": "18:00",
    "weekdays": ["M", "T", "W", "TH", "F"],
    "is_active": true,
    "created_at": "2026-01-22T10:00:00Z",
    "updated_at": "2026-01-22T10:00:00Z"
  }
]
```

---

### 10. Check if Rule is Active
Determine if a specific rule should be active based on its time group assignments.

```http
GET /api/time-groups/check-rule?rule_type=ACL&rule_id=1
```

**Response (200 - Active):**
```json
{
  "is_active": true,
  "message": "working_hours ichida faol (Monday 09:00-18:00)"
}
```

**Response (200 - Inactive):**
```json
{
  "is_active": false,
  "message": "hech bir vaqt oynasi ichida emas - o'chirildi"
}
```

---

## Weekday Codes

| Code | Day |
|------|-----|
| `M` | Monday (Dushanba) |
| `T` | Tuesday (Seshanba) |
| `W` | Wednesday (Chorshanba) |
| `TH` | Thursday (Payshanba) |
| `F` | Friday (Juma) |
| `SA` | Saturday (Shanba) |
| `SU` | Sunday (Yakshanba) |

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "JSON validatsiya xatosi: invalid field"
}
```

### 404 Not Found
```json
{
  "error": "vaqt grupp topilmadi: invalid-id"
}
```

### 500 Internal Server Error
```json
{
  "error": "xatolik: database connection failed"
}
```

---

## Request/Response Examples

### Example 1: Create Multiple Time Groups

```bash
# Create working_hours
curl -X POST http://localhost:8000/api/time-groups \
  -H "Content-Type: application/json" \
  -d '{
    "name": "working_hours",
    "description": "9 AM to 6 PM",
    "start_time": "09:00",
    "end_time": "18:00",
    "weekdays": ["M","T","W","TH","F"],
    "is_active": true
  }'

# Create lunch_time
curl -X POST http://localhost:8000/api/time-groups \
  -H "Content-Type: application/json" \
  -d '{
    "name": "lunch_time",
    "description": "Lunch break",
    "start_time": "12:00",
    "end_time": "13:00",
    "weekdays": ["M","T","W","TH","F"],
    "is_active": true
  }'

# Create off_hours
curl -X POST http://localhost:8000/api/time-groups \
  -H "Content-Type: application/json" \
  -d '{
    "name": "off_hours",
    "description": "Evening and weekends",
    "start_time": "18:00",
    "end_time": "09:00",
    "weekdays": ["M","T","W","TH","F","SA","SU"],
    "is_active": false
  }'
```

### Example 2: Assign and Check Status

```bash
# Get ID of working_hours group (from list response)
WORKING_HOURS_ID="550e8400-e29b-41d4-a716-446655440000"

# Assign to ACL rule #1
curl -X POST http://localhost:8000/api/time-groups/$WORKING_HOURS_ID/assign \
  -H "Content-Type: application/json" \
  -d '{
    "rule_type": "ACL",
    "rule_id": "1"
  }'

# Check if ACL rule #1 is active
curl http://localhost:8000/api/time-groups/check-rule?rule_type=ACL&rule_id=1

# Check status of working_hours group
curl http://localhost:8000/api/time-groups/$WORKING_HOURS_ID/status
```

---

## Integration with Frontend

The Time Management UI automatically handles all API calls:

```javascript
// TIME_MANAGER global object (defined in time.html)

TIME_MANAGER.loadTimeGroups()          // GET /api/time-groups
TIME_MANAGER.saveTimeGroup()           // POST /api/time-groups
TIME_MANAGER.editTimeGroup(id)         // GET /api/time-groups/:id
TIME_MANAGER.updateTimeGroup()         // PUT /api/time-groups/:id
TIME_MANAGER.deleteTimeGroup(id)       // DELETE /api/time-groups/:id
TIME_MANAGER.showStatus(id)            // GET /api/time-groups/:id/status
```

---

## Authentication

All endpoints require being logged in (check your existing auth middleware).

---

## Rate Limiting

No rate limiting applied. Consider implementing if needed.

---

## Logging

All API calls are logged via `logger.LogConfigChange()`:
- User ID
- Client IP
- Action (CREATE, UPDATE, DELETE, ASSIGN_TIME, UNASSIGN_TIME)
- Details (full request JSON)

---

## Performance

- **Response Time**: < 50ms typically
- **Concurrent Requests**: Fully thread-safe
- **Database**: File-based JSON (no external DB needed)

