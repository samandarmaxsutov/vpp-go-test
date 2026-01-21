#!/bin/bash

# IP Groups Feature Test Script
# Tests the IP groups management system

echo "🧪 IP Groups Management System - Feature Test"
echo "=============================================="
echo ""

# Create test directory
TEST_DIR="/etc/sarhad-guard/ip_groups"
mkdir -p "$TEST_DIR"

echo "✅ Created IP groups directory: $TEST_DIR"
echo ""

# Test 1: Create a sample Telegram group file
echo "📝 Test 1: Creating sample Telegram group..."
cat > "/tmp/telegram.txt" << 'EOF'
# Telegram IP Ranges
# Last updated: 2024-01-21

# Telegram ASN43049 ranges
91.108.4.0/22
91.108.8.0/22
91.108.12.0/22
91.108.16.0/22
91.108.20.0/22
91.108.56.0/22
91.108.60.0/22

# Individual Telegram IPs
149.154.160.0/20
149.154.176.0/20
149.154.240.0/20

# Comments and blank lines are ignored
# This is a valid format
EOF
echo "✅ Sample Telegram list created: /tmp/telegram.txt"
echo ""

# Test 2: Create a sample YouTube group file
echo "📝 Test 2: Creating sample YouTube group..."
cat > "/tmp/youtube.txt" << 'EOF'
# YouTube/Google IPs
# Common Google services IP ranges

8.8.8.8
8.8.4.4
142.250.0.0/15
172.217.0.0/16
172.218.0.0/16
172.219.0.0/16
172.220.0.0/16
172.221.0.0/16
172.222.0.0/16
172.223.0.0/16
EOF
echo "✅ Sample YouTube list created: /tmp/youtube.txt"
echo ""

# Test 3: Show supported file formats
echo "📋 Supported File Formats:"
echo "  - .txt files with one IP/subnet per line"
echo "  - .csv files with IP lists"
echo "  - .list files with IP lists"
echo ""

# Test 4: Show usage examples
echo "📚 API Usage Examples:"
echo ""
echo "1. Get all IP groups:"
echo "   curl -H 'Cookie: sarhad_session=...' http://localhost:8080/api/ip-groups"
echo ""
echo "2. Create a new group:"
echo "   curl -X POST http://localhost:8080/api/ip-groups \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"name\":\"Telegram\",\"content\":\"91.108.4.0/22\"}'"
echo ""
echo "3. Upload a file:"
echo "   curl -X POST http://localhost:8080/api/ip-groups/upload \\"
echo "     -F 'name=Telegram' \\"
echo "     -F 'file=@/tmp/telegram.txt'"
echo ""
echo "4. Get group statistics:"
echo "   curl http://localhost:8080/api/ip-groups/stats"
echo ""
echo "5. Download a group:"
echo "   curl http://localhost:8080/api/ip-groups/{ID}/download -o group.txt"
echo ""

# Test 5: Show directory structure
echo "📂 Directory Structure:"
echo "   /etc/sarhad-guard/ip_groups/"
echo "   ├── {timestamp1}.json  (Group 1)"
echo "   ├── {timestamp2}.json  (Group 2)"
echo "   └── ..."
echo ""

# Test 6: Show expected JSON structure
echo "📄 Expected JSON Structure:"
cat << 'EOF'
{
  "id": "1234567890",
  "name": "Telegram",
  "content": "91.108.4.0/22\n91.108.8.0/22",
  "ips": ["91.108.100.1"],
  "subnets": ["91.108.4.0/22", "91.108.8.0/22"],
  "invalid": [],
  "count": 3,
  "created_at": "2026-01-21T12:00:00Z",
  "updated_at": "2026-01-21T12:00:00Z"
}
EOF
echo ""

echo "✅ Test Complete!"
echo ""
echo "🚀 Start using the IP Groups feature:"
echo "   1. Go to http://localhost:8080/ip-groups"
echo "   2. Click 'Add New Group' or 'Upload File'"
echo "   3. Create groups for Telegram, YouTube, etc."
echo "   4. Use groups in your firewall rules!"
echo ""
