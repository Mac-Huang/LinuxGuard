#!/bin/bash
#
# Test the Automated Pipeline Orchestrator
# This demonstrates the complete self-healing pipeline
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

BASE_DIR="/home/mac/private/linux-guard"
cd "$BASE_DIR"

echo -e "${MAGENTA}======================================${NC}"
echo -e "${MAGENTA}   Automated Pipeline Test${NC}"
echo -e "${MAGENTA}======================================${NC}"
echo ""
echo "This test demonstrates the self-healing pipeline:"
echo "• Automatic pattern extraction"
echo "• Iterative checker generation"
echo "• Compilation error repair"
echo "• Validation and verification"
echo ""

# Clean previous runs if requested
if [ "$1" == "--clean" ]; then
    echo -e "${YELLOW}Cleaning previous runs...${NC}"
    rm -f results/*.json checkers/generated/*
    python3 scripts/module3_integration.py --restore 2>/dev/null || true
    echo "✓ Cleaned"
    echo ""
fi

# Run orchestrator
echo -e "${CYAN}Starting orchestrator...${NC}"
echo ""

python3 scripts/orchestrator.py \
    --commit 80af3745ca465c6c47e833c1902004a7fa944f37 \
    --max-iterations 3 \
    --max-repairs 3

# Check results
if [ -f "results/orchestrator_result.json" ]; then
    echo ""
    echo -e "${CYAN}Final Result:${NC}"
    python3 -c "
import json
with open('results/orchestrator_result.json', 'r') as f:
    result = json.load(f)
    if result['success']:
        print(f'✅ Checker: {result[\"checker\"][\"checker_name\"]}')
        print(f'   Type: {result[\"checker\"].get(\"anti_pattern_type\", \"unknown\")}')
        print(f'   Time: {result[\"elapsed_time\"]:.1f}s')
    else:
        print('❌ Generation failed')
"
else
    echo -e "${RED}No result file generated${NC}"
fi
