#!/bin/bash
# ============================================================
# VISHANTI eBPF — Tenant Onboarding (calls provider + tenant)
# ============================================================

echo ""
echo "============================================================"
echo "  VISHANTI eBPF — Tenant Onboarding"
echo "============================================================"
echo ""
echo "  This will run TWO steps:"
echo "    Step 1: Set PROVIDER ceiling (platform admin)"
echo "    Step 2: Set TENANT limits (tenant admin)"
echo ""
echo "  You can also run them separately:"
echo "    /root/configure-provider.sh"
echo "    /root/configure-tenant.sh"
echo ""

read -p "  Continue with full onboarding? (yes/no): " proceed
if [ "$proceed" != "yes" ]; then
    echo "  Aborted."
    exit 0
fi

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  STEP 1: Provider Ceiling                               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

/root/configure-provider.sh

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  STEP 2: Tenant Limits                                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

/root/configure-tenant.sh

echo ""
echo "============================================================"
echo "  Tenant onboarding COMPLETE"
echo "  Provider ceiling + Tenant limits applied"
echo "============================================================"
