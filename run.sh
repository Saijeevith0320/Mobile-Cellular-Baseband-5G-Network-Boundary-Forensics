#!/bin/bash
# ============================================================
# Mobile Cellular Baseband & 5G Network Boundary Forensics
# Quick Launch Script
# ============================================================

echo "📡 Starting Baseband & 5G Forensics Suite..."
echo "================================================"
echo ""

# Check for ADB
if ! command -v adb &> /dev/null; then
    echo "⚠️  ADB not found. Please install Android SDK Platform Tools."
    echo "   Download from: https://developer.android.com/studio/releases/platform-tools"
    echo ""
    echo "   macOS:  brew install android-platform-tools"
    echo "   Linux:  sudo apt install adb"
    echo "   Win:    choco install adb"
    echo ""
fi

# Check for Python dependencies
echo "🔍 Checking Python dependencies..."
pip install -r requirements.txt -q 2>/dev/null

echo ""
echo "🚀 Launching Streamlit application..."
echo "   Open http://localhost:8501 in your browser"
echo ""

# Run Streamlit
streamlit run app.py \
    --server.port=8501 \
    --server.address=0.0.0.0 \
    --browser.gatherUsageStats=false \
    --theme.base="dark"