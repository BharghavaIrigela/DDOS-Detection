#!/bin/bash

echo "📊 Extracting flows..."
python3 flow_extractor.py

echo "🤖 Running prediction..."
python3 predictor.py