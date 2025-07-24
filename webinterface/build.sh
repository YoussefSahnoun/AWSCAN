#!/usr/bin/env bash
set -e

echo "Installing frontend dependencies..."
cd frontend
npm install

echo "Starting frontend..."

npm run start &

sleep 2

echo "Starting Flask backend..."
cd ../backend
export FLASK_APP="app.py"
flask run --port 5000
