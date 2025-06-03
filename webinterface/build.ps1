# Set current location to the frontend directory
Write-Host "Installing frontend dependencies..."
cd .\frontend
npm install

Write-Host "Starting frontend..."
Start-Process powershell -ArgumentList "npm run start" -NoNewWindow

# Set the FLASK_APP environment variable and start the Flask server
Write-Host "Starting Flask backend..."
cd ..\backend
$env:FLASK_APP = "app.py"
flask run --port 5000