To run the vulnerable version:
cd vulnerable-version
pip install flask
python app.py

cd secure-version
pip install flask flask-wtf
set BANK_ADMIN_PASSWORD=admin123
python app.py
