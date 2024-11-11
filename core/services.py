from django.conf import settings
from .models import ThreatLog, MaintenanceRecord, ThreatDatabase
from django.core.mail import send_mail
import requests
from datetime import datetime
import numpy as np
from sklearn.linear_model import LinearRegression
import subprocess
from requests.auth import HTTPBasicAuth
from django.core.exceptions import ObjectDoesNotExist
from dotenv import load_dotenv
import os
import logging

# Configure logging (you can place this in your settings)
logger = logging.getLogger(__name__)

# Load environment variables from the .env file
load_dotenv()

# Example of using the environment variables in your service.py code
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")
THREAT_THRESHOLD = float(os.getenv("THREAT_THRESHOLD", 0.8))  # default to 0.8 if not set
SECURITY_TEAM_EMAIL = os.getenv("SECURITY_TEAM_EMAIL")
REPORT_TIMEFRAME = int(os.getenv("REPORT_TIMEFRAME", 30))  # default to 30 if not set
RISK_MULTIPLIER = int(os.getenv("RISK_MULTIPLIER", 2))  # default to 2 if not set
HIGH_RISK_THRESHOLD = int(os.getenv("HIGH_RISK_THRESHOLD", 80))  # default to 80 if not set

# ====================
# Predictive Maintenance
# ====================

def collect_historical_data():
    """
    Collects historical data relevant to maintenance predictions.
    This can include past failures, maintenance records, sensor data, etc.
    """
    # Fetch all maintenance records with non-null failure probability (assuming this data is available)
    historical_data = MaintenanceRecord.objects.filter(failure_probability__isnull=False).order_by('-last_updated')[:100]

    return historical_data

def forecast_failures(historical_data):
    """
    Predicts potential failures based on historical data using a time-series forecasting model.
    """
    # Prepare data for the forecasting model
    timestamps = np.array([d.last_updated.timestamp() for d in historical_data]).reshape(-1, 1)
    failure_probabilities = np.array([d.failure_probability for d in historical_data])

    # Linear Regression Model to predict failure based on historical failure probabilities
    model = LinearRegression()
    model.fit(timestamps, failure_probabilities)

    # Predict future failure probability based on current time
    future_timestamp = np.array([[datetime.now().timestamp()]])  # Current time prediction
    predicted_failure_probability = model.predict(future_timestamp)[0]

    return predicted_failure_probability




def send_maintenance_alert(failure_probability, device_id, user_email):
    """
    Sends a maintenance alert if the failure probability exceeds the threshold.
    Sends an email to both IT team and the user for high failure probabilities.
    """
    if failure_probability > 0.8:  # Threshold for failure probability
        subject = f"URGENT: Device {device_id} Maintenance Alert"
        message = f"Device {device_id} has a high failure probability of {failure_probability:.2f}. Immediate attention required."
        recipient_list = [user_email]  # Added user_email to the recipient list
        from_email = 'your-email@domain.com'

        # Send the email alert
        send_mail(subject, message, from_email, recipient_list)

        # Log that the alert was sent
        logger.info(f"Maintenance alert sent for {device_id} with failure probability: {failure_probability:.2f}")
    else:
        # Log when no alert is sent
        logger.info(f"No alert needed for {device_id}. Failure probability: {failure_probability:.2f}")

# Threat Intelligence Feed


def fetch_and_store_threat_data():
    """
    Fetches real-time threat data from IBM X-Force Exchange API and stores it in the database.
    Handles rate limiting by checking response headers and waiting if necessary.
    """
    # IBM X-Force Exchange API endpoint
    url = 'https://api.xforce.ibmcloud.com/api/threats'
    
    # API Key and API Password for authentication
    api_key = '1792294d-df75-42d3-a8ad-a061bfae4c720'  # Replace with your actual API Key
    api_password = '938820e8-3ec7-4b38-818a-360dd8a4c3280'  # Replace with your actual API Password
    
    # Set up Basic Authentication with API key and password
    auth = HTTPBasicAuth(api_key, api_password)
    
    # Set up the headers
    headers = {
        'Content-Type': 'application/json',
    }

    # Make the GET request to fetch the threat data
    response = requests.get(url, headers=headers, auth=auth)
    
    # Check for rate limit and handle it
    if response.status_code == 200:
        # Check if rate limit headers are present
        rate_limit = response.headers.get('X-RateLimit-Limit')
        rate_remaining = response.headers.get('X-RateLimit-Remaining')
        rate_reset = response.headers.get('X-RateLimit-Reset')

        if rate_limit and rate_remaining and rate_reset:
            rate_limit = int(rate_limit)
            rate_remaining = int(rate_remaining)
            rate_reset = int(rate_reset)
            
            if rate_remaining == 0:
                reset_time = datetime.fromtimestamp(rate_reset)
                sleep_time = (reset_time - datetime.now()).total_seconds()
                print(f"Rate limit reached. Sleeping for {sleep_time} seconds.")
                time.sleep(sleep_time)
                
                # Retry the request after waiting
                response = requests.get(url, headers=headers, auth=auth)

        try:
            threat_data = response.json()
            threats = threat_data.get('threats', [])
            if threats:
                # Loop through the data and store it in the database
                for threat in threats:
                    threat_name = threat.get('title', 'Unknown Threat')
                    description = threat.get('description', 'No Description')
                    threat_type = threat.get('type', 'Unknown Type')
                    source = 'IBM X-Force Exchange'

                    # Save the fetched threat data to the database
                    threat_record = threat_data.objects.create(
                        threat_name=threat_name,
                        description=description,
                        threat_type=threat_type,
                        source=source,
                        timestamp=datetime.now(),
                        additional_info=threat  # Optionally, store the full threat data as JSON
                    )
                    threat_record.save()
                    print(f"Stored threat: {threat_name} - {threat_type}")
            else:
                print("No threats found in the response.")
        except ValueError:
            print("Failed to parse JSON response.")
    else:
        print(f"Failed to fetch threat data. Status code: {response.status_code}")


def update_threat_database(threat_data):
    if not threat_data:
        print("No threat data available to update.")
        return
    
    for threat in threat_data:
        ThreatDatabase.objects.update_or_create(
            threat_id=threat['id'],
            defaults={'threat_data': threat},
        )
        print(f"Updated/Created threat with ID: {threat['id']}")


def enrich_detection_data(detection_data, threat_data):
    """
    Enhances threat detection by cross-referencing detection data with external intelligence feeds.
    """
    enriched_data = []
    for threat in threat_data:
        for detection in detection_data:
            if detection['pattern'] in threat['pattern']:
                enriched_data.append({**detection, **threat})
    return enriched_data

# ==========================
# Automated Incident Response
# ==========================

def isolate_system(system_id):
    """
    Isolates a compromised system or network segment using automated protocols.
    """
    subprocess.run(['ansible-playbook', 'isolate_system.yml', '-e', f'system_id={system_id}'])

def block_ip_address(ip_address):
    """
    Blocks incoming traffic from suspicious IP addresses using firewall rules.
    """
    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])

def run_playbook(playbook_name):
    """
    Runs a predefined Ansible playbook for incident response.
    """
    subprocess.run(['ansible-playbook', playbook_name])

# ==========================
# AI-Driven Vulnerability Analysis
# ==========================

def analyze_security_advisory(advisory_data):
    """
    Analyzes security advisories to extract and rank vulnerabilities using NLP.
    """
    vulnerabilities = []
    for advisory in advisory_data:
        vulnerabilities.append({
            'vulnerability': advisory['vulnerability'],
            'severity': advisory['severity'],
        })
    return vulnerabilities

def rank_vulnerabilities(vulnerabilities):
    """
    Ranks vulnerabilities based on severity and exploitability.
    """
    ranked_vulnerabilities = sorted(vulnerabilities, key=lambda x: x['severity'], reverse=True)
    return ranked_vulnerabilities

def send_vulnerability_alert(vulnerabilities):
    """
    Sends alerts about high-risk vulnerabilities.
    """
    high_risk_vulnerabilities = [v for v in vulnerabilities if v['severity'] == 'high']
    for vuln in high_risk_vulnerabilities:
        send_vulnerability_alert_email(vuln)

def send_vulnerability_alert_email(vuln):
    """
    Sends an email notification for a high-risk vulnerability.
    """
    subject = f"High-Risk Vulnerability: {vuln['vulnerability']}"
    message = f"A high-risk vulnerability has been detected: {vuln['vulnerability']}. Severity: {vuln['severity']}"
    send_mail(subject, message, 'admin@network.com', ['security-team@network.com'])

# ==========================
# Interactive Dashboards & Reports
# ==========================

def get_real_time_data():
    """
    Fetches live data on threats, device health, and maintenance predictions from PostgreSQL.
    """

    # Fetch current threats data from the database (Django ORM)
    threats = ThreatDatabase.objects.all()

    # Fetch maintenance predictions that are still pending (Ensure this is correct based on your model)
    pending_maintenance = MaintenanceRecord.objects.filter(status='pending')  # Assuming MaintenanceRecord model exists

    # Real-Time Monitoring (e.g., count active threats)
    active_threats_count = threats.filter(status='Active').count()  # Match the 'Active' status in your database
    maintenance_due_count = pending_maintenance.count()

    # Real-Time data including threats and maintenance
    real_time_data = {
        'current_threats': list(threats.values('threat_name', 'threat_level', 'timestamp', 'status', 'affected_system')),  # Correct fields
         'maintenance_predictions': list(pending_maintenance.values('device_id', 'last_checked', 'status')),  # Assuming MaintenanceRecord has these fields
        'active_threats_count': active_threats_count,
        'maintenance_due_count': maintenance_due_count
    }

    return real_time_data


def generate_report(report_type):
    """
    Generates reports based on the report type (e.g., daily, weekly).
    """
    # Example logic: Aggregate data and generate report in the specified format
    if report_type == 'daily':
        data = get_real_time_data()
        # Generate a daily report (PDF, Excel, etc.)
        return {'data': data, 'type': 'daily'}
    return {'error': 'Unknown report type'}

def visualize_data(data):
    """
    Formats data for visualization on the dashboard using Chart.js.
    """
    return {'labels': [item['timestamp'] for item in data], 'values': [item['performance_metric'] for item in data]}

# ==========================
# Threat Detection & Alerts
# ==========================

def analyze_traffic():
    """Analyzes network traffic for anomalies."""
    # model = MLModel(settings.TRAINED_MODEL_PATH)
    # data = fetch_live_network_data()
    # predictions = model.predict(data)
    # if is_threat(predictions):
    #     trigger_alert(predictions)
    #     log_threat(predictions)
    return 0

def fetch_live_network_data():
    """Fetches real-time network data for analysis."""
    network_data = requests.get(settings.NETWORK_DATA_ENDPOINT).json()
    return network_data

def is_threat(predictions):
    """Determines if predictions indicate a threat based on threshold."""
    for prediction in predictions:
        if prediction.get('threat_level', 0) > settings.THREAT_THRESHOLD:
            return True
    return False

def log_threat(threat_data):
    """Logs threat details in the database."""
    ThreatLog.objects.create(details=threat_data)

def trigger_alert(threat_data):
    """Sends alerts for detected threats."""
    send_email_alert(threat_data)
    send_sms_alert(threat_data)

def send_email_alert(threat_data):
    """Sends an email alert to the security team."""
    subject = "CyberVision Alert: Potential Threat Detected"
    message = f"A threat has been detected: {threat_data}"
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [settings.SECURITY_TEAM_EMAIL]
    )

def send_sms_alert(threat_data):
    """Sends an SMS alert to the security team."""
    sms_message = f"Alert: Threat detected - {threat_data.get('details', 'N/A')}"
    # Here, integrate with an SMS API (e.g., Twilio) to send the SMS
    # requests.post(SMS_API_ENDPOINT, data={'message': sms_message, 'to': settings.SECURITY_TEAM_PHONE})

def generate_report():
    """Generates a report of recent threats."""
    recent_threats = ThreatLog.objects.filter(timestamp__gte=settings.REPORT_TIMEFRAME)
    report_data = {
        'total_threats': recent_threats.count(),
        'threats': recent_threats.values('details', 'timestamp')
    }
    return report_data

def evaluate_risk(threat_data):
    """Assesses the risk level based on threat data severity."""
    risk_score = threat_data.get('severity', 0) * settings.RISK_MULTIPLIER
    if risk_score > settings.HIGH_RISK_THRESHOLD:
        trigger_high_risk_alert(threat_data, risk_score)
    return risk_score

def trigger_high_risk_alert(threat_data, risk_score):
    """Sends alerts for high-risk threats with a significant score."""
    subject = "High-Risk Threat Detected!"
    message = f"High-Risk Threat: {threat_data}. Risk Score: {risk_score}"
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [settings.SECURITY_TEAM_EMAIL]
    )
