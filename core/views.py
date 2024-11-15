from datetime import datetime
import pickle
import django
import pandas as pd
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os
from django.db import IntegrityError
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import platform
from rest_framework.decorators import api_view
from rest_framework import status
from .models import NetworkLog, MaintenanceRecord, Threat, ThreatLog
from .serializers import NetworkLogSerializer, MaintenanceRecordSerializer, ThreatLogSerializer
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from .services import (
    fetch_and_store_threat_data,
    get_real_time_data,
    generate_report,
    collect_historical_data,
    forecast_failures,
    send_maintenance_alert,
    update_threat_database,
    isolate_system,
    block_ip_address,
    run_playbook,
    analyze_security_advisory,
    rank_vulnerabilities,
    send_vulnerability_alert,
    visualize_data,
     analyze_traffic, generate_report, evaluate_risk 
)


# views.py
MODEL_PATH = os.path.join(settings.BASE_DIR, 'cybervision_ai', 'models')



from django.http import JsonResponse


def server(request):
    return render(request, 'connect.html')


def welcome(request):
    # Extract the client's IP address
    ip_address = request.META.get('REMOTE_ADDR', None)
    
    # Get the current server time
    server_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Get the User-Agent from the request headers (used to infer device/browser)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
    
    # Get the request method (GET/POST)
    request_method = request.method
    
    # Extract the host from the request headers
    host = request.META.get('HTTP_HOST', 'Unknown')
    
    # Get the referrer (if exists) and origin (if exists)
    referrer = request.META.get('HTTP_REFERER', 'None')
    origin = request.META.get('HTTP_ORIGIN', 'None')
    
    # Get the request path (URL) and query parameters
    request_path = request.path
    query_params = request.GET.dict()
    
    # Content type of the request (if exists)
    content_type = request.META.get('CONTENT_TYPE', 'Unknown')
    
    # Get the platform details (OS and Architecture)
    system_info = platform.platform()
    
    # Session ID if using Django sessions
    session_id = request.session.session_key if request.session.session_key else "No session"

    # Get request headers like Accept-Language, Accept-Encoding, etc.
    accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', 'None')
    accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', 'None')
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', 'None')
    
    # Get cookies sent with the request
    cookies = request.COOKIES
    
    # Django settings and version
    django_version = django.get_version()
    environment = 'Development' if settings.DEBUG else 'Production'
    
    # Record request start time for performance measurement
    start_time = datetime.now()
    
    # Handle POST requests by getting the request body if it's not empty
    request_body = None
    if request.method == 'POST':
        try:
            request_body = json.loads(request.body)
        except json.JSONDecodeError:
            request_body = "Invalid JSON body"
    
    # Calculate the time taken to process the request
    processing_time = (datetime.now() - start_time).total_seconds()

    # User Authentication Info (if available)
    if request.user.is_authenticated:
        user_info = {
            "username": request.user.username,
            "email": request.user.email,
            "is_staff": request.user.is_staff,
            "is_superuser": request.user.is_superuser
        }
    else:
        user_info = "User not authenticated"

    # Create the response data with all gathered information
    response_data = {
        "message": "Welcome to CyberVision",
        "ip_address": ip_address,
        "server_time": server_time,
        "user_agent": user_agent,
        "request_method": request_method,
        "host": host,
        "referrer": referrer,
        "origin": origin,
        "request_path": request_path,
        "query_params": query_params,
        "content_type": content_type,
        "system_info": system_info,
        "session_id": session_id,
        "accept_language": accept_language,
        "accept_encoding": accept_encoding,
        "x_forwarded_for": x_forwarded_for,
        "cookies": cookies,
        "django_version": django_version,
        "environment": environment,
        "processing_time_seconds": processing_time,
        "request_body": request_body,
        "user_info": user_info
    }

    return JsonResponse(response_data)

def load_model(model_name):
    """Loads a model from the models directory."""
    with open(os.path.join(MODEL_PATH, model_name), 'rb') as model_file:
        model = pickle.load(model_file)
    return model

def preprocess_data(data):
    """Preprocess data before prediction (depends on your data cleaning steps)."""
    # Example: Convert data to a DataFrame if necessary
    df = pd.DataFrame(data)
    # Apply any other preprocessing steps here if needed
    return df


# views.py

class ModelPredictionView(APIView):
    def post(self, request):
        model_name = request.data.get('model', 'random_forest.pkl')  # Default to random forest
        data = request.data.get('data', None)

        if not data:
            return Response({"error": "No data provided"}, status=400)

        try:
            # Load model and preprocess data
            model = load_model(model_name)
            processed_data = preprocess_data(data)

            # Make predictions
            predictions = model.predict(processed_data)
            response = {"model": model_name, "predictions": predictions.tolist()}
            return JsonResponse(response)

        except FileNotFoundError:
            return Response({"error": f"Model '{model_name}' not found."}, status=404)
        except Exception as e:
            return Response({"error": str(e)}, status=500)


# Home view (example)
def home(request):
    return render(request, 'home.html')

@csrf_exempt
def create_threat(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            src_ip = data.get('src_ip')
            dst_ip = data.get('dst_ip')
            protocol = data.get('protocol')

            # Create threat
            threat = Threat.objects.create(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol)
            threat_id = threat.id

            # Send a message to WebSocket clients
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                'threats_group',  # Group name
                {
                    'type': 'threat_message',  # This will call the 'threat_message' method in consumer
                    'message': f'New threat logged: {src_ip} -> {dst_ip} using {protocol}.'
                }
            )

            return JsonResponse({"message": "Threat logged successfully", "threat_id": threat_id}, status=201)
        except IntegrityError:
            return JsonResponse({"error": "Data integrity error"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

def view_threats(request):
    threats = Threat.objects.all().order_by('-created_at')
    return render(request, 'view_threats.html', {'threats': threats})

class RealTimeDataView(APIView):
    def get(self, request):
        """
        Handles GET requests to fetch real-time data (e.g., threats, device health, etc.).
        """
        real_time_data = get_real_time_data()  # Call the service function to get real-time data
        return Response(real_time_data)  #

class GenerateReportView(APIView):
    def get(self, request, report_type):
        report = generate_report(report_type)
        return Response(report)

class MaintenancePredictionView(APIView):
    def get(self, request):
        # Collect historical data for maintenance prediction
        historical_data = collect_historical_data()

        if not historical_data:
            return Response({"error": "No historical data available for prediction."}, status=400)

        # Forecast failure based on historical data
        failure_probability = forecast_failures(historical_data)
        user_email = 'hardikbhammar88@gmail.com' 
        # Send maintenance alert if necessary
        device_id = 'device1'  # Replace with the actual device ID or fetch it dynamically
        send_maintenance_alert(failure_probability, device_id, user_email)

        # Return the failure probability in the response
        return Response({'failure_probability': failure_probability,'status': 'Maintenance alert sent successfully!'})

from rest_framework.views import APIView
from rest_framework.response import Response

class ThreatDataView(APIView):
    def get(self, request):
        threat_data = fetch_and_store_threat_data()
        update_threat_database(threat_data)
        
        if threat_data:
            return Response({
                'status': 'Threat data updated',
                'threats': threat_data
            })
        else:
            return Response({
                'status': 'No new threat data available',
                'threats': []
            })


class IncidentResponseView(APIView):
    def post(self, request):
        action = request.data.get('action')
        if action == 'isolate':
            isolate_system('device1')
        elif action == 'block_ip':
            block_ip_address('192.168.1.1')
        elif action == 'run_playbook':
            run_playbook('incident_response.yml')
        return Response({'status': 'Incident response executed'})

class VulnerabilityAnalysisView(APIView):
    def post(self, request):
        advisory_data = request.data.get('advisory_data')
        vulnerabilities = analyze_security_advisory(advisory_data)
        ranked_vulnerabilities = rank_vulnerabilities(vulnerabilities)
        send_vulnerability_alert(ranked_vulnerabilities)
        return Response({'vulnerabilities': ranked_vulnerabilities})

class DataVisualizationView(APIView):
    def get(self, request):
        data = collect_historical_data()
        visualized_data = visualize_data(data)
        return Response(visualized_data)


class NetworkLogView(APIView):
    def post(self, request):
        """
        Handle POST requests to create new network logs.
        """
        serializer = NetworkLogSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        """
        Handle GET requests to retrieve all network logs.
        """
        logs = NetworkLog.objects.all()
        serializer = NetworkLogSerializer(logs, many=True)
        return Response(serializer.data)


class MaintenanceRecordView(APIView):
    def get(self, request):
        """
        Handle GET requests to retrieve all maintenance records.
        """
        records = MaintenanceRecord.objects.all()
        serializer = MaintenanceRecordSerializer(records, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """
        Handle POST requests to create a new maintenance record.
        """
        serializer = MaintenanceRecordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def traffic_analysis_view(request):
    """API endpoint for real-time traffic analysis."""
    try:
        results = analyze_traffic()
        return Response({"status": "success", "data": results}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def generate_threat_report(request):
    """API endpoint to generate a summary report of recent threats."""
    try:
        report_data = generate_report()
        return Response({"status": "success", "data": report_data}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def evaluate_threat_risk(request):
    """API endpoint to evaluate and assess the risk of detected threats."""
    try:
        threat_data = request.data  # Expecting threat data as input
        risk_score = evaluate_risk(threat_data)
        return Response({"status": "success", "risk_score": risk_score}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ThreatLogView(APIView):
    def get(self, request):
        """
        Handle GET requests to retrieve all threat logs.
        """
        logs = ThreatLog.objects.all()
        serializer = ThreatLogSerializer(logs, many=True)
        return Response(serializer.data)
    
    def post(self, request):
        """
        Handle POST requests to create a new threat log.
        """
        serializer = ThreatLogSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def custom_404(request, exception=None):
    # If it's an API route, return a JSON error
    if request.path.startswith('/api/'):  # API path condition
        return JsonResponse({'error': 'Page not found', 'message': 'The requested API endpoint does not exist.'}, status=404)
    
    # For non-API routes, render a custom HTML 404 page
    return render(request, '404.html', status=404)