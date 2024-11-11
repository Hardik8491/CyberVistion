# core/serializers.py
from rest_framework import serializers
from .models import NetworkLog, MaintenanceRecord, ThreatLog

class NetworkLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkLog
        fields = '__all__'  # Include all fields from the NetworkLog model

class MaintenanceRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = MaintenanceRecord
        fields = '__all__'  # Include all fields from the MaintenanceRecord model

class ThreatLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatLog
        fields = '__all__'
