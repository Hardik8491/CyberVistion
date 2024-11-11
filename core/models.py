from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone

class Threat(models.Model):
    src_ip = models.CharField(max_length=100)
    dst_ip = models.CharField(max_length=100)
    protocol = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  # Track when this record was last updated

    def __str__(self):
        return f"Threat from {self.src_ip} to {self.dst_ip} using {self.protocol}"

class ThreatLog(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)  # ForeignKey automatically creates 'threat_id' field
    details = models.TextField()
    severity = models.CharField(max_length=50, choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='low')
    timestamp = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)  # Whether the threat has been resolved or not

    def __str__(self):
        return f"Threat ID: {self.threat.threat_id}, Severity: {self.severity}"

class ThreatDatabase(models.Model):
    threat_name = models.CharField(max_length=255)
    threat_level = models.CharField(max_length=50)
    description = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, default='Active')
    affected_system = models.CharField(max_length=255)
    risk_score = models.IntegerField()
    remediation_actions = models.TextField()
    source = models.CharField(max_length=50)
    detected_by = models.CharField(max_length=100)

    def __str__(self):
        return f'{self.threat_name} - {self.threat_level}'

class MaintenanceRecord(models.Model):
    last_updated = models.DateTimeField(auto_now=True)
    threat_data = models.TextField()
    threat_id = models.IntegerField()
    device_id = models.CharField(max_length=100)
    status = models.CharField(max_length=50, choices=[('pending', 'Pending'), ('completed', 'Completed')], default='pending')
    failure_probability = models.FloatField()
    last_checked = models.DateTimeField(auto_now=True)
    next_due = models.DateTimeField(null=True, blank=True)  # Allows the field to be left empty

    def __str__(self):
        return f"Device: {self.device_id}, Status: {self.status}"

    def clean(self):
        # Validation for failure_probability to ensure it is between 0 and 1
        if not (0 <= self.failure_probability <= 1):
            raise ValidationError('Failure probability must be between 0 and 1.')

    def get_maintenance_predictions(self):
        return MaintenanceRecord.objects.filter(status='pending', failure_probability__gt=0.8)

    @staticmethod
    def predict_device_maintenance(device_id, failure_probability):
        if failure_probability > 0.75:
            return 'pending'
        else:
            return 'completed'

class VulnerabilityDatabase(models.Model):
    advisory_id = models.CharField(max_length=100, unique=True)
    vulnerability_data = models.JSONField()
    severity = models.CharField(max_length=50, choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], default='medium')
    last_updated = models.DateTimeField(auto_now=True)
    patched = models.BooleanField(default=False)  # Whether the vulnerability has been patched or not

    def __str__(self):
        return f"Advisory ID: {self.advisory_id}, Severity: {self.severity}"

class IncidentResponse(models.Model):
    incident_id = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    actions_taken = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    incident_status = models.CharField(max_length=50, choices=[('open', 'Open'), ('resolved', 'Resolved')], default='open')

    def __str__(self):
        return f"Incident ID: {self.incident_id}, Actions: {self.actions_taken}"

class SystemConfig(models.Model):
    config_name = models.CharField(max_length=100, unique=True)
    config_value = models.CharField(max_length=255)

    def __str__(self):
        return f"Config Name: {self.config_name}, Config Value: {self.config_value}"

class NetworkLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    message = models.TextField()
    level = models.CharField(max_length=20, choices=[('info', 'Info'), ('warning', 'Warning'), ('error', 'Error')], default='info')  # Categorize log messages

    def __str__(self):
        return f"[{self.level}] {self.timestamp}: {self.message}"
