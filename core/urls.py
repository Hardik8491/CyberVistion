from django.urls import path

from .views import (
    ModelPredictionView,
    RealTimeDataView,
    GenerateReportView,
    MaintenancePredictionView,
    ThreatDataView,
    IncidentResponseView,
    VulnerabilityAnalysisView,
    DataVisualizationView,
    NetworkLogView,
    MaintenanceRecordView,
    create_threat,
    home,
    traffic_analysis_view,
    generate_threat_report,
    evaluate_threat_risk,
    ThreatLogView,
    view_threats,

)

urlpatterns = [
    path('create-threat/', create_threat, name='create_threat'),
    path('threats/', view_threats, name='view-threats'),
    path('', home, name='home'),  # The home view
    # Real-time data endpoint
    path('real-time-data/', RealTimeDataView.as_view(), name='real-time-data'),
    
    # Report generation endpoint
    path('generate-report/<str:report_type>/', GenerateReportView.as_view(), name='generate-report'),
    
    # Maintenance prediction endpoint
    path('maintenance-prediction/', MaintenancePredictionView.as_view(), name='maintenance-prediction'),
    
    # Threat data fetching endpoint
    path('fetch-threat-data/', ThreatDataView.as_view(), name='fetch-threat-data'),
    
    # Incident response endpoint
    path('incident-response/', IncidentResponseView.as_view(), name='incident-response'),
    
    # Vulnerability analysis endpoint
    path('vulnerability-analysis/', VulnerabilityAnalysisView.as_view(), name='vulnerability-analysis'),
    
    # Data visualization endpoint
    path('visualize-data/', DataVisualizationView.as_view(), name='visualize-data'),
    
    # Network logs endpoint
    path('network-logs/', NetworkLogView.as_view(), name='network-logs'),
    
    # Maintenance records endpoint
    path('maintenance-records/', MaintenanceRecordView.as_view(), name='maintenance-records'),
    
    # Traffic analysis endpoint (function-based view)
    path('traffic-analysis/', traffic_analysis_view, name='traffic-analysis'),
    
    # Threat report generation endpoint (function-based view)
    path('generate-threat-report/', generate_threat_report, name='generate-threat-report'),
    
    # Evaluate threat risk endpoint (function-based view)
    path('evaluate-risk/', evaluate_threat_risk, name='evaluate-risk'),
    
    path('predict/', ModelPredictionView.as_view(), name='predict'),  
    
    # Threat logs endpoint
    path('threat-logs/', ThreatLogView.as_view(), name='threat-logs'),
]

handler404 = 'core.views.custom_404_view'