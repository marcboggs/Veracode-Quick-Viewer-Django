from django.urls import path
from . import views

app_name = 'reporter' # Namespace for URLs

urlpatterns = [
    path('', views.application_list, name='application_list'),
    path('app/<str:app_id>/builds/', views.build_list, name='build_list'),
    path('report/<str:build_id>/', views.report_detail, name='report_detail'),
    path('report/<str:build_id>/export/static/', views.export_static_findings_csv, name='export_static_csv'),
    path('report/<str:build_id>/export/sca/', views.export_sca_findings_csv, name='export_sca_csv'),
]
