from celery import shared_task
from django.utils.timezone import now, timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP


SENSITIVE_PATHS = ["/admin", "/login"]


@shared_task
def detect_anomalies():
    """
    Detect anomalies:
    - IPs with >100 requests in the past hour
    - IPs accessing sensitive paths (/admin, /login)
    """
    one_hour_ago = now() - timedelta(hours=1)

    # --- Rule 1: Excessive requests ---
    heavy_users = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for entry in heavy_users:
        ip = entry["ip_address"]
        reason = f"Excessive requests: {entry['request_count']} in the last hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)

    # --- Rule 2: Sensitive paths ---
    sensitive_hits = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS
    ).values_list("ip_address", "path")

    for ip, path in sensitive_hits:
        reason = f"Accessed sensitive path: {path}"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)
