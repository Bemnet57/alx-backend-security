from .models import RequestLog
from django.utils.timezone import now

class IPLoggingMiddleware:
    """
    Middleware to log the IP address, timestamp, and path of every incoming request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP
        ip_address = self.get_client_ip(request)
        path = request.path
        timestamp = now()

        # Save request log
        RequestLog.objects.create(
            ip_address=ip_address,
            path=path,
            timestamp=timestamp
        )

        # Continue with request
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """
        Retrieve the client IP address considering proxies.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
