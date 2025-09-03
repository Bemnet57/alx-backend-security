from django.http import HttpResponseForbidden
from django.utils.timezone import now
from django.core.cache import cache
from ipgeolocation import geolocator
from .models import RequestLog, BlockedIP


class IPLoggingMiddleware:
    """
    Middleware to log the IP address, timestamp, path,
    and geolocation data (country, city).
    Blocks requests if the IP is blacklisted.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path
        timestamp = now()

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Get cached geolocation
        cache_key = f"geo_{ip_address}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            try:
                geo_data = geolocator.get(ip_address)
                cache.set(cache_key, geo_data, 60 * 60 * 24)  # cache 24 hours
            except Exception:
                geo_data = {"country": None, "city": None}

        country = geo_data.get("country", None)
        city = geo_data.get("city", None)

        # Save request log with geolocation
        RequestLog.objects.create(
            ip_address=ip_address,
            path=path,
            timestamp=timestamp,
            country=country,
            city=city,
        )

        return self.get_response(request)

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
