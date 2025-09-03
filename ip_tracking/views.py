from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from ratelimit.decorators import ratelimit
from ip_tracking.utils import user_or_ip


# Anonymous users → 5 req/min
@ratelimit(key="ip", rate="5/m", block=True, method=["POST"])
# Authenticated users → 10 req/min
@ratelimit(key=user_or_ip, rate="10/m", block=True, method=["POST"])
def login_view(request):
    """
    Simple login view with rate limiting:
    - Anonymous: 5 requests/min
    - Authenticated: 10 requests/min
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({"success": True, "message": "Login successful"})
        else:
            return JsonResponse({"success": False, "message": "Invalid credentials"}, status=401)

    return JsonResponse({"message": "Send a POST request with username and password"}, status=400)
