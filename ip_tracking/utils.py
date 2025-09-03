def user_or_ip(request):
    """
    Returns a key for rate limiting:
    - If authenticated, use user ID
    - Else, use client IP address
    """
    if request.user.is_authenticated:
        return str(request.user.pk)
    return request.META.get("REMOTE_ADDR")
