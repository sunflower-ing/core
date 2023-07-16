from django.http import JsonResponse


def index(request):
    return JsonResponse({"i'm": "ok"})
