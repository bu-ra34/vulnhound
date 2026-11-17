from django.db import connection
from django.http import HttpResponse
from myapp.models import Item


def search(request):
    term = request.GET.get("q")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM items WHERE name LIKE %s", ["%" + term + "%"])
    return HttpResponse(len(Item.objects.filter(name=term)))
