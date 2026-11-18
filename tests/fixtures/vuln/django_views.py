import subprocess

from django.db import connection
from django.http import HttpResponse
from myapp.models import Item


def search(request):
    term = request.GET.get("q")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM items WHERE name LIKE '%" + term + "%'")  # VH-EXPECT: sqli
    return HttpResponse("ok")


def by_name(request):
    n = request.POST["name"]
    items = Item.objects.raw(f"SELECT * FROM items WHERE name = '{n}'")  # VH-EXPECT: sqli
    return HttpResponse(len(list(items)))


def run(request):
    cmd = request.GET["cmd"]
    subprocess.Popen(cmd, shell=True)  # VH-EXPECT: cmdi
    return HttpResponse("started")
