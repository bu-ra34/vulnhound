import os
import subprocess

import tornado.web
from rest_framework.views import APIView


class Report(APIView):
    def post(self, request):
        n = int(request.data["n"])
        os.system("report --count " + str(n))
        subprocess.run(["report", "--out", "x"], env=os.environ.copy())


class Plain:
    def get(self, job):
        os.system("run " + job)


class PingHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("pong")

    def helper(self, job):
        os.system("run " + job)
