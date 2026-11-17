import os
import sqlite3
import subprocess

import tornado.web
from rest_framework.views import APIView


class Export(APIView):
    def post(self, request):
        os.system("tar cf out.tar " + request.data["dir"])  # VH-EXPECT: cmdi

    def get(self, request):
        conn = sqlite3.connect("db")
        conn.execute("select * from t where n = '%s'" % self.request.query_params.get("n"))  # VH-EXPECT: sqli


class BaseHandler(tornado.web.RequestHandler):
    pass


class RunHandler(BaseHandler):
    def get(self, job):
        subprocess.call("run " + job, shell=True)  # VH-EXPECT: cmdi

    def post(self):
        cmd = self.get_argument("cmd")
        os.system(cmd)  # VH-EXPECT: cmdi
        name = self.request.body
        open(name)  # VH-EXPECT: path-traversal
