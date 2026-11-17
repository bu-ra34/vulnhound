import os

import requests
from django.shortcuts import get_object_or_404, redirect
from flask import Flask, request, send_file
from sqlalchemy.orm import Session

from models import Article, Doc

app = Flask(__name__)


class UserDAO:
    @staticmethod
    def find_by_id(uid):
        return Doc.objects.get(pk=uid)


@app.route("/a")
def orm_get_then_fetch(session: Session):
    doc = Doc.objects.get(pk=request.args["id"])
    return requests.get(doc.callback_url).text


@app.route("/b")
def orm_filter_first():
    row = Article.objects.filter(slug=request.args["slug"]).first()
    return send_file(row.attachment_path)


@app.route("/c")
def get_or_404():
    art = get_object_or_404(Article, pk=request.args["id"])
    return redirect(art.url)


@app.route("/d")
def sqlalchemy_session_get(session: Session):
    obj = session.get(Doc, request.args["id"])
    return requests.get(obj.homepage).text


@app.route("/e")
def sqlalchemy_query_first(session: Session):
    obj = session.query(Doc).filter_by(name=request.args["n"]).first()
    return send_file(obj.path)


@app.route("/f")
def dao_find():
    user = UserDAO.find_by_id(request.args["id"])
    return redirect(user.profile_url)


@app.route("/g")
def generic_find_by(repo):
    item = repo.find_by_name(request.args["n"])
    return send_file(os.path.join("/srv", item.filename))


@app.route("/h")
def attribute_chain_through_lookup():
    owner = Doc.objects.get(pk=request.args["id"]).owner
    return redirect(owner.homepage)
