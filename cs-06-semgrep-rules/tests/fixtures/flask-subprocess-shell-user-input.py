import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


def vulnerable():
    host = request.args.get("host")
    # ruleid: flask-subprocess-shell-user-input
    subprocess.run("ping -c 1 " + host, shell=True)
    cmd = f"nslookup {request.form['name']}"
    # ruleid: flask-subprocess-shell-user-input
    subprocess.Popen(cmd, shell=True)
    # ruleid: flask-subprocess-shell-user-input
    subprocess.check_output("ls %s" % request.json["dir"], shell=True)
    # ruleid: flask-subprocess-shell-user-input
    os.system("rm -rf " + request.args["path"])
    # ruleid: flask-subprocess-shell-user-input
    os.popen("cat " + request.values.get("f"))


def safe():
    host = request.args.get("host")
    # ok: flask-subprocess-shell-user-input
    subprocess.run(["ping", "-c", "1", host])
    # ok: flask-subprocess-shell-user-input
    subprocess.run("ls -la /var/log", shell=True)
    # ok: flask-subprocess-shell-user-input
    subprocess.run(["ping", host], shell=False)
    constant = "uptime"
    # ok: flask-subprocess-shell-user-input
    os.system(constant)
