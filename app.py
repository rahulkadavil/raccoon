
#!/usr/bin/env python3
import os, subprocess
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, scoped_session, selectinload

BASE_DIR=os.path.abspath(os.path.dirname(__file__))
DB_PATH="sqlite:///"+os.path.join(BASE_DIR,"recon.db")

USERNAME="admin"
PASSWORD="password"

SUBFINDER_CMD="subfinder"
NAABU_CMD="naabu"
HTTPX_CMD="httpx"
NUCLEI_CMD="nuclei"
NUCLEI_TEMPLATES=os.path.join(BASE_DIR,"nuclei-templates")

CATEGORIES=["cves","misconfig","exposures","technologies","exposed-panels","takeovers"]

app=Flask(__name__)
app.secret_key="change-this-secret"
engine=create_engine(DB_PATH,connect_args={"check_same_thread":False})
SessionDB=scoped_session(sessionmaker(bind=engine))
Base=declarative_base()
executor=ThreadPoolExecutor(max_workers=6)

def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*a,**k)
    return w

class ScanJob(Base):
    __tablename__="scan_jobs"
    id=Column(Integer,primary_key=True)
    domain=Column(String,unique=True)
    status=Column(String)
    created_at=Column(DateTime,default=datetime.utcnow)
    subdomains=relationship("Subdomain",cascade="all,delete-orphan")

class Subdomain(Base):
    __tablename__="subdomains"
    id=Column(Integer,primary_key=True)
    scan_id=Column(Integer,ForeignKey("scan_jobs.id"))
    name=Column(String)
    http_alive=Column(Boolean,default=False)
    ports=relationship("Port",cascade="all,delete-orphan",lazy="selectin")
    findings=relationship("NucleiFinding",cascade="all,delete-orphan",lazy="selectin")

class Port(Base):
    __tablename__="ports"
    id=Column(Integer,primary_key=True)
    subdomain_id=Column(Integer,ForeignKey("subdomains.id"))
    port=Column(String)

class NucleiFinding(Base):
    __tablename__="nuclei_findings"
    id=Column(Integer,primary_key=True)
    subdomain_id=Column(Integer,ForeignKey("subdomains.id"))
    raw=Column(Text)
    category=Column(String)
    created_at=Column(DateTime,default=datetime.utcnow)

class NucleiProgress(Base):
    __tablename__="nuclei_progress"
    id=Column(Integer,primary_key=True)
    subdomain_id=Column(Integer,unique=True)
    status=Column(String)

Base.metadata.create_all(engine)

def run(cmd):
    try:
        return subprocess.check_output(cmd,stderr=subprocess.DEVNULL).decode().splitlines()
    except:
        return []

def enumerate_subs(domain):
    subs=set(run([SUBFINDER_CMD,"-silent","-d",domain]))
    subs.add(domain)
    return sorted(subs)

def httpx_scan(subs):
    tmp=os.path.join(BASE_DIR,"httpx.txt")
    open(tmp,"w").write("\n".join(subs))
    urls=run([HTTPX_CMD,"-silent","-l",tmp])
    return {u.split("://",1)[1].split("/",1)[0] for u in urls if "://" in u}

def start_scan(domain):
    s=SessionDB()
    job=ScanJob(domain=domain,status="running")
    s.add(job); s.commit()
    subs=enumerate_subs(domain)
    alive=httpx_scan(subs)
    for sub in subs:
        s.add(Subdomain(scan_id=job.id,name=sub,http_alive=sub in alive))
    s.commit()
    for sd in job.subdomains:
        for p in run([NAABU_CMD,"-host",sd.name,"-silent"]):
            s.add(Port(subdomain_id=sd.id,port=p))
    s.commit()
    job.status="finished"
    s.commit(); s.close()

def nuclei_bg(sub_id,cats):
    s=SessionDB()
    prog=s.query(NucleiProgress).filter_by(subdomain_id=sub_id).first()
    if not prog:
        prog=NucleiProgress(subdomain_id=sub_id,status="running"); s.add(prog)
    prog.status="running"; s.commit()
    sub=s.get(Subdomain,sub_id)
    for c in cats:
        tmpl=os.path.join(NUCLEI_TEMPLATES,c)
        for line in run([NUCLEI_CMD,"-u",sub.name,"-t",c,"-silent"]):
            s.add(NucleiFinding(subdomain_id=sub.id,raw=line,category=c))
    prog.status="finished"
    s.commit(); s.close()

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        if request.form["username"]==USERNAME and request.form["password"]==PASSWORD:
            session["logged_in"]=True
            return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    s=SessionDB(); jobs=s.query(ScanJob).all(); s.close()
    return render_template("index.html",jobs=jobs)

@app.route("/scan",methods=["POST"])
@login_required
def scan():
    executor.submit(start_scan,request.form["domain"])
    return redirect(url_for("index"))

@app.route("/scan/<domain>")
@login_required
def scan_view(domain):
    only_alive=request.args.get("http_alive")=="yes"
    s=SessionDB()
    q=s.query(Subdomain).join(ScanJob).options(selectinload(Subdomain.ports)).filter(ScanJob.domain==domain)
    if only_alive: q=q.filter(Subdomain.http_alive==True)
    subs=q.all()
    job=s.query(ScanJob).filter_by(domain=domain).first()
    progress={p.subdomain_id:p.status for p in s.query(NucleiProgress).all()}
    s.close()
    return render_template("scan.html",job=job,subdomains=subs,progress=progress,categories=CATEGORIES,only_alive=only_alive)

@app.route("/results/<domain>")
@login_required
def results(domain):
    only_alive=request.args.get("http_alive")=="yes"
    s=SessionDB()
    q=s.query(Subdomain).join(ScanJob).options(selectinload(Subdomain.findings)).filter(ScanJob.domain==domain)
    if only_alive: q=q.filter(Subdomain.http_alive==True)
    subs=q.all()
    job=s.query(ScanJob).filter_by(domain=domain).first()

    grouped_results={}
    for sd in subs:
        grouped=defaultdict(list)
        for f in sd.findings:
            grouped[f.category].append(f.raw)
        grouped_results[sd.id]=grouped

    s.close()
    return render_template(
        "results.html",
        job=job,
        subdomains=subs,
        grouped_results=grouped_results,
        only_alive=only_alive
    )

@app.route("/run_nuclei/<int:sid>",methods=["POST"])
@login_required
def run_nuclei(sid):
    executor.submit(nuclei_bg,sid,request.form.getlist("categories"))
    return jsonify({"status":"started"})

if __name__=="__main__":
    app.run(host="0.0.0.0",port=5000,debug=True)
