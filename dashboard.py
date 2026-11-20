import os, json
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from scanner import scan_site
from reporter import save_reports

def create_app():
    app = Flask(__name__)
    app.secret_key = os.urandom(32)
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
    app.config["LAST_SCAN"] = None
    app.config["HISTORY"] = []

    @app.get("/")
    def index():
        return render_template("index.html", data=app.config["LAST_SCAN"])

    @app.post("/scan")
    def scan():
        target = request.form.get("target", "").strip()
        auth = request.form.get("auth", "").strip()
        cookie = request.form.get("cookie", "").strip()
        confirm = request.form.get("authorized")
        if confirm != "yes":
            flash("স্ক্যানের আগে মালিকানা/লিখিত অনুমতি নিশ্চিত করুন।", "error")
            return redirect(url_for("index"))
        try:
            result = scan_site(target, auth, cookie)
            # Do not store auth material in reports/history.
            paths = save_reports(result)
            result["reports"] = paths
            app.config["LAST_SCAN"] = result
            app.config["HISTORY"].insert(0, {"target": target, "pages": result["page_count"],
                                             "findings": result["finding_count"]})
            app.config["HISTORY"] = app.config["HISTORY"][:15]
            flash("Scan complete. ফলাফল যাচাই করে দেখুন।", "success")
        except Exception as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.get("/history")
    def history():
        return render_template("history.html", history=app.config["HISTORY"])

    @app.get("/report/<kind>")
    def report(kind):
        data = app.config["LAST_SCAN"]
        if not data:
            flash("কোনো রিপোর্ট নেই।", "error")
            return redirect(url_for("index"))
        paths = data.get("reports", [])
        mapping = {os.path.splitext(p)[1][1:]: p for p in paths}
        if kind not in mapping or not os.path.exists(mapping[kind]):
            flash("রিপোর্ট পাওয়া যায়নি।", "error")
            return redirect(url_for("index"))
        return send_file(mapping[kind], as_attachment=True)
    return app
