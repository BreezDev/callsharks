from pathlib import Path

from flask import Flask, abort, render_template

BASE_DIR = Path(__file__).resolve().parent
HTML_FILES = {path.name for path in BASE_DIR.glob("*.html")}

app = Flask(__name__, template_folder=str(BASE_DIR), static_folder=str(BASE_DIR))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/<path:page>")
def page(page: str):
    if page in HTML_FILES:
        return render_template(page)
    abort(404)


if __name__ == "__main__":
    app.run(debug=True)
