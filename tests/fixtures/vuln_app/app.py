from flask import Flask, jsonify, request


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return (
            """
            <html>
              <head><title>VPT Fixture App</title></head>
              <body>
                <h1>VPT Fixture App</h1>
                <p><a href="/page2">Page 2</a></p>
                <p><a href="/echo?q=hello">Echo (q=hello)</a></p>
                <form action="/submit" method="post">
                  <input name="name" value="alice" />
                  <button type="submit">Submit</button>
                </form>
              </body>
            </html>
            """,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.get("/page2")
    def page2():
        return (
            """
            <html>
              <head><title>VPT Fixture App - Page 2</title></head>
              <body>
                <h2>Page 2</h2>
                <p><a href="/echo?q=page2">Echo (q=page2)</a></p>
              </body>
            </html>
            """,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.get("/echo")
    def echo():
        q = request.args.get("q", "")
        # Intentionally reflect user input to provide predictable scanner surface area.
        return (
            f"<html><body><pre>ECHO:{q}</pre></body></html>",
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.post("/submit")
    def submit():
        name = request.form.get("name", "")
        return (
            f"<html><body>SUBMIT:{name}</body></html>",
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.get("/api/hello")
    def api_hello():
        return jsonify({"ok": True, "message": "hello"})

    return app


app = create_app()

