import os

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from iptools import ip_bp


def _rate_key():
    # Rate-limit on the real client IP behind the Cloudflare tunnel.
    from flask import request

    return request.headers.get("CF-Connecting-IP") or get_remote_address()


def create_app():
    app = Flask(__name__)
    limiter = Limiter(
        key_func=_rate_key,
        default_limits=["120 per minute"],
        storage_uri="memory://",
        app=app,
    )
    app.register_blueprint(ip_bp)
    # Tighter limit on the suggestion form to curb spam.
    limiter.limit("5 per hour")(app.view_functions["ip_bp.api_suggest"])
    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(port=port, debug=True)
