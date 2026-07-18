from flask import Flask, request, abort
from WAF import waf_middleware

app = Flask(__name__)

@app.before_request
def waf_check():
    result = waf_middleware(
        ip=request.remote_addr,
        method=request.method,
        path=request.path,
        headers=dict(request.headers),
        body=request.get_data(as_text=True)
    )
    if result["action"] in ("block", "block_temp", "block_permanent"):
        abort(403)

@app.route('/')
def home():
    return {"message": "Hello, I am protected by WAF!"}