from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from WAF import waf_middleware

app = FastAPI()

@app.middleware("http")
async def waf_check(request: Request, call_next):
    body = await request.body()
    result = waf_middleware(
        ip=request.client.host,
        method=request.method,
        path=request.url.path,
        headers=dict(request.headers),
        body=body.decode(errors="ignore")
    )
    if result["action"] in ("block", "block_temp", "block_permanent"):
        return JSONResponse(status_code=403, content={"error": "Blocked by WAF"})
    return await call_next(request)

@app.get("/")
def home():
    return {"message": "Hello, I am protected by WAF!"}