from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .db import init_db
from .routes import router

ROOT = Path(__file__).resolve().parents[2]


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title='SentinelX Security Operations', version='0.1.0', lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=False,
    allow_methods=['GET', 'POST', 'PATCH'],
    allow_headers=['*'],
)


@app.middleware('http')
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; connect-src 'self' ws: wss:; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:"
    return response


app.include_router(router)


@app.get('/manus-routes.json', include_in_schema=False)
def route_manifest():
    return FileResponse(ROOT / 'public' / 'manus-routes.json', media_type='application/json')


@app.get('/targets', include_in_schema=False)
@app.get('/findings', include_in_schema=False)
@app.get('/research', include_in_schema=False)
def spa_entry():
    return FileResponse(ROOT / 'frontend' / 'index.html', media_type='text/html')


app.mount('/', StaticFiles(directory=ROOT / 'frontend', html=True), name='frontend')
