from fastapi import FastAPI, Request
from database import engine, Base
from routers import auth, todos, admin, users
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from routers.todos import root_entry


app = FastAPI()

Base.metadata.create_all(bind=engine)


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", include_in_schema=False)
async def test(request: Request):
    return await root_entry (request)

@app.get("/healthy")
def health_check():
    return {'status': 'Healthy'}


app.include_router(auth.router)
app.include_router(todos.router)
app.include_router(admin.router)
app.include_router(users.router)
