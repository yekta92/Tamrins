from fastapi import FastAPI
from api.utils.database import create_db_and_tables
from contextlib import asynccontextmanager

from api.routers.todo_api import todos_router
from api.routers.auth import auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield
    # (Optional) Shutdown logic



app = FastAPI(lifespan=lifespan)
app.include_router(todos_router, prefix="/todo")
app.include_router(auth_router, prefix="/auth")

