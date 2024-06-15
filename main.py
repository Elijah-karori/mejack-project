from fastapi import FastAPI, Depends
from routers import users
from fastapi.middleware.cors import CORSMiddleware
from routers import items


app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(users.router)
app.include_router(items.router)