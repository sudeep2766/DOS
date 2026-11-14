'''
run this shi before starting the server

mkdir ~/social && cd ~/social
python3 -m venv venv && source venv/bin/activate
pip install fastapi uvicorn sqlalchemy pymysql
''' 

from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import create_engine, text

engine = create_engine(
    "mysql+pymysql://app:ChangeMe123@127.0.0.1/social",
    pool_size=10, max_overflow=10, pool_pre_ping=True)
app = FastAPI()

class PostIn(BaseModel):
    user_id: int
    body: str

@app.post("/posts")
def create_post(p: PostIn):
    with engine.begin() as c:
        r = c.execute(text("INSERT INTO posts (user_id, body) VALUES (:u, :b)"),
                      {"u": p.user_id, "b": p.body})
        return {"id": r.lastrowid}

@app.get("/feed/{user_id}")
def feed(user_id: int, limit: int = 20):
    with engine.connect() as c:
        rows = c.execute(text("""
            SELECT p.id, p.user_id, p.body, p.created_at
            FROM posts p JOIN follows f ON f.followee_id = p.user_id
            WHERE f.follower_id = :u
            ORDER BY p.created_at DESC LIMIT :l"""),
            {"u": user_id, "l": limit}).mappings().all()
    return [dict(r) for r in rows]
