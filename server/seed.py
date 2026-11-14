import random
from sqlalchemy import create_engine, text
e = create_engine("mysql+pymysql://app:ChangeMe123@127.0.0.1/social")
N = 10000
with e.begin() as c:
    c.execute(text("INSERT INTO users (name) VALUES (:n)"),
              [{"n": f"user{i}"} for i in range(N)])
    c.execute(text("INSERT IGNORE INTO follows VALUES (:a,:b)"),
              [{"a": i, "b": random.randint(1, N)} for i in range(1, N+1) for _ in range(50)])
    c.execute(text("INSERT INTO posts (user_id, body) VALUES (:u,:b)"),
              [{"u": random.randint(1, N), "b": "hello world " * 5} for _ in range(500000)])
