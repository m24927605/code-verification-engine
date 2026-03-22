from fastapi import FastAPI, Depends
from auth.middleware import require_auth

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/users/{user_id}")
def get_user(user_id: str, auth=Depends(require_auth)):
    return {"id": user_id}

@app.post("/users")
def create_user(auth=Depends(require_auth)):
    return {"id": "new"}
