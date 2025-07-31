from fastapi import FastAPI
from routes import router

app = FastAPI(title="Palisade Moderation API")

app.include_router(router)

@app.get("/")
def health():
    return {"status": "ok"}
