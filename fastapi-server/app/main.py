from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from database import engine, Base
import performance.item
import log.item
import rule.item
import agent.item
import config.item
import performance 
import log
import rule
import agent
import config

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Create the database tables
Base.metadata.create_all(bind=engine)
app = FastAPI(title="WAF", description="This is a WAF project", version="1.0.0")

@app.get("/")
def read_root():
    return {"message": "Hello World!"}


app.include_router(performance.item.router)
app.include_router(log.item.router)
app.include_router(rule.item.router)
app.include_router(agent.item.router)
app.include_router(config.item.router)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=5555, reload=True)

