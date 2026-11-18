import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("examples.hardened_bot.app:app", host="127.0.0.1", port=int(os.environ.get("PORT", "8001")))
