import os

import uvicorn

from injectprobe.dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()  # BOT_LLM and API keys may live in .env
    uvicorn.run("examples.hardened_bot.app:app", host="127.0.0.1", port=int(os.environ.get("PORT", "8001")))
