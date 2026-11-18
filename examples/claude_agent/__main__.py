"""Serve the Claude agent: python -m examples.claude_agent  (http://127.0.0.1:8010/chat/<model>)"""

import os

import uvicorn

if __name__ == "__main__":
    uvicorn.run("examples.claude_agent.agent:app", host="127.0.0.1", port=int(os.environ.get("PORT", "8010")))
