import os

# Never let a developer's real .env (API keys) leak into the test run.
os.environ["INJECTPROBE_NO_DOTENV"] = "1"
