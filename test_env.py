# test_env.py
import os
from dotenv import load_dotenv

load_dotenv()

print("DATABASE_URL:", os.environ.get("DATABASE_URL"))
print("SECRET_KEY:", os.environ.get("SECRET_KEY"))
print("MAIL_USERNAME:", os.environ.get("MAIL_USERNAME"))
print("Current directory:", os.getcwd())
