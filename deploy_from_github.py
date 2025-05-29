import os
import subprocess

# Step into your project directory
project_dir = "/home/felixkirui/flasky_blog"
os.chdir(project_dir)

# Pull latest changes from GitHub
subprocess.run(["git", "pull"])

# Touch wsgi.py to reload the web app
subprocess.run(["touch", "/var/www/felixkirui_pythonanywhere_com_wsgi.py"])
