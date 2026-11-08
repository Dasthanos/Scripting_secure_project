"""Safer counterparts for the demonstration; these are examples, not a proof of safety."""
import json
import os
import ssl
import subprocess
import tempfile
import yaml


def search_users(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))


def run_tool(filename):
    # No shell: the argument is passed as data rather than shell syntax.
    subprocess.run(["cat", filename], check=True)


def read_settings(text):
    # JSON is a data format; validate the resulting shape before use.
    settings = json.loads(text)
    if not isinstance(settings, dict):
        raise ValueError("Expected a JSON object")
    return settings


def get_api_key():
    return os.environ.get("APP_API_KEY")


def read_configuration(untrusted_text):
    # Safe YAML loader treats the document as data rather than arbitrary objects.
    return yaml.safe_load(untrusted_text)


def create_secure_resources():
    tls_context = ssl.create_default_context()
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    return tls_context, temp_file.name
