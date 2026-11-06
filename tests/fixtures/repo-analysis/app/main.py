"""Synthetic migration-risk fixture. Never run or deploy this file."""
# ruff: noqa: F401, I001, S105

import boto3
import sqlite3

REGION = "ap-northeast-1"
API_TOKEN = "demo-value-never-a-real-credential"  # Deliberately fake, used for redaction tests.

database = sqlite3.connect("state.db")
with open("cache.json", "w") as output:
    output.write("demo")
