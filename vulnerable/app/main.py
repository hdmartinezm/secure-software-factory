"""
EFEX Transfer Microservice - VULNERABLE VERSION (DEMO)
=======================================================
This file contains INTENTIONAL vulnerabilities for demonstration purposes.
All secrets are FAKE demo values that will be detected by security scanners.

DO NOT USE IN PRODUCTION - For educational purposes only.

Vulnerabilities present:
- EFEX-VULN-001: Hardcoded secrets (demo values)
- EFEX-VULN-002: SQL Injection
- EFEX-VULN-003: Command Injection
- EFEX-VULN-004: Insecure YAML deserialization
- EFEX-VULN-005: Sensitive data in logs
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import sqlite3
import subprocess
import yaml
import logging

app = FastAPI(
    title="EFEX Transfer Service",
    description="Internal transfer processing API",
    version="1.0.0"
)

# =============================================================================
# EFEX-VULN-001: Hardcoded Secrets (DEMO VALUES - NOT REAL)
# These are intentionally detectable by Gitleaks/Semgrep
# =============================================================================
DATABASE_PASSWORD = "HARDCODED_SECRET_FOR_DEMO_efex2024"
SPEI_API_TOKEN = "DEMO_API_KEY_spei_tk_12345678"
JWT_SECRET_KEY = "DEMO_JWT_SECRET_super_insecure_key"
STRIPE_KEY = "sk_test_DEMO_KEY_not_real_abcdef123456"
AWS_ACCESS_KEY = "AKIADEMO12345EXAMPLE"
AWS_SECRET_KEY = "DEMO_SECRET_wJalrXUtnFEMI_K7MDENG_bPxRfiCY"

# Database connection with hardcoded credentials
DATABASE_URL = f"postgresql://efex_admin:{DATABASE_PASSWORD}@db.efex.mx:5432/transfers"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TransferRequest(BaseModel):
    source_clabe: str
    destination_clabe: str
    amount: float
    reference: str
    beneficiary_name: Optional[str] = None


def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY,
            source_clabe TEXT,
            destination_clabe TEXT,
            amount REAL,
            status TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            clabe TEXT,
            balance REAL,
            owner_name TEXT,
            owner_rfc TEXT
        )
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO accounts VALUES
        (1, '646180123456789012', 50000.00, 'Juan Perez', 'PEPJ800101XXX')
    """)
    conn.commit()
    return conn


# =============================================================================
# EFEX-VULN-002: SQL Injection
# User input concatenated directly into SQL query
# =============================================================================
@app.get("/api/v1/accounts/{account_id}")
def get_account(account_id: str):
    """
    VULNERABLE: SQL Injection via string concatenation.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: Direct string concatenation allows SQL injection
    query = f"SELECT * FROM accounts WHERE clabe = '{account_id}'"
    cursor.execute(query)

    result = cursor.fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")

    return {
        "clabe": result[1],
        "balance": result[2],
        "owner_name": result[3],
        "owner_rfc": result[4]
    }


@app.get("/api/v1/transfers/search")
def search_transfers(status: str, limit: int = 10):
    """
    VULNERABLE: SQL Injection via f-string.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: User input in f-string
    query = f"SELECT * FROM transfers WHERE status = '{status}' LIMIT {limit}"
    cursor.execute(query)

    return {"transfers": cursor.fetchall()}


# =============================================================================
# EFEX-VULN-003: Command Injection
# User input passed to shell without sanitization
# =============================================================================
@app.post("/api/v1/reports/generate")
def generate_report(report_type: str, date: str):
    """
    VULNERABLE: Command injection via shell=True.
    """
    # VULNERABLE: shell=True with user input allows command injection
    command = f"python generate_report.py --type {report_type} --date {date}"
    result = subprocess.run(command, shell=True, capture_output=True)

    return {"status": "generated", "output": result.stdout.decode()}


# =============================================================================
# EFEX-VULN-004: Insecure Deserialization
# yaml.load without safe_load allows arbitrary code execution
# =============================================================================
@app.post("/api/v1/config/import")
def import_config(config_yaml: str):
    """
    VULNERABLE: yaml.load can execute arbitrary Python code.
    """
    # VULNERABLE: yaml.load (not safe_load) allows code execution
    config = yaml.load(config_yaml, Loader=yaml.Loader)

    return {"status": "imported", "config": config}


# =============================================================================
# EFEX-VULN-005: Sensitive Data in Logs
# Logging passwords, tokens, and PII
# =============================================================================
@app.post("/api/v1/transfers")
def create_transfer(transfer: TransferRequest):
    """
    VULNERABLE: Logs sensitive data including tokens and PII.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: Logging sensitive data
    logger.debug(f"Processing transfer with API token: {SPEI_API_TOKEN}")
    logger.info(f"Transfer from {transfer.source_clabe} to {transfer.destination_clabe}")
    logger.info(f"Amount: {transfer.amount}, Beneficiary: {transfer.beneficiary_name}")
    logger.debug(f"Using database password: {DATABASE_PASSWORD}")

    cursor.execute("""
        INSERT INTO transfers (source_clabe, destination_clabe, amount, status)
        VALUES (?, ?, ?, 'PENDING')
    """, (transfer.source_clabe, transfer.destination_clabe, transfer.amount))

    conn.commit()

    return {
        "transfer_id": cursor.lastrowid,
        "status": "PENDING"
    }


# VULNERABLE: Debug endpoint exposing all secrets
@app.get("/debug/config")
def debug_config():
    """
    VULNERABLE: Exposes all configuration including secrets.
    Should never exist in production.
    """
    return {
        "database_url": DATABASE_URL,
        "database_password": DATABASE_PASSWORD,
        "spei_token": SPEI_API_TOKEN,
        "jwt_secret": JWT_SECRET_KEY,
        "stripe_key": STRIPE_KEY,
        "aws_access_key": AWS_ACCESS_KEY,
        "aws_secret_key": AWS_SECRET_KEY
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    # VULNERABLE: Debug mode enabled in production
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
