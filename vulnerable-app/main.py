"""
EFEX Transfer Microservice - VULNERABLE SEED
============================================
Este microservicio contiene vulnerabilidades INTENCIONALES para demostrar
el pipeline DevSecOps. NO usar en produccion.

Vulnerabilidades incluidas:
- EFEX-VULN-001: Hardcoded secrets (API keys, DB passwords)
- EFEX-VULN-002: SQL Injection
- EFEX-VULN-003: Command Injection
- EFEX-VULN-004: Insecure Deserialization (YAML)
- EFEX-VULN-005: Sensitive data exposure in logs
"""

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
import sqlite3
import subprocess
import yaml
import logging
import os

app = FastAPI(
    title="EFEX Transfer Service",
    description="Internal transfer processing API",
    version="1.0.0"
)

# ============================================================================
# EFEX-VULN-001: Hardcoded Secrets
# Detectado por: gitleaks
# Regulacion: SOC 2 CC6.1, CNBV Art. 316 Bis
# Riesgo: Acceso no autorizado a sistemas financieros, robo de fondos
# ============================================================================
# NOTE: These are INTENTIONALLY FAKE secrets for DevSecOps demonstration
# They follow patterns that security scanners detect but are not real credentials
DATABASE_PASSWORD = "EXAMPLE_efex_pr0d_password_123"  # nosec: intentional demo
STRIPE_API_KEY = "sk_test_EXAMPLE1234567890abcdefghijklmnop"  # nosec: test key pattern
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"  # nosec: AWS documented example key
SPEI_API_TOKEN = "spei_test_EXAMPLE_9f8e7d6c5b4a"  # nosec: intentional demo
JWT_SECRET = "EXAMPLE-jwt-secret-for-demo-only"  # nosec: intentional demo

# Database connection with hardcoded credentials
DB_CONNECTION_STRING = f"mysql://efex_admin:{DATABASE_PASSWORD}@prod-db.efex.internal:3306/transfers"

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TransferRequest(BaseModel):
    source_clabe: str
    destination_clabe: str
    amount: float
    reference: str
    beneficiary_name: Optional[str] = None


class AccountQuery(BaseModel):
    account_id: str
    format: Optional[str] = "json"


def get_db_connection():
    """Simulated database connection."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY,
            source_clabe TEXT,
            destination_clabe TEXT,
            amount REAL,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            clabe TEXT,
            balance REAL,
            owner_name TEXT,
            owner_rfc TEXT,
            kyc_status TEXT
        )
    """)
    # Insert sample data
    cursor.execute("""
        INSERT INTO accounts (clabe, balance, owner_name, owner_rfc, kyc_status)
        VALUES ('646180123456789012', 50000.00, 'Juan Perez', 'PEPJ800101XXX', 'VERIFIED')
    """)
    conn.commit()
    return conn


# ============================================================================
# EFEX-VULN-002: SQL Injection
# Detectado por: Semgrep (python.lang.security.audit.formatted-sql-query)
# Regulacion: OWASP A03:2021, SOC 2 CC6.6
# Riesgo: Extraccion de datos KYC/AML, manipulacion de saldos
# ============================================================================
@app.get("/api/v1/accounts/{account_id}")
def get_account(account_id: str):
    """
    Retrieve account details by CLABE.
    VULNERABLE: SQL injection via account_id parameter.

    Exploit example: /api/v1/accounts/' OR '1'='1' --
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: String concatenation in SQL query
    query = f"SELECT * FROM accounts WHERE clabe = '{account_id}'"
    logger.debug(f"Executing query: {query}")  # EFEX-VULN-005: Logging sensitive data

    cursor.execute(query)
    result = cursor.fetchone()

    if not result:
        raise HTTPException(status_code=404, detail="Account not found")

    return {
        "clabe": result[1],
        "balance": result[2],
        "owner_name": result[3],
        "kyc_status": result[5]
    }


@app.get("/api/v1/transfers/search")
def search_transfers(
    status: str = Query(..., description="Transfer status"),
    limit: int = Query(10, description="Max results")
):
    """
    Search transfers by status.
    VULNERABLE: SQL injection via status parameter.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: f-string SQL
    query = f"SELECT * FROM transfers WHERE status = '{status}' LIMIT {limit}"
    cursor.execute(query)

    return {"transfers": cursor.fetchall()}


# ============================================================================
# EFEX-VULN-003: Command Injection
# Detectado por: Semgrep (python.lang.security.audit.subprocess-shell-true)
# Regulacion: OWASP A03:2021, CWE-78
# Riesgo: RCE, acceso a infraestructura interna, lateral movement
# ============================================================================
@app.get("/api/v1/reports/generate")
def generate_report(report_type: str, date: str):
    """
    Generate a report for the given date.
    VULNERABLE: Command injection via report_type parameter.

    Exploit example: /api/v1/reports/generate?report_type=daily;cat /etc/passwd&date=2024-01-01
    """
    # VULNERABLE: shell=True with user input
    command = f"python generate_report.py --type {report_type} --date {date}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    return {
        "status": "generated",
        "output": result.stdout,
        "command": command  # VULNERABLE: Exposing internal commands
    }


@app.post("/api/v1/export")
def export_data(filename: str):
    """
    Export data to a file.
    VULNERABLE: Command injection via filename.

    NOTE: This is INTENTIONALLY VULNERABLE for DevSecOps demonstration.
    """
    # VULNERABLE: Unsanitized input in shell command
    # Using subprocess for the demo (os.system equivalent vulnerability)
    cmd = f"mysqldump -u efex_admin -p{DATABASE_PASSWORD} transfers > /tmp/{filename}"
    subprocess.run(cmd, shell=True)

    return {"status": "exported", "file": filename}


# ============================================================================
# EFEX-VULN-004: Insecure Deserialization (YAML)
# Detectado por: Semgrep, Bandit
# CVE relacionado: CVE-2020-14343 (PyYAML)
# Riesgo: Remote Code Execution
# ============================================================================
@app.post("/api/v1/config/import")
def import_config(config_yaml: str):
    """
    Import configuration from YAML.
    VULNERABLE: yaml.load without safe_load allows arbitrary code execution.

    Exploit payload:
    !!python/object/apply:os.system ['id']
    """
    # VULNERABLE: yaml.load without Loader (allows arbitrary Python execution)
    config = yaml.load(config_yaml)

    return {"status": "imported", "config": str(config)}


@app.post("/api/v1/transfers")
def create_transfer(transfer: TransferRequest):
    """
    Create a new SPEI transfer.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # VULNERABLE: Logging sensitive financial data
    logger.info(f"Creating transfer: {transfer.source_clabe} -> {transfer.destination_clabe}, amount: {transfer.amount}")
    logger.debug(f"Using API token: {SPEI_API_TOKEN}")  # EFEX-VULN-005

    # This would normally call the SPEI API
    cursor.execute("""
        INSERT INTO transfers (source_clabe, destination_clabe, amount, status)
        VALUES (?, ?, ?, 'PENDING')
    """, (transfer.source_clabe, transfer.destination_clabe, transfer.amount))

    conn.commit()
    transfer_id = cursor.lastrowid

    return {
        "transfer_id": transfer_id,
        "status": "PENDING",
        "tracking_key": f"EFEX{transfer_id:012d}"
    }


@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "database": "connected"
    }


@app.get("/debug/config")
def debug_config():
    """
    Debug endpoint exposing configuration.
    VULNERABLE: Exposes secrets in API response.
    """
    return {
        "database_url": DB_CONNECTION_STRING,
        "stripe_key_prefix": STRIPE_API_KEY[:20],  # Still leaks partial key
        "environment": "production",
        "debug": True  # VULNERABLE: Debug enabled in prod
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
