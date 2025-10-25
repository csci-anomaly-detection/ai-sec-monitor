import psycopg2
import os

def create_table():
    conn = psycopg2.connect(
        dbname=os.getenv("POSTGRES_DB", "alertsdb"),
        user=os.getenv("POSTGRES_USER", "myuser"),
        password=os.getenv("POSTGRES_PASSWORD", "mypassword"),
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432")
    )
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alert_batches (
            batch_id SERIAL PRIMARY KEY,
            signature_id INT NOT NULL,
            signature TEXT NOT NULL,
            mitre_id TEXT,
            alert_count INT NOT NULL,
            src_ips JSONB,
            dst_ips JSONB,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("Table alert_batches created (if not exists).")

if __name__ == "__main__":
    create_table()