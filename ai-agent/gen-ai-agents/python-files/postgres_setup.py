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
            id SERIAL PRIMARY KEY,
            source_ip VARCHAR(50),
            dest_ip VARCHAR(50),
            severity VARCHAR(20),
            confidence_score FLOAT,
            attack_types TEXT,
            total_events INT,
            rules_violated TEXT,
            timestamps TEXT,
            src_ips TEXT,
            dest_ips TEXT,
            ports TEXT,
            batch_time TIMESTAMP DEFAULT NOW(),
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("Table alert_batches created (if not exists).")

if __name__ == "__main__":
    create_table()