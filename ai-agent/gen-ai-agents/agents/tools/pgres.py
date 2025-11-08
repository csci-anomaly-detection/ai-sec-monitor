import psycopg2
import os
import json
from datetime import datetime, date

def run_query(query, params=None):
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        user=os.getenv("POSTGRES_USER", "myuser"),
        password=os.getenv("POSTGRES_PASSWORD", "mypassword"),
        dbname=os.getenv("POSTGRES_DB", "alertsdb")
    )
    cur = conn.cursor()
    cur.execute(query, params or ())
    
    if cur.description:  # SELECT query
        columns = [desc[0] for desc in cur.description]
        results = []
        for row in cur.fetchall():
            # Convert datetime/date objects to ISO strings
            row_dict = {}
            for col, val in zip(columns, row):
                if isinstance(val, (datetime, date)):
                    row_dict[col] = val.isoformat()
                else:
                    row_dict[col] = val
            results.append(row_dict)
        cur.close()
        conn.close()
        return results
    else:  # INSERT/UPDATE/DELETE
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "success", "rowcount": cur.rowcount}
