from fastapi import APIRouter, Query
import sqlite3

from app.database import DB_PATH

router = APIRouter()


@router.get("/api/events")
def get_security_events(limit: int = Query(default=100, ge=1, le=500)):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT *
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]