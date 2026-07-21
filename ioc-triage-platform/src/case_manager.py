"""
Case Management Module.

Implements a SQLite-based case management system that mirrors
real SOC investigation workflows. This is the feature that shows
you understand the full investigation lifecycle, not just enrichment.

Features:
- Case creation with auto-generated IDs
- IOC-to-case linking
- Status tracking (Open, In Progress, Closed, Escalated)
- Assignment and notes
- Evidence storage
- Timeline of investigation
"""

import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Literal
from dataclasses import dataclass, asdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)


@dataclass
class Case:
    """Represents a security investigation case."""
    case_id: str
    title: str
    status: Literal["Open", "In Progress", "Closed", "Escalated"]
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    created_at: str
    updated_at: str
    assigned_to: str = "Unassigned"
    ioc: str = ""
    ioc_type: str = ""
    recommendation: str = ""
    evidence: str = ""  # JSON string
    notes: str = ""
    tags: str = ""  # Comma-separated
    mitre_techniques: str = ""  # Comma-separated MITRE ATT&CK IDs

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def get_evidence(self) -> Dict[str, Any]:
        """Parse evidence JSON."""
        try:
            return json.loads(self.evidence) if self.evidence else {}
        except json.JSONDecodeError:
            return {}

    def get_tags(self) -> List[str]:
        """Get tags as list."""
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    def get_mitre_techniques(self) -> List[str]:
        """Get MITRE techniques as list."""
        return [t.strip() for t in self.mitre_techniques.split(",") if t.strip()]


class CaseManager:
    """
    SQLite-based case management system.

    Manages the full lifecycle of security investigations:
    creation → enrichment → scoring → assignment → closure
    """

    def __init__(self, db_path: Path = None):
        self.db_path = db_path or Path("cases.db")
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Open',
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    assigned_to TEXT DEFAULT 'Unassigned',
                    ioc TEXT,
                    ioc_type TEXT,
                    recommendation TEXT,
                    evidence TEXT,
                    notes TEXT,
                    tags TEXT,
                    mitre_techniques TEXT
                )
            """)

            # Timeline table for audit trail
            conn.execute("""
                CREATE TABLE IF NOT EXISTS case_timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT DEFAULT 'system',
                    details TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(case_id)
                )
            """)

            conn.commit()
            logger.info(f"Database initialized: {self.db_path}")

    def _generate_case_id(self) -> str:
        """Generate unique case ID: CASE-YYYYMMDD-XXXX"""
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d")

        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM cases WHERE case_id LIKE ?",
                (f"CASE-{date_str}-%",)
            )
            count = cursor.fetchone()[0] + 1

        return f"CASE-{date_str}-{count:04d}"

    def create_case(
        self,
        ioc: str,
        ioc_type: str,
        severity: str,
        recommendation: str,
        evidence: Dict[str, Any],
        title: str = None,
        tags: List[str] = None,
        mitre_techniques: List[str] = None
    ) -> Case:
        """
        Create a new investigation case.

        Args:
            ioc: The indicator of compromise
            ioc_type: Type of IOC (ip, domain, filehash, url)
            severity: Calculated severity level
            recommendation: Action recommendation
            evidence: Enrichment data from all sources
            title: Optional case title
            tags: Optional list of tags
            mitre_techniques: Optional MITRE ATT&CK technique IDs

        Returns:
            Created Case object
        """
        case_id = self._generate_case_id()
        now = datetime.now(timezone.utc).isoformat()

        case = Case(
            case_id=case_id,
            title=title or f"Investigation: {ioc}",
            status="Open",
            severity=severity,
            created_at=now,
            updated_at=now,
            ioc=ioc,
            ioc_type=ioc_type,
            recommendation=recommendation,
            evidence=json.dumps(evidence, default=str),
            tags=",".join(tags or []),
            mitre_techniques=",".join(mitre_techniques or [])
        )

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO cases (
                    case_id, title, status, severity, created_at, updated_at,
                    assigned_to, ioc, ioc_type, recommendation, evidence,
                    notes, tags, mitre_techniques
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case.case_id, case.title, case.status, case.severity,
                case.created_at, case.updated_at, case.assigned_to,
                case.ioc, case.ioc_type, case.recommendation,
                case.evidence, case.notes, case.tags, case.mitre_techniques
            ))

            # Add timeline entry
            conn.execute("""
                INSERT INTO case_timeline (case_id, timestamp, action, details)
                VALUES (?, ?, ?, ?)
            """, (case_id, now, "CASE_CREATED", f"Case opened for {ioc}"))

            conn.commit()

        logger.info(f"Case created: {case_id} for {ioc}")
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        """Retrieve a case by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()

            if row:
                return Case(**dict(row))
            return None

    def get_case_by_ioc(self, ioc: str) -> Optional[Case]:
        """Find case by IOC value."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM cases WHERE ioc = ? ORDER BY created_at DESC LIMIT 1",
                (ioc,)
            ).fetchone()

            if row:
                return Case(**dict(row))
            return None

    def update_status(
        self,
        case_id: str,
        new_status: Literal["Open", "In Progress", "Closed", "Escalated"],
        actor: str = "analyst",
        notes: str = ""
    ) -> bool:
        """Update case status with audit trail."""
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
                (new_status, now, case_id)
            )

            if cursor.rowcount == 0:
                return False

            conn.execute("""
                INSERT INTO case_timeline (case_id, timestamp, action, actor, details)
                VALUES (?, ?, ?, ?, ?)
            """, (case_id, now, f"STATUS_CHANGED_TO_{new_status.upper()}", actor, notes))

            conn.commit()

        logger.info(f"Case {case_id} status updated to {new_status}")
        return True

    def assign_case(self, case_id: str, analyst: str) -> bool:
        """Assign case to an analyst."""
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE cases SET assigned_to = ?, updated_at = ? WHERE case_id = ?",
                (analyst, now, case_id)
            )

            if cursor.rowcount == 0:
                return False

            conn.execute("""
                INSERT INTO case_timeline (case_id, timestamp, action, actor, details)
                VALUES (?, ?, ?, ?, ?)
            """, (case_id, now, "ASSIGNED", "system", f"Assigned to {analyst}"))

            conn.commit()

        logger.info(f"Case {case_id} assigned to {analyst}")
        return True

    def add_note(self, case_id: str, note: str, actor: str = "analyst") -> bool:
        """Add investigation note to case."""
        now = datetime.now(timezone.utc).isoformat()

        with self._get_connection() as conn:
            # Get existing notes
            row = conn.execute(
                "SELECT notes FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()

            if not row:
                return False

            existing = row["notes"] or ""
            new_notes = f"{existing}\n[{now}] {actor}: {note}".strip()

            conn.execute(
                "UPDATE cases SET notes = ?, updated_at = ? WHERE case_id = ?",
                (new_notes, now, case_id)
            )

            conn.execute("""
                INSERT INTO case_timeline (case_id, timestamp, action, actor, details)
                VALUES (?, ?, ?, ?, ?)
            """, (case_id, now, "NOTE_ADDED", actor, note[:200]))

            conn.commit()

        return True

    def get_timeline(self, case_id: str) -> List[Dict[str, Any]]:
        """Get investigation timeline for a case."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM case_timeline WHERE case_id = ? ORDER BY timestamp",
                (case_id,)
            ).fetchall()

            return [dict(row) for row in rows]

    def list_cases(
        self,
        status: str = None,
        severity: str = None,
        assigned_to: str = None,
        limit: int = 100
    ) -> List[Case]:
        """List cases with optional filters."""
        query = "SELECT * FROM cases WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if assigned_to:
            query += " AND assigned_to = ?"
            params.append(assigned_to)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [Case(**dict(row)) for row in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Get case management statistics."""
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]

            status_counts = conn.execute("""
                SELECT status, COUNT(*) as count FROM cases GROUP BY status
            """).fetchall()

            severity_counts = conn.execute("""
                SELECT severity, COUNT(*) as count FROM cases GROUP BY severity
            """).fetchall()

            open_cases = conn.execute(
                "SELECT COUNT(*) FROM cases WHERE status = 'Open'"
            ).fetchone()[0]

            escalated = conn.execute(
                "SELECT COUNT(*) FROM cases WHERE status = 'Escalated'"
            ).fetchone()[0]

        return {
            "total_cases": total,
            "open_cases": open_cases,
            "escalated_cases": escalated,
            "by_status": {row["status"]: row["count"] for row in status_counts},
            "by_severity": {row["severity"]: row["count"] for row in severity_counts}
        }

    def export_case_report(self, case_id: str) -> Dict[str, Any]:
        """Generate comprehensive case report."""
        case = self.get_case(case_id)
        if not case:
            return {"error": "Case not found"}

        timeline = self.get_timeline(case_id)

        return {
            "case": case.to_dict(),
            "evidence": case.get_evidence(),
            "timeline": timeline,
            "tags": case.get_tags(),
            "mitre_techniques": case.get_mitre_techniques()
        }
