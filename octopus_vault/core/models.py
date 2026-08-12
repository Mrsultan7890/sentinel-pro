from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

@dataclass
class Case:
    title: str
    description: str = ""
    status: str = "Active"
    id: Optional[int] = None
    created_at: Optional[str] = None

@dataclass
class Subject:
    case_id: int
    name: str
    aliases: str = ""
    emails: str = ""
    phones: str = ""
    usernames: str = ""
    addresses: str = ""
    notes: str = ""
    id: Optional[int] = None
    created_at: Optional[str] = None

@dataclass
class Evidence:
    case_id: int
    type: str
    title: str = ""
    content: str = ""
    source: str = ""
    file_path: str = ""
    tags: str = ""
    subject_id: Optional[int] = None
    id: Optional[int] = None
    created_at: Optional[str] = None

@dataclass
class TimelineEvent:
    case_id: int
    title: str
    description: str = ""
    event_date: str = ""
    linked_evidence_id: Optional[int] = None
    id: Optional[int] = None
    created_at: Optional[str] = None

@dataclass
class Note:
    case_id: int
    title: str = ""
    content: str = ""
    id: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

@dataclass
class Tag:
    name: str
    color: str = "#E94560"
    id: Optional[int] = None
