from pydantic import BaseModel
from typing import Optional
from datetime import date


class EmployeeCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    password: str

    role: Optional[str] = "employee"
    department: Optional[str] = None
    position: Optional[str] = None
    location: Optional[str] = None
    phone: Optional[str] = None
    status: Optional[str] = "active"
    join_date: Optional[date] = None