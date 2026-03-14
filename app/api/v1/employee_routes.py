from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import uuid4

from app.db.postgres import get_db
from app.models.employee import Employee
from app.schemas.employee_schema import EmployeeCreate
from app.core.auth import hash_password

router = APIRouter()


@router.post("/employees/add")
def add_employee(
    data: EmployeeCreate,
    organization_id: str,  # passed from frontend or token later
    db: Session = Depends(get_db)
):

    # Check if employee email already exists in this company
    existing = db.query(Employee).filter(
        Employee.email == data.email,
        Employee.organization_id == organization_id
    ).first()

    if existing:
        raise HTTPException(status_code=400, detail="Employee already exists")

    employee = Employee(
        id=uuid4(),
        organization_id=organization_id,
        first_name=data.first_name,
        last_name=data.last_name,
        email=data.email,
        password_hash=hash_password(data.password),
        role=data.role,
        department=data.department,
        phone=data.phone
    )

    db.add(employee)
    db.commit()

    return {
        "message": "Employee created successfully"
    }