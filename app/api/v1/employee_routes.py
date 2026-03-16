from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import uuid4, UUID

from app.db.postgres import get_db
from app.models.employee import Employee
from app.schemas.employee_schema import EmployeeCreate
from app.core.auth import hash_password

router = APIRouter()


# ===============================
# GET ALL EMPLOYEES
# ===============================
@router.get("/")
def get_employees(
    organization_id: UUID,
    db: Session = Depends(get_db)
):
    employees = db.query(Employee).filter(
        Employee.organization_id == organization_id
    ).all()

    return employees


# ===============================
# ADD EMPLOYEE
# ===============================
@router.post("/add")
def add_employee(
    data: EmployeeCreate,
    organization_id: UUID,
    db: Session = Depends(get_db)
):

    # Check if employee email already exists
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
        role=data.role or "employee",
        department=data.department,
        position=data.position,
        location=data.location,
        status=data.status if data.status else "active",
        phone=data.phone,
        join_date=data.join_date
    )

    db.add(employee)
    db.commit()
    db.refresh(employee)

    return {
        "message": "Employee created successfully",
        "employee_id": str(employee.id)
    }