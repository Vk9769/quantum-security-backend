from pydantic import BaseModel, EmailStr


class EmployeeCreate(BaseModel):

    first_name: str
    last_name: str
    email: EmailStr
    password: str
    role: str = "employee"
    department: str | None = None
    phone: str | None = None