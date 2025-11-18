"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
Each class name maps to a collection with its lowercase name.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal

# Users with roles
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt hash of password")
    role: Literal['client','employee','admin'] = Field('client', description="User role")
    is_active: bool = Field(True)

# Public agent catalog
class Agent(BaseModel):
    name: str
    price: float = Field(..., ge=0)
    rating: float = Field(..., ge=0, le=5)
    skills: List[str] = Field(default_factory=list)
    problems: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    featured: bool = True

# Simple comparison list stored per user (optional)
class CompareItem(BaseModel):
    user_id: Optional[str] = None
    agent_ids: List[str] = Field(default_factory=list)
