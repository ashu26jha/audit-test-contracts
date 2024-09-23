from datetime import datetime
from typing import Any, Optional

from bson import ObjectId
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    GetCoreSchemaHandler,
    GetJsonSchemaHandler,
    field_serializer,
)
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import core_schema


class PyObjectId(ObjectId):
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: Any, handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_plain_validator_function(cls.validate)

    @classmethod
    def __get_pydantic_json_schema__(
        cls, schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        return {"type": "string"}

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)


class UserBase(BaseModel):
    username: str
    email: EmailStr
    githubId: str
    avatarUrl: Optional[str] = None
    name: Optional[str] = None


class UserCreate(UserBase):
    accessToken: str


class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None


class UserInDB(UserBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    accessToken: str
    avatarUrl: Optional[str] = None
    name: Optional[str] = None
    createdAt: datetime
    updatedAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    @field_serializer("id")
    def serialize_object_id(self, object_id: PyObjectId):
        return str(object_id)


class UserResponse(UserBase):
    id: str

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
