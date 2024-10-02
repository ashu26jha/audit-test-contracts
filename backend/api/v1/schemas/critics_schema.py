from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class CriticReviewBase(BaseModel):
    movie_id: int = Field(..., description="ID of the movie being reviewed")
    critic_name: str = Field(..., description="Name of the critic")
    review_text: str = Field(..., description="The full text of the review")
    rating: float = Field(..., ge=0, le=10, description="Rating out of 10")


class CriticReviewCreate(CriticReviewBase):
    pass


class CriticReviewResponse(CriticReviewBase):
    id: int = Field(..., description="Unique ID of the critic")
    createdAt: datetime = Field(..., description="Timestamp of when the critic was created")
