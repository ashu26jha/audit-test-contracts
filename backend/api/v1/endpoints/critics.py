from fastapi import APIRouter, Depends, HTTPException
from services import critics_service
from api.v1.schemas import critics_schema

router = APIRouter()

@router.post("/critic", response_model=critics_schema.CriticReviewResponse)
async def create_critic_(review: critics_schema.CriticReviewCreate):
    try:
        created_review = await critics_service.apply_critic(review)
        return critics_schema.CriticReviewResponse(**created_review)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
