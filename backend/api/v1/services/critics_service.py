from __future__ import annotations

from api.v1.schemas.critics_schema import CriticReviewCreate
from common.logger import logger


async def apply_critic(review: CriticReviewCreate) -> dict:
    logger.info(f"Applying critic: {review}")

    # Dummy logic - replace with actual database insertion

    return "Critic applied"
