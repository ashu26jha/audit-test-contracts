from common.logger import logger
from api.v1.schemas.critics_schema import CriticReviewCreate


async def apply_critic(review: CriticReviewCreate) -> dict:
    logger.info(f"Applying critic")
    
    # Dummy logic - replace with actual database insertion
    
    return 'Critic applied'