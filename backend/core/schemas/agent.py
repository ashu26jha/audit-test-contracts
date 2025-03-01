from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger

# Define a type variable for the response model
ResponseType = TypeVar("ResponseType", bound=BaseModel)


class Agent(BaseModel, Generic[ResponseType]):
    """
    A base Agent class for all agents that encapsulates interaction with an LLM.
    Agents can hold prompts, call external tools, store memory, and parse responses.
    """

    name: str = Field(default="Agent", description="Name of the agent")
    description: str = Field(
        default="", description="A short description of the agent's responsibilities"
    )
    prompt: str = Field(default="", description="Prompt of the agent")
    model: str = Field(default=LLM_UTILITY, description="LLM model of the agent")
    steps: int = Field(default=1, description="Number of steps the agent is allowed to take")
    tools: List = Field(default_factory=list, description="A list of tools the agent can invoke")
    response_model: type[ResponseType] = Field(
        description="A Pydantic model used to parse the LLM response"
    )
    thinking: Optional[bool] = Field(
        default=False, description="Whether the agent should think before responding"
    )

    class Config:
        arbitrary_types_allowed = True

    async def run(self) -> ResponseType:
        """
        Sends the stored prompt to the LLM and returns the parsed response.

        Returns:
            ResponseType: The parsed response from the LLM
        """
        response = await send_prompt_to_llm_async(
            model_type=self.model,
            messages=self.prompt,
            response_model=self.response_model,
            thinking=self.thinking,
        )

        logger.info(f"[Agent] {self.name} responded successfully")
        return response
