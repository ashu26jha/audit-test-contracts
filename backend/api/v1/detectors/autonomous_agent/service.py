from api.v1.tools.service import duckduckgo_search_service
from core.utils.logger import logger

from .schema import Agent, AutonomousAgentRequest


async def autonomous_agent_service(request: AutonomousAgentRequest):
    agent = Agent(llm=request.llm, max_steps=request.max_steps, contracts=request.contracts)

    while agent.current_step < agent.max_steps:
        agent.current_action = await agent.decide_action()
        logger.info(
            f"Decided to use {agent.current_action.tool} with reason: {agent.current_action.reason} and instructions: {agent.current_action.instructions}"
        )
        if agent.current_action.tool == "duckduckgo_search":
            result = await duckduckgo_search_service(agent.current_action.instructions)
        # Increment step
        agent.current_action_result = result
        agent.previous_action_results.append(result)
        agent.current_step += 1
