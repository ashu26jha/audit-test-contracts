from typing import List, Optional

from pydantic import BaseModel

from config.prompts.decide_action_prompts import DECIDE_ACTION_PROMPT
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding


class AutonomousAgentRequest(BaseModel):
    contracts: str
    findings: Optional[List[Finding]] = None
    max_steps: int
    llm: str


class AutonomousAgentResponse(BaseModel):
    data: str


class DecideActionResponse(BaseModel):
    tool: str
    reason: str
    instructions: str


class Vulnerability(BaseModel):
    title: str
    description: str
    severity: str
    proof_of_concept: str


class Vulnerabilities(BaseModel):
    vulnerabilities: List[Vulnerability]


class Agent:
    """
    Represents an agent that decides on and executes actions based.
        `llm`: The language model used for decision making.
        `max_steps`: Maximum number of steps (actions) to execute per intent.
        `previous_action_results`: List of previous action results.
        `summary`: Summary of the agent's actions, if context size is exceeded.
        `current_action`: The current action to execute.
    """

    def __init__(self, llm, max_steps, contracts):
        if not isinstance(contracts, str):
            raise ValueError("Contracts must be provided as a string")

        self.llm = llm
        self.previous_action_results = []
        self.summary = ""
        self.max_steps = max_steps
        self.current_action = None
        self.current_action_result = None
        self.current_step = 0
        self.agent_findings = []
        self.deduplicated_findings = []
        self.contracts = contracts
        self.tools = Tools()

    async def decide_action(self):
        """
        Decides on the next action to execute. It takes into account the previous actions and the contracts.
        It will return the next action to execute. Previous actions are provided.

        You can check the available tools using the Tools class:
            tools = Tools()
            available = tools.list_tools()
        """
        # Format history as a string if it's not empty
        history_str = (
            "\n".join(str(result) for result in self.previous_action_results)
            if self.previous_action_results
            else "No previous actions"
        )

        # Add current action and result to history
        if self.current_action and self.current_action_result:
            history_str += (
                "\n"
                + "Current action taken: "
                + self.current_action
                + "\n"
                + "Current action result: "
                + self.current_action_result
            )

        decide_action_prompt = DECIDE_ACTION_PROMPT.format(
            contracts=str(self.contracts),
            history=history_str,
            tools=self.tools.list_tool_descriptions(),
        )
        response = await send_prompt_to_llm_async(
            model_type=self.llm,
            messages=decide_action_prompt,
            response_model=DecideActionResponse,
        )
        return response

    async def execute_action(self):
        """
        Executes the current action.
        """
        pass

    async def summarize_actions(self):
        """
        Summarizes the action results.
        """
        pass

    async def deduplicate_findings(self):
        """
        Dedupe the findings.
        """
        pass

    async def find_vulnerabilities(self):
        """
        Find vulnerabilities in the contracts, based on the previous actions.
        This will be run at the end of runs also before generating the summary.
        """
        pass


class Tools:
    """
    Aggregates all available tools for the Autonomous Agent.
    """

    def __init__(self):
        from api.v1.tools.helpers.duckduckgo import search as duckduckgo_search

        self.duckduckgo_search = duckduckgo_search

    def list_tools(self) -> list:
        """
        Returns a list of available tool names.
        """
        return ["duckduckgo_search"]

    def list_tool_descriptions(self) -> str:
        """
        Returns a string containing the descriptions for all available tools.
        """
        from api.v1.tools.helpers.duckduckgo import get_description as duckduckgo_desc

        return "\n".join(
            [
                duckduckgo_desc(),
            ]
        )
