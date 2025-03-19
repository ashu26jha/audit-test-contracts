import json
from typing import Dict, List, Optional, Union

from api.v1.utilities.invariants.schema import InvariantsResponse
from config.prompts.cairo_prompt import CAIRO_PROMPT, CAIRO_SYSTEM_PROMPT
from config.prompts.context_scan_prompts import (
    CONTEXT_PROMPT,
    SYSTEM_PROMPT,
)
from config.settings import SUPPORTED_MODELS
from core.schemas.llm_schema import Message
from core.utils.profiles import Profiles, load_profile

EMPTY_RESPONSE = "None Given"


class PromptBuilder:
    def __init__(self):
        """Initialize with cached static data"""
        self._prompt_templates = {
            "context_scan_template": CONTEXT_PROMPT,
            "cairo_scan_template": CAIRO_PROMPT,
        }
        self._system_prompts = {
            "default": SYSTEM_PROMPT,
            "cairo": CAIRO_SYSTEM_PROMPT,
        }
        # Cache profiles
        self._profiles: Dict[Profiles, List[Message]] = {}

    def _ensure_profile_loaded(self, profile: Profiles) -> None:
        """Lazy load profile if not already cached"""
        if profile not in self._profiles:
            self._profiles[profile] = load_profile(profile)

    def build_messages(
        self,
        model_type: str,
        user_input: str,
        system_prompt: Optional[str] = None,
        message_history: Optional[List[Message]] = None,
        profile: Optional[Profiles] = None,
    ) -> Union[str, List[Message]]:
        """
        Build messages for LLM request. Can handle both context scans and standalone prompts.
        Returns either a string (Gemini) or list of messages (OpenAI/Anthropic).

        Args:
            model_type: The model to use
            user_input: The main prompt/user input
            system_prompt: Optional system prompt (overrides profile's system prompt)
            message_history: Optional message history (overrides profile's history)
            profile: Optional profile to use for system prompt and history
        """
        # Load profile if specified
        if profile is not None:
            self._ensure_profile_loaded(profile)
            profile_history = self._profiles[profile]
            # Use profile's system prompt if none provided
            if system_prompt is None and profile != Profiles.NONE:
                # Use Cairo system prompt for Cairo profile
                if profile == Profiles.CAIRO:
                    system_prompt = self._system_prompts["cairo"]
                else:
                    system_prompt = self._system_prompts["default"]
        else:
            profile_history = []

        # Use provided message history or profile's history
        final_history = message_history if message_history is not None else profile_history

        # Apply cache control to profile messages if using Anthropic
        if model_type in SUPPORTED_MODELS["anthropic"] and profile is not None:
            # Transform profile messages to include cache control
            final_history = self._add_cache_control_to_messages(final_history)

        # Handle different model types
        if model_type in SUPPORTED_MODELS["gemini"]:
            return self._build_gemini_format(user_input, system_prompt, final_history)

        # For OpenAI/Anthropic, build message list
        messages: List[Message] = []

        # Add system prompt if provided
        if system_prompt and model_type in SUPPORTED_MODELS["openai"]:
            role = "developer" if "o1" in model_type else "system"
            messages.append({"role": role, "content": system_prompt})

        # Add message history
        messages.extend(final_history)

        # Add user message
        messages.append({"role": "user", "content": user_input})

        return messages

    def build_context_scan_prompt(
        self,
        contracts: str,
        summary: Optional[str],
        docs: Optional[str],
        invariants: Optional[InvariantsResponse],
        duckduckgo_results: Optional[str] = None,
        contract_language: str = "solidity",
    ) -> str:
        """
        Build the context scan specific prompt

        Args:
            contracts: The flattened contracts to scan
            summary: The summary of the contracts (if any)
            docs: The documentation of the contracts (if any)
            invariants: The invariants of the contracts (if any)
            duckduckgo_results: The duckduckgo results of the contracts (if any)
            contract_language: The language of the contracts
        """

        # 1. Add summary as string if provided
        summary_str = summary or EMPTY_RESPONSE

        # 2. Add invariants as string if provided
        invariants_str = json.dumps(invariants.model_dump()) if invariants else EMPTY_RESPONSE

        # 3. Add duckduckgo results as string if provided
        duckduckgo_results_str = duckduckgo_results or EMPTY_RESPONSE

        # 4. Add docs as string if provided
        docs_str = docs.replace("```", "") if docs else EMPTY_RESPONSE

        # 5. Select the appropriate template based on contract language
        template_key = (
            "cairo_scan_template"
            if contract_language.lower() == "cairo"
            else "context_scan_template"
        )
        template = self._prompt_templates[template_key]

        return template.format(
            summary=summary_str,
            docs=docs_str,
            invariants=invariants_str,
            duckduckgo_results=duckduckgo_results_str,
            flattened_contracts=contracts,
        )

    def _add_cache_control_to_messages(self, messages: List[Message]) -> List[Message]:
        """Add cache_control to message content for Anthropic caching."""
        cached_messages = []

        for message in messages:
            # Clone the message to avoid modifying the original
            new_message = message.copy()

            # If message has content in string format, transform to structured format with cache control
            if "content" in new_message and isinstance(new_message["content"], str):
                new_message["content"] = [
                    {
                        "type": "text",
                        "text": new_message["content"],
                        "cache_control": {"type": "ephemeral"},
                    }
                ]

            cached_messages.append(new_message)

        return cached_messages

    def _build_gemini_format(
        self,
        prompt: str,
        system_prompt: Optional[str],
        message_history: List[Message],
    ) -> str:
        """Build Gemini-specific format, maintaining existing logic"""
        full_prompt = ""
        if system_prompt:
            full_prompt += f"System: {system_prompt}\n\n"

        for msg in message_history:
            full_prompt += f"{msg['role'].capitalize()}: {msg['content']}\n"

        full_prompt += f"User: {prompt}"
        return full_prompt
