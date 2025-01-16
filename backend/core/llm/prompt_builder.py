from typing import Dict, List, Optional, Union

from config.prompts.context_scan_prompts import (
    CONTEXT_PROMPT,
    CONTEXT_PROMPT_WITH_DOCS,
    SYSTEM_PROMPT,
)
from config.settings import SUPPORTED_MODELS
from core.schemas.llm_schema import Message
from core.utils.profiles import Profiles, load_profile


class PromptBuilder:
    def __init__(self):
        """Initialize with cached static data"""
        self._prompt_templates = {
            "with_docs": CONTEXT_PROMPT_WITH_DOCS,
            "without_docs": CONTEXT_PROMPT,
        }
        self._system_prompts = {"default": SYSTEM_PROMPT}
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
                system_prompt = self._system_prompts["default"]
        else:
            profile_history = []

        # Use provided message history or profile's history
        final_history = message_history if message_history is not None else profile_history

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
    ) -> str:
        """Build the context scan specific prompt"""
        template = self._prompt_templates["with_docs" if docs else "without_docs"]
        clean_docs = docs.replace("```", "") if docs else None

        return template.format(
            summary=summary,
            docs=clean_docs,
            flattened_contracts=contracts,
        )

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
