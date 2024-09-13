from common.profiles import Profiles, load_profile
from config.settings import TEMPERATURE
from common.llm_clients import CLAUDE_CLIENT
from openai import AsyncOpenAI
from langfuse.decorators import langfuse_context
from api.v1.prompts.context_scan_prompts import system_prompt


async def send_prompt_to_llm_async(
    prompt, model_type, profile: Profiles = Profiles.NONE
):
    try:
        # langfuse_context.update_current_trace(tags=["code-auditor", model_type])

        messages = []
        system = None

        if profile != Profiles.NONE:
            system = system_prompt

        if system and "gpt-4o" in model_type:
            messages.append({"role": "system", "content": system})

        # Add the few-shot examples from the profile (if any)
        profile_messages = load_profile(profile)
        messages.extend(profile_messages)

        # Append the final user prompt
        messages.append({"role": "user", "content": prompt})

        if "gpt-4o" in model_type:
            async with AsyncOpenAI() as client:
                response = await client.chat.completions.create(
                    model=model_type,
                    messages=messages,
                    # max_tokens="None",
                    temperature=TEMPERATURE,
                    n=1,
                    stop=None,
                )
            return response.choices[0].message.content.strip()

        elif model_type in ["claude-3-5-sonnet-20240620", "claude-3-opus-20240229"]:
            # Claude Models
            response = await CLAUDE_CLIENT.messages.create(
                model=model_type,
                system=system if profile != Profiles.NONE else None,
                messages=messages,
                # max_tokens="None",
                temperature=TEMPERATURE,
            )

            # Update usage context
            langfuse_context.update_current_observation(
                model=model_type,
                usage={
                    "input": response.usage.input_tokens,
                    "output": response.usage.output_tokens,
                },
            )
            return response.content[0].text.strip()

        else:
            raise ValueError(f"Unsupported model type: {model_type}")

    except Exception as e:
        langfuse_context.update_current_trace(metadata={"error": str(e)})
        print(f"Error sending prompt to {model_type}: {e}")
        return None
