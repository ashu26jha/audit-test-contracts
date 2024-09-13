from common.profiles import Profiles, load_profile
from config.settings import TEMPERATURE, SUPPORTED_OPENAI_MODELS
from common.llm_clients import CLAUDE_CLIENT
from openai import AsyncOpenAI
from langfuse.decorators import langfuse_context
import json

def return_role_prompt(role, input):
    return {
        "role": role,
        "content": [
            {
                "type": "text",
                "text": input
            }
        ]
    }

def build_messages_openai(input, system_prompt, message_pair):
    messages = []

    # Add system prompt if exists
    if system_prompt:
        messages.append(return_role_prompt('system', system_prompt))
    
    # If there exists a message pair for few-shot add to the message array
    if message_pair:
        messages.extend(message_pair)

    messages.append(return_role_prompt('user',input))

    return messages

def build_messages_anthropic(input, message_pair):    
    message_pair.append(return_role_prompt('user',input))
    return message_pair

async def send_prompt_to_LLM_async(
    model_type, input, system_prompt = "", message_pair = []
):
    try:

        if model_type in SUPPORTED_OPENAI_MODELS:
            messages = build_messages_openai(input, system_prompt, message_pair)
            async with AsyncOpenAI() as client:
                if model_type in ["o1-preview", "o1-mini" ]:
                    message_pair.append(return_role_prompt('user', input))
                    response = await client.chat.completions.create(
                        model=model_type,
                        messages=message_pair
                    )
                else:
                    response = await client.chat.completions.create(
                        model=model_type,
                        messages=messages,
                        temperature=TEMPERATURE,
                        n=1,
                        stop=None,
                    )
            return response.choices[0].message.content.strip()

        elif model_type in ["claude-3-5-sonnet-20240620", "claude-3-opus-20240229"]:
            messages = build_messages_anthropic(input, message_pair)
            response = CLAUDE_CLIENT.messages.create(
                model=model_type,
                system=system_prompt,
                messages=messages,
                max_tokens=8192,
                temperature=TEMPERATURE,
            )
            content = response.content[0].text.strip()

            langfuse_context.update_current_observation(
                model=model_type,
                usage={
                    "input": response.usage.input_tokens,
                    "output": response.usage.output_tokens,
                },
            )
            return content
    except Exception as e:
        langfuse_context.update_current_trace(metadata={"error": str(e)})
        print(f"Error sending prompt to {model_type}: {e}")
        return None
