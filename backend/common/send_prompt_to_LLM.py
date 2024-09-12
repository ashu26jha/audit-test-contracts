from common.llm_clients import CLAUDE_CLIENT
from openai import AsyncOpenAI
from langfuse.decorators import langfuse_context


async def send_prompt_to_llm_async(prompt, model_type):
    try:
        # langfuse_context.update_current_trace(tags=["code-auditor", model_type])

        if "gpt-4o" in model_type:
            async with AsyncOpenAI() as client:
                response = await client.chat.completions.create(
                    model=model_type,
                    messages=[{"role": "user", "content": prompt}],
                    # max_tokens="None",
                    temperature=0.2,
                    n=1,
                    stop=None,
                )
            return response.choices[0].message.content.strip()

        elif model_type in ["claude-3-5-sonnet-20240620", "claude-3-opus-20240229"]:
            # Claude Models
            response = await CLAUDE_CLIENT.messages.create(
                model=model_type,
                # max_tokens="None",
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}],
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
