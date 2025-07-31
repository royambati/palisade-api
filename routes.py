from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import openai
from config import OPENAI_API_KEY

router = APIRouter()

client = openai.OpenAI(api_key=OPENAI_API_KEY)

class TextInput(BaseModel):
    text: str

class ImageInput(BaseModel):
    image_url: str

class Message(BaseModel):
    sender_id: str
    content: str
    timestamp: Optional[str] = None

class ContextualInput(BaseModel):
    conversation_id: str
    messages: List[Message]

@router.post("/moderate/text")
async def moderate_text(input: TextInput):
    try:
        response = client.moderations.create(input=input.text)
        result = response.results[0]

        flagged = result.flagged
        categories = [cat for cat, val in dict(result.categories).items() if val]
        max_score = max(dict(result.category_scores).values())

        return {
            "safe": not flagged,
            "categories": categories,
            "confidence": round(max_score, 3),
            "suggested_action": "block" if flagged else "allow"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/moderate/image")
async def moderate_image(input: ImageInput):
    try:
        # Load image from URL
        image_url = input.image_url

        # Call OpenAI Vision
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "user",
                    "content": [
                        { "type": "text", "text": (
                            "Moderate this image. Is there any nudity, violence, gore, or explicit content? "
                            "Return only a JSON object like this: {\"safe\": true, \"categories\": [\"nudity\"], \"confidence\": 0.95, \"suggested_action\": \"block\"}. No explanation, just the JSON."

                        )},
                        { "type": "image_url", "image_url": { "url": image_url } }
                    ]
                }
            ],
            max_tokens=300
        )

        # Parse the assistant's message content as JSON
        import json
        result_text = response.choices[0].message.content
        result = json.loads(result_text)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image moderation failed: {str(e)}")

@router.post("/moderate/contextual")
async def moderate_contextual(input: ContextualInput):
    try:
        messages_formatted = "\n".join(
            [f"{m.timestamp} - {m.sender_id}: {m.content}" for m in input.messages]
        )

        system_prompt = (
            "You are a trust & safety analyst. Analyze the following conversation for grooming, manipulation, "
            "harassment, power imbalance, or any kind of risk.\n\n"
            "Return only a JSON object with:\n"
            "{"
            "\"safe\": true/false, "
            "\"risk_factors\": [\"string\"], "
            "\"suggested_action\": \"allow/escalate/block\""
            "}\n\n"
            "DO NOT include any explanation. ONLY return the JSON."
        )

        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": messages_formatted}
            ],
            max_tokens=300
        )

        import json
        result_text = response.choices[0].message.content
        result = json.loads(result_text)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Contextual moderation failed: {str(e)}")
