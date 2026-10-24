"""Model backends. 'offline' needs no key; 'anthropic' and 'openai' (any OpenAI-compatible endpoint) use your own key."""
from __future__ import annotations
import json, os, re, urllib.request


class OfflineBackend:
    name = "offline"
    tokens = 0

    def __init__(self, sabotage=None):
        self.sabotage = sabotage or {}


class AnthropicBackend:
    name = "anthropic"
    tokens = 0

    def __init__(self):
        import anthropic  # pip install anthropic
        self.client = anthropic.Anthropic()
        self.model = os.environ.get("PATCHSENTINEL_MODEL", "claude-sonnet-5-5")

    def complete(self, system: str, user: str) -> str:
        r = self.client.messages.create(model=self.model, max_tokens=4096, system=system,
                                        messages=[{"role": "user", "content": user}])
        self.tokens += getattr(r.usage, "input_tokens", 0) + getattr(r.usage, "output_tokens", 0)
        return "".join(b.text for b in r.content if getattr(b, "type", "") == "text")


class OpenAIBackend:
    """Works with OpenAI, and any provider exposing /chat/completions (set OPENAI_BASE_URL)."""
    name = "openai"
    tokens = 0

    def __init__(self):
        self.base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.key = os.environ["OPENAI_API_KEY"]
        self.model = os.environ.get("PATCHSENTINEL_MODEL", "gpt-4o")

    def complete(self, system: str, user: str) -> str:
        body = json.dumps({"model": self.model, "temperature": 0,
                           "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}).encode()
        req = urllib.request.Request(f"{self.base}/chat/completions", data=body,
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"})
        with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310 - user-configured HTTPS endpoint
            data = json.loads(resp.read())
        self.tokens += (data.get("usage") or {}).get("total_tokens", 0)
        return data["choices"][0]["message"]["content"]


def get_backend(name: str, sabotage=None):
    if name == "offline":
        return OfflineBackend(sabotage)
    if name == "anthropic":
        return AnthropicBackend()
    if name == "openai":
        return OpenAIBackend()
    raise SystemExit(f"unknown provider {name!r} (use offline, anthropic or openai)")


def extract_json(text: str) -> dict:
    text = re.sub(r"```(?:json)?", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < 0:
        raise ValueError("no JSON object in model reply")
    return json.loads(text[start:end + 1])


def extract_code(text: str) -> str:
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).rstrip() + "\n"
