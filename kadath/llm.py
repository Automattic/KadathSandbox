"""The one place that knows Ollama exists. Sampling profiles, the /api/chat
client with schema-constrained output and a single validation retry, and a
minimal JSON-schema validator (stdlib only, so no jsonschema dependency)."""
import copy
import json
import os
import urllib.error
import urllib.request

DEFAULT_MODEL = "orcarouter/Qwen3.8-27B-Uncensored:latest"
DEFAULT_URL = "http://localhost:11434"

# Per-tier sampling. Cavern and Offering are seeded so a re-run reproduces the
# judgment; Deep Scrying is not, and must not run greedy (Qwen3 loops with
# thinking on at temperature 0). repeat_penalty above ~1.1 degrades JSON/YARA.
PROFILES = {
    "cavern": {"temperature": 0.1, "top_p": 0.8, "top_k": 20, "min_p": 0,
               "repeat_penalty": 1.05, "seed": 42, "num_ctx": 16384, "num_predict": 1024},
    "offer": {"temperature": 0.2, "top_p": 0.8, "top_k": 20, "min_p": 0,
              "repeat_penalty": 1.05, "seed": 42, "num_ctx": 32768, "num_predict": 4096},
    "deepscry": {"temperature": 0.6, "top_p": 0.95, "top_k": 20, "min_p": 0,
                 "repeat_penalty": 1.05, "num_ctx": 65536, "num_predict": 8192},
    "runes": {"temperature": 0.1, "top_p": 0.8, "top_k": 20, "min_p": 0,
              "repeat_penalty": 1.05, "seed": 42, "num_ctx": 32768, "num_predict": 2048},
}


class LLMError(RuntimeError):
    pass


def _num(s):
    try:
        return int(s)
    except ValueError:
        try:
            return float(s)
        except ValueError:
            return s


def parse_overrides(items):
    """['deepscry.temperature=0.4'] -> {'deepscry': {'temperature': 0.4}}"""
    out = {}
    for it in items or []:
        if "=" not in it or "." not in it.split("=", 1)[0]:
            raise ValueError(f"override must be tier.key=value: {it!r}")
        key, val = it.split("=", 1)
        tier, k = key.split(".", 1)
        if tier not in PROFILES:
            raise ValueError(f"unknown tier {tier!r} in override {it!r}")
        out.setdefault(tier, {})[k] = _num(val)
    return out


def build_profiles(overrides=None, profiles_file=None, seed=None):
    if profiles_file:
        with open(profiles_file) as f:
            prof = json.load(f)
    else:
        prof = copy.deepcopy(PROFILES)
    for tier, kv in (overrides or {}).items():
        prof.setdefault(tier, {}).update(kv)
    if seed is not None:
        for p in prof.values():
            p["seed"] = seed
    return prof


_TYPES = {"string": str, "boolean": bool, "array": list, "object": dict}


def validate_against(schema, obj, path="$"):
    t = schema.get("type")
    if t == "integer":
        if isinstance(obj, bool) or not isinstance(obj, int):
            raise ValueError(f"{path}: expected integer")
    elif t == "number":
        if isinstance(obj, bool) or not isinstance(obj, (int, float)):
            raise ValueError(f"{path}: expected number")
    elif t in _TYPES and not isinstance(obj, _TYPES[t]):
        raise ValueError(f"{path}: expected {t}")
    if "enum" in schema and obj not in schema["enum"]:
        raise ValueError(f"{path}: {obj!r} not in {schema['enum']}")
    if "minimum" in schema and obj < schema["minimum"]:
        raise ValueError(f"{path}: below minimum {schema['minimum']}")
    if "maximum" in schema and obj > schema["maximum"]:
        raise ValueError(f"{path}: above maximum {schema['maximum']}")
    if "maxLength" in schema and isinstance(obj, str) and len(obj) > schema["maxLength"]:
        raise ValueError(f"{path}: longer than {schema['maxLength']}")
    if t == "object":
        for k in schema.get("required", []):
            if k not in obj:
                raise ValueError(f"{path}: missing required {k!r}")
        for k, sub in schema.get("properties", {}).items():
            if k in obj:
                validate_against(sub, obj[k], f"{path}.{k}")
    if t == "array" and "items" in schema:
        for i, it in enumerate(obj):
            validate_against(schema["items"], it, f"{path}[{i}]")


def _post(url, payload, timeout):
    data = json.dumps(payload).encode()
    for attempt in range(2):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except (urllib.error.URLError, OSError) as e:
            # one retry: Ollama drops idle keep-alive connections mid-run
            if attempt == 0:
                continue
            raise LLMError(f"ollama request failed: {e}") from e
        except ValueError as e:
            raise LLMError(f"ollama request failed: {e}") from e


def _get(url, timeout):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise LLMError(f"ollama request failed: {e}") from e


class Client:
    def __init__(self, base_url=None, model=None, profiles=None):
        self.base_url = (base_url or os.environ.get("KADATH_OLLAMA_URL") or DEFAULT_URL).rstrip("/")
        self.model = model or os.environ.get("KADATH_MODEL") or DEFAULT_MODEL
        self.profiles = profiles or copy.deepcopy(PROFILES)

    def reachable(self):
        """True if the Ollama server answers /api/tags — distinguishes a
        transient per-request timeout from the server being down."""
        try:
            _get(f"{self.base_url}/api/tags", timeout=10)
            return True
        except LLMError:
            return False

    def preflight(self):
        tags = _get(f"{self.base_url}/api/tags", timeout=10)
        names = [m.get("name") for m in tags.get("models", [])]
        if self.model not in names:
            raise LLMError(f"model {self.model!r} not in ollama tags: {names}")
        self.chat([{"role": "user", "content": "Reply with the single word: ok"}],
                  profile="cavern", timeout=120)

    def chat(self, messages, *, profile, json_schema=None, tools=None, timeout=300,
             think=False, validate=None):
        msgs = list(messages)
        payload = {"model": self.model, "messages": msgs, "stream": False, "think": think,
                   "options": dict(self.profiles[profile])}
        if json_schema is not None:
            payload["format"] = json_schema
        if tools:
            payload["tools"] = tools
        last_err = None
        for attempt in range(2):
            payload["messages"] = msgs
            resp = _post(f"{self.base_url}/api/chat", payload, timeout)
            m = resp.get("message", {})
            content = m.get("content", "") or ""
            tool_calls = m.get("tool_calls", []) or []
            reply = {"role": "assistant", "content": content}
            if tool_calls:
                reply["tool_calls"] = tool_calls
            msgs = msgs + [reply]
            if json_schema is None:
                return {"content": content, "tool_calls": tool_calls, "parsed": None, "messages": msgs}
            try:
                parsed = json.loads(content)
                if validate:
                    validate(parsed)
                return {"content": content, "tool_calls": tool_calls, "parsed": parsed, "messages": msgs}
            except (ValueError, TypeError) as e:
                last_err = str(e)
                msgs = msgs + [{"role": "user", "content":
                                f"Your previous reply failed validation: {last_err}. "
                                "Reply again with valid JSON only, matching the schema."}]
        raise LLMError(f"model output failed validation twice: {last_err}")
