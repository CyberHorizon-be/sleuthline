#!/usr/bin/env python3
"""
Sleuthline - provider-independent access layer to language models (standard library
only: no SDK dependency).

Providers ("provider" key of llm_config.json):
  anthropic   Claude Messages API (native tools, prompt caching).
  openai      Any OpenAI-compatible /v1/chat/completions API: OpenAI, Azure OpenAI,
              Mistral, Groq, OpenRouter, and locally Ollama, LM Studio, vLLM, llama.cpp...
              (base_url parameter).
  mock        Scripted answers (JSON file): tests without network calls.

Tool calling mode ("tool_mode" key):
  native      native function/tool calling of the API (recommended).
  json        for models without tool calling: the model answers with a JSON block
              {"tool": "...", "args": {...}} that the program interprets.

Internal (neutral) messages:
  {"role": "user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id", "name", "args"}]}
  {"role": "tool", "tool_call_id": str, "name": str, "content": str}
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Reply:
    text: str = ""
    tool_calls: list = field(default_factory=list)
    input_tokens: int = 0           # total input (cache included)
    output_tokens: int = 0
    stop_reason: str = ""
    cache_read_tokens: int = 0      # share read from the cache (billed ~10 %)
    cache_write_tokens: int = 0     # share written to the cache (billed ~125 %)

    def billed_input(self) -> float:
        """Input tokens as full-price equivalent (used for the budget)."""
        plain = self.input_tokens - self.cache_read_tokens - self.cache_write_tokens
        return plain + 0.1 * self.cache_read_tokens + 1.25 * self.cache_write_tokens


class LLMError(RuntimeError):
    pass


def read_keys_file(path: Path) -> dict:
    """Reads a "NAME = value" file (# lines ignored, quotes removed)."""
    keys = {}
    try:
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = v.strip().strip('"').strip("'")
            if v:
                keys[k.strip()] = v
    except OSError:
        pass
    return keys


def _http_json(url: str, payload: dict, headers: dict, timeout: int, retries: int = 6) -> dict:
    data = json.dumps(payload).encode("utf-8")
    delay = 5.0
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"content-type": "application/json", **headers})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:2000]
            last = f"HTTP {e.code}: {body}"
            if e.code in (408, 409, 425, 429, 500, 502, 503, 504, 529):
                retry_after = e.headers.get("retry-after")
                wait = float(retry_after) if retry_after and retry_after.replace(".", "").isdigit() else delay
                time.sleep(min(wait, 120))
                delay = min(delay * 2, 120)
                continue
            raise LLMError(last)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = f"network: {e}"
            time.sleep(delay)
            delay = min(delay * 2, 120)
    raise LLMError(f"failed after {retries} attempts: {last}")


# ------------------------------------------------------------------------------------------
# JSON mode (models without native tool calling)
# ------------------------------------------------------------------------------------------
def json_mode_instructions(tools: list[dict]) -> str:
    lines = ["", "# Using the tools",
             "You have no native function calling. To use a tool, answer ONLY with a block:",
             "```json", '{"tool": "<nom>", "args": {...}}', "```",
             "One tool per answer. The result will be sent back to you in the next message.",
             "Available tools (name, description, JSON Schema parameters):"]
    for t in tools:
        lines.append(f"- {t['name']}: {t['description']}\n  parameters: {json.dumps(t['parameters'], ensure_ascii=False)}")
    return "\n".join(lines)


def parse_json_tool_call(text: str):
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S) or re.search(r"(\{\s*\"tool\".*\})", text, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(1))
    except ValueError:
        return None
    if isinstance(obj, dict) and isinstance(obj.get("tool"), str):
        return {"id": "call_" + uuid.uuid4().hex[:12], "name": obj["tool"], "args": obj.get("args") or {}}
    return None


def neutral_to_json_mode(messages: list[dict]) -> list[dict]:
    """Neutral conversation -> plain user/assistant text (tool calls/results in clear text)."""
    out = []
    for m in messages:
        if m["role"] == "assistant":
            txt = m.get("content") or ""
            for tc in m.get("tool_calls", []):
                txt += "\n```json\n" + json.dumps({"tool": tc["name"], "args": tc["args"]}, ensure_ascii=False) + "\n```"
            out.append({"role": "assistant", "content": txt.strip() or "(empty)"})
        elif m["role"] == "tool":
            out.append({"role": "user", "content": f"Result of the tool {m['name']}:\n{m['content']}"})
        else:
            out.append({"role": "user", "content": m["content"]})
    merged = []
    for m in out:                                   # alternating roles required by some APIs
        if merged and merged[-1]["role"] == m["role"]:
            merged[-1]["content"] += "\n\n" + m["content"]
        else:
            merged.append(dict(m))
    return merged


# ------------------------------------------------------------------------------------------
# Providers
# ------------------------------------------------------------------------------------------
class Provider:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.model = cfg.get("model", "")
        self.max_tokens = int(cfg.get("max_tokens", 8192))
        self.temperature = cfg.get("temperature", 0.1)
        self.timeout = int(cfg.get("timeout_s", 600))
        self.tool_mode = cfg.get("tool_mode", "native")

    def api_key(self) -> str | None:
        """API key: environment variable, otherwise the key file (config\\api_keys.txt),
        otherwise the 'api_key' value of the configuration (not recommended)."""
        env = self.cfg.get("api_key_env")
        if env and os.environ.get(env):
            return os.environ[env]
        if env and self.cfg.get("_keys_file"):
            key = read_keys_file(Path(self.cfg["_keys_file"])).get(env)
            if key:
                return key
        return self.cfg.get("api_key") or None

    def missing_key_message(self) -> str:
        env = self.cfg.get("api_key_env", "ANTHROPIC_API_KEY")
        where = self.cfg.get("_keys_file") or "api_keys.txt"
        return f"API key missing: fill in the line \"{env} = ...\" in {where} (or set the environment variable {env})"

    def chat(self, system: str, messages: list[dict], tools: list[dict]) -> Reply:
        raise NotImplementedError

    def describe(self) -> str:
        return f"{self.cfg.get('provider')} / {self.model} (tools: {self.tool_mode})"


class AnthropicProvider(Provider):
    def chat(self, system, messages, tools):
        key = self.api_key()
        if not key:
            raise LLMError(self.missing_key_message())
        url = self.cfg.get("base_url", "https://api.anthropic.com").rstrip("/") + "/v1/messages"
        headers = {"x-api-key": key, "anthropic-version": self.cfg.get("api_version", "2023-06-01")}
        if self.tool_mode == "json":
            payload_msgs = neutral_to_json_mode(messages)
            sys_text = system + json_mode_instructions(tools)
        else:
            payload_msgs = self._convert(messages)
            sys_text = system
        # Second cache breakpoint on the last message: the conversation of a step (queries and results
        # already sent) is read back from the cache on the next turn instead of being billed again in full.
        if payload_msgs:
            last = payload_msgs[-1]
            if isinstance(last.get("content"), str):
                last["content"] = [{"type": "text", "text": last["content"]}]
            if last["content"]:
                last["content"][-1] = {**last["content"][-1], "cache_control": {"type": "ephemeral"}}
        payload = {"model": self.model, "max_tokens": self.max_tokens, "messages": payload_msgs,
                   "system": [{"type": "text", "text": sys_text, "cache_control": {"type": "ephemeral"}}]}
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        if self.tool_mode != "json" and tools:
            payload["tools"] = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
                                for t in tools]
        r = _http_json(url, payload, headers, self.timeout)
        rep = Reply(stop_reason=r.get("stop_reason", ""))
        u = r.get("usage", {})
        rep.cache_read_tokens = u.get("cache_read_input_tokens", 0) or 0
        rep.cache_write_tokens = u.get("cache_creation_input_tokens", 0) or 0
        rep.input_tokens = (u.get("input_tokens", 0) or 0) + rep.cache_read_tokens + rep.cache_write_tokens
        rep.output_tokens = u.get("output_tokens", 0)
        texts = []
        for b in r.get("content", []):
            if b.get("type") == "text":
                texts.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                rep.tool_calls.append({"id": b["id"], "name": b["name"], "args": b.get("input") or {}})
        rep.text = "\n".join(texts).strip()
        if self.tool_mode == "json" and not rep.tool_calls:
            tc = parse_json_tool_call(rep.text)
            if tc:
                rep.tool_calls = [tc]
        return rep

    @staticmethod
    def _convert(messages):
        out = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": [{"type": "text", "text": m["content"]}]})
            elif m["role"] == "assistant":
                blocks = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls", []):
                    blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["name"], "input": tc["args"]})
                out.append({"role": "assistant", "content": blocks or [{"type": "text", "text": "(empty)"}]})
            elif m["role"] == "tool":
                block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
                if out and out[-1]["role"] == "user" and all(b.get("type") == "tool_result" for b in out[-1]["content"]):
                    out[-1]["content"].append(block)
                else:
                    out.append({"role": "user", "content": [block]})
        return out


class OpenAICompatProvider(Provider):
    def chat(self, system, messages, tools):
        base = self.cfg.get("base_url", "https://api.openai.com/v1").rstrip("/")
        url = base + "/chat/completions"
        headers = {}
        key = self.api_key()
        if not key and self.cfg.get("api_key_env"):
            raise LLMError(self.missing_key_message())
        if key:
            headers["authorization"] = f"Bearer {key}"
            if self.cfg.get("azure"):
                headers = {"api-key": key}
        if self.tool_mode == "json":
            msgs = [{"role": "system", "content": system + json_mode_instructions(tools)}] + neutral_to_json_mode(messages)
        else:
            msgs = [{"role": "system", "content": system}] + self._convert(messages)
        payload = {"model": self.model, "messages": msgs}
        payload[self.cfg.get("max_tokens_param", "max_tokens")] = self.max_tokens
        if self.temperature is not None:
            payload["temperature"] = self.temperature
        if self.tool_mode != "json" and tools:
            payload["tools"] = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                                  "parameters": t["parameters"]}} for t in tools]
        payload.update(self.cfg.get("extra_body", {}))
        r = _http_json(url, payload, headers, self.timeout)
        try:
            choice = r["choices"][0]
        except (KeyError, IndexError):
            raise LLMError(f"unexpected answer: {json.dumps(r)[:500]}")
        msg = choice.get("message", {})
        rep = Reply(text=(msg.get("content") or "").strip(), stop_reason=choice.get("finish_reason", ""))
        u = r.get("usage") or {}
        rep.input_tokens, rep.output_tokens = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
        rep.cache_read_tokens = ((u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)   # OpenAI automatic caching
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {"_raw": fn.get("arguments")}
            rep.tool_calls.append({"id": tc.get("id") or "call_" + uuid.uuid4().hex[:12], "name": fn.get("name"), "args": args})
        if not rep.tool_calls and rep.text:
            tc = parse_json_tool_call(rep.text) if self.tool_mode == "json" or self.cfg.get("json_fallback", True) else None
            if tc:
                rep.tool_calls = [tc]
        return rep

    @staticmethod
    def _convert(messages):
        out = []
        for m in messages:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                o = {"role": "assistant", "content": m.get("content") or ""}
                if m.get("tool_calls"):
                    o["tool_calls"] = [{"id": tc["id"], "type": "function",
                                        "function": {"name": tc["name"], "arguments": json.dumps(tc["args"], ensure_ascii=False)}}
                                       for tc in m["tool_calls"]]
                out.append(o)
            elif m["role"] == "tool":
                out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        return out


class MockProvider(Provider):
    """Replays a script: list of answers {"text": ..., "tool_calls": [{"name", "args"}]}.
    When the script is exhausted, ends the current step (step_complete)."""

    def __init__(self, cfg):
        super().__init__(cfg)
        self.script = json.loads(Path(cfg["script"]).read_text(encoding="utf-8")) if cfg.get("script") else []
        self.i = 0

    def chat(self, system, messages, tools):
        if self.i < len(self.script):
            item = self.script[self.i]
            self.i += 1
        else:
            item = {"tool_calls": [{"name": "step_complete", "args": {"summary": "Simulated step (mock provider)."}}]}
        calls = [{"id": "mock_" + uuid.uuid4().hex[:8], "name": c["name"], "args": c.get("args", {})}
                 for c in item.get("tool_calls", [])]
        return Reply(text=item.get("text", ""), tool_calls=calls, input_tokens=len(system) // 4, output_tokens=50)


PROVIDERS = {"anthropic": AnthropicProvider, "openai": OpenAICompatProvider, "mock": MockProvider}


def make_provider(cfg: dict) -> Provider:
    name = cfg.get("provider", "anthropic")
    if name not in PROVIDERS:
        raise LLMError(f"unknown provider: {name} (available: {', '.join(PROVIDERS)})")
    return PROVIDERS[name](cfg)
