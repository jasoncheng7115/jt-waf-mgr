"""Client for a local, OpenAI-compatible LLM server (e.g. llama.cpp / vLLM style: /v1/models,
/v1/chat/completions). Standard library only.

Safety:
- the API key is sent only to the configured base URL; redirects are not followed;
- responses are size-limited and parsed as JSON;
- what the model says is never trusted: callers validate every field (see analyst.py).
"""
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_RESPONSE = 4 * 1024 * 1024
_THINK = re.compile(r'<think>.*?(?:</think>|$)', re.S | re.I)


def strip_thinking(text):
    """Reasoning models (e.g. Qwen3) may put a <think>…</think> block before the answer."""
    return _THINK.sub('', text or '').strip()


class LLMError(Exception):
    def __init__(self, code, detail=''):
        super().__init__(code)
        self.code, self.detail = code, str(detail)[:300]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    def __init__(self, cfg):
        c = cfg['llm']
        self.base = (c.get('url') or '').rstrip('/')
        self.model = c.get('model') or ''
        self.key = c.get('api_key') or ''
        self.timeout = int(c.get('timeout_seconds') or 180)
        self.enabled = bool(c.get('enabled'))

    def _check(self):
        u = urllib.parse.urlsplit(self.base)
        if u.scheme not in ('http', 'https') or not u.hostname:
            raise LLMError('not_configured', 'set the LLM server URL in Settings')

    def _call(self, method, path, body=None, timeout=None):
        self._check()
        headers = {'Accept': 'application/json', 'User-Agent': 'jt-waf-mgr'}
        if self.key:
            headers['Authorization'] = 'Bearer ' + self.key
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            with opener.open(req, timeout=timeout or self.timeout) as r:
                raw = r.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as e:
            code = {401: 'unauthorized', 403: 'unauthorized', 404: 'not_found'}.get(e.code, 'http_%d' % e.code)
            raise LLMError(code, e.reason)
        except (urllib.error.URLError, OSError) as e:
            raise LLMError('unreachable', getattr(e, 'reason', e))
        if len(raw) > MAX_RESPONSE:
            raise LLMError('response_too_large')
        try:
            return json.loads(raw.decode('utf-8', 'replace'))
        except ValueError:
            raise LLMError('bad_response', raw[:200])

    def models(self):
        d = self._call('GET', '/models', timeout=15)
        return [m.get('id') for m in (d.get('data') or []) if isinstance(m, dict) and m.get('id')]

    def chat(self, messages, max_tokens=4096, temperature=0.1, json_mode=False, schema=None):
        """Returns (text, usage, seconds). schema: a JSON schema the server constrains the answer to (llama.cpp, vLLM
        and others accept it as response_format json_schema); a server that refuses it gets plain JSON mode."""
        body = {'model': self.model, 'messages': messages, 'max_tokens': max_tokens, 'temperature': temperature,
                'stream': False}
        if schema:
            body['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'answer', 'strict': True, 'schema': schema}}
        elif json_mode:
            body['response_format'] = {'type': 'json_object'}
        t = time.time()
        try:
            d = self._call('POST', '/chat/completions', body)
        except LLMError as e:
            if not schema or e.code not in ('http_400', 'http_422', 'http_500', 'http_501'):
                raise
            body['response_format'] = {'type': 'json_object'}
            d = self._call('POST', '/chat/completions', body)
        try:
            text = d['choices'][0]['message']['content'] or ''
        except (KeyError, IndexError, TypeError):
            raise LLMError('bad_response', json.dumps(d)[:200])
        return text, d.get('usage') or {}, round(time.time() - t, 1)

    def test(self):
        """Connection, key and model in one small round trip."""
        t = time.time()
        models = self.models()
        if self.model and models and self.model not in models:
            raise LLMError('model_not_found', 'available: ' + ', '.join(models[:10]))
        # room for a reasoning model's thinking before the one-word answer
        text, usage, secs = self.chat([{'role': 'user', 'content': 'Reply with the single word OK.'}], max_tokens=400,
                                      temperature=0)
        return {'ok': True, 'models': models[:50], 'model': self.model or (models[0] if models else ''),
                'reply': strip_thinking(text)[:40], 'seconds': round(time.time() - t, 1)}


def parse_json_reply(text):
    """The model's JSON answer, tolerating a ```json fence or text around one object."""
    s = strip_thinking(text)
    if s.startswith('```'):
        s = s.split('\n', 1)[1] if '\n' in s else s
        s = s.rsplit('```', 1)[0]
    i, j = s.find('{'), s.rfind('}')
    if i < 0 or j < i:
        raise LLMError('bad_json')
    try:
        return json.loads(s[i:j + 1])
    except ValueError:
        raise LLMError('bad_json')
