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
# an answer cut short by max_tokens (often a reasoning model still thinking), as servers word it in an error
TRUNCATED = re.compile(r'finish_reason\W{0,3}length|structured_output_failed|max[ _]tokens while|output budget', re.I)
_THINK = re.compile(r'<think>.*?(?:</think>|$)', re.S | re.I)


def strip_thinking(text):
    """Reasoning models (e.g. Qwen3) may put a <think>…</think> block before the answer."""
    return _THINK.sub('', text or '').strip()


class LLMError(Exception):
    def __init__(self, code, detail='', info=None):
        super().__init__(code)
        self.code, self.detail = code, str(detail)[:300]
        self.info = info or {}      # what went wrong, for the run's error log: never the key or the request


LOG_HEADERS = ('server', 'via', 'content-type', 'content-length', 'retry-after', 'x-request-id', 'cf-ray', 'date')
LOG_BODY = 1500


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
        t0 = time.time()
        to = timeout or self.timeout
        info = {'method': method, 'url': self.base + path, 'timeout': to, 'request_bytes': len(data or b'')}

        def done(**k):
            info.update(k, seconds=round(time.time() - t0, 1))
            return self._scrub(info)
        try:
            with opener.open(req, timeout=to) as r:
                raw = r.read(MAX_RESPONSE + 1)
                status, rh = r.status, r.headers
        except urllib.error.HTTPError as e:
            code = {401: 'unauthorized', 403: 'unauthorized', 404: 'not_found'}.get(e.code, 'http_%d' % e.code)
            try:
                body = e.read(LOG_BODY + 1)
            except OSError:
                body = b''
            hdr = {k: v for k, v in (e.headers or {}).items() if k.lower() in LOG_HEADERS}
            e.close()
            if TRUNCATED.search(body[:LOG_BODY].decode('utf-8', 'replace')):
                # a server that checks the JSON itself (strata) refuses an answer cut short by max_tokens with a 5xx
                code = 'output_truncated'
            raise LLMError(code, e.reason, done(status=e.code, reason=str(e.reason)[:200], headers=hdr,
                                                body=body[:LOG_BODY].decode('utf-8', 'replace')))
        except (urllib.error.URLError, OSError) as e:
            why = getattr(e, 'reason', e)
            raise LLMError('unreachable', why, done(error='%s: %s' % (type(why).__name__, str(why)[:300])))
        if len(raw) > MAX_RESPONSE:
            raise LLMError('response_too_large', '', done(status=status, bytes=len(raw)))
        try:
            return json.loads(raw.decode('utf-8', 'replace'))
        except ValueError:
            raise LLMError('bad_response', raw[:200], done(status=status, body=raw[:LOG_BODY].decode('utf-8', 'replace'),
                                                           headers={k: v for k, v in rh.items() if k.lower() in LOG_HEADERS}))

    def _scrub(self, d):
        """The API key never reaches a log, even when a server echoes it back."""
        if not self.key or len(self.key) < 4:
            return d
        return json.loads(json.dumps(d, ensure_ascii=False).replace(self.key, '[key]'))

    def resolve_model(self):
        """An empty model ("server default" in Settings) becomes the server's first listed model, the one the connection
        test shows. 0.5.54: the event analysis treated it as not configured and ran on the program rules only."""
        models = self.models()
        if not models:
            raise LLMError('not_configured', 'the server lists no model: pick one in Settings')
        self.model = models[0]
        return self.model

    def models(self):
        d = self._call('GET', '/models', timeout=15)
        return [m.get('id') for m in (d.get('data') or []) if isinstance(m, dict) and m.get('id')]

    def chat(self, messages, max_tokens=4096, temperature=0.1, json_mode=False, schema=None):
        """Returns (text, usage, seconds). schema: a JSON schema the server constrains the answer to (llama.cpp, vLLM
        and others accept it as response_format json_schema); a server that refuses it gets plain JSON mode."""
        if not self.model:
            self.resolve_model()
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
            finish = d['choices'][0].get('finish_reason')
        except (KeyError, IndexError, TypeError, AttributeError):
            raise LLMError('bad_response', json.dumps(d)[:200],
                           self._scrub({'method': 'POST', 'url': self.base + '/chat/completions', 'seconds': round(time.time() - t, 1),
                                        'body': json.dumps(d, ensure_ascii=False)[:LOG_BODY]}))
        if finish == 'length' and (schema or json_mode):
            # a JSON answer cut short is no answer: the caller can ask again with more room
            raise LLMError('output_truncated', 'max_tokens %d' % max_tokens,
                           self._scrub({'method': 'POST', 'url': self.base + '/chat/completions', 'seconds': round(time.time() - t, 1),
                                        'max_tokens': max_tokens, 'usage': d.get('usage') or {}}))
        return text, d.get('usage') or {}, round(time.time() - t, 1)

    def test(self):
        """Connection, key and model in one small round trip."""
        t = time.time()
        models = self.models()
        if self.model and models and self.model not in models:
            e = LLMError('model_not_found', 'available: ' + ', '.join(models[:10]))
            e.models = models[:50]      # 0.5.48: the page offers these (the saved model is gone from the server)
            raise e
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
