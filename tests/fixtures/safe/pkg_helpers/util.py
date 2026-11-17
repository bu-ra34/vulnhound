import shlex


def _normalize(text):
    text = text.strip()
    return shlex.quote(text)


def make_command(opts):
    cleaned = _normalize(opts)
    return "convert " + cleaned
