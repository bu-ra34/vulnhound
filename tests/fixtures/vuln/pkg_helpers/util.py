def _normalize(text):
    text = text.strip()
    parts = text.split(",")
    return " ".join(parts)


def make_command(opts):
    cleaned = _normalize(opts)
    return "convert " + cleaned
