import os


def _build(opts):
    return "mytool " + opts


def run_tool(opts):
    cmd = _build(opts)
    return os.popen(cmd).read()  # VH-EXPECT: cmdi
