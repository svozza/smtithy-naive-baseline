def parse_port(raw):
    return int(raw)


def build_url(host, raw_port):
    return f"http://{host}:{parse_port(raw_port)}"
