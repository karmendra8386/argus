"""Dev runner: starts the gateway with mock providers. Not for production."""

import sys

sys.path.insert(0, "/home/hatch/workspace/ai-gateway")

from gateway.server import run

if __name__ == "__main__":
    run(host="127.0.0.1", port=4123)
