"""Builders for credential-*shaped* test strings.

Every value is generated at runtime from a seeded RNG, so the repository never
contains a literal that looks like a real credential (and secret scanners such
as GitHub push protection have nothing to flag). None of these are real.
"""

from __future__ import annotations

import base64
import random
import string

ALNUM = string.ascii_letters + string.digits
UPPER_ALNUM = string.ascii_uppercase + string.digits
B64 = string.ascii_letters + string.digits + "+/"


def rand(n: int, alphabet: str = ALNUM, seed: str = "egressveil") -> str:
    rng = random.Random(f"{seed}:{n}:{alphabet}")  # noqa: S311 - not crypto
    body = [rng.choice(alphabet) for _ in range(n)]
    # Guarantee at least one letter and one digit when the alphabet has both.
    if n >= 2 and any(c.isdigit() for c in alphabet) and any(c.isalpha() for c in alphabet):
        body[0] = next(c for c in alphabet if c.isalpha())
        body[1] = next(c for c in alphabet if c.isdigit())
    return "".join(body)


def anthropic_key() -> str:
    return "sk-" + "ant-" + "api03-" + rand(93, ALNUM + "-_")


def openai_key() -> str:
    return "sk-" + "proj-" + rand(48)


def aws_access_key_id() -> str:
    return "AK" + "IA" + rand(16, UPPER_ALNUM)


def aws_doc_example_key() -> str:
    return "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"


def aws_secret() -> str:
    return rand(40, B64)


def github_token() -> str:
    return "gh" + "p_" + rand(36)


def github_fine_grained() -> str:
    return "github" + "_pat_" + rand(82, ALNUM + "_")


def gitlab_token() -> str:
    return "gl" + "pat-" + rand(20)


def slack_token() -> str:
    return "xo" + "xb-" + rand(12, string.digits) + "-" + rand(24)


def slack_webhook() -> str:
    return (
        "https://hooks."
        + "slack.com/services/T"
        + rand(10, UPPER_ALNUM)
        + "/B"
        + rand(10, UPPER_ALNUM)
        + "/"
        + rand(24)
    )


def stripe_key() -> str:
    return "sk" + "_live_" + rand(24)


def google_api_key() -> str:
    return "AI" + "za" + rand(35, ALNUM + "-_")


def npm_token() -> str:
    return "np" + "m_" + rand(36)


def huggingface_token() -> str:
    return "h" + "f_" + rand(34)


def private_key_block() -> str:
    body = base64.b64encode(random.Random("pk").randbytes(600)).decode()  # noqa: S311
    lines = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    label = "RSA " + "PRIVATE KEY"
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----"


def jwt() -> str:
    def seg(n: int) -> str:
        return rand(n, ALNUM + "-_", seed=f"jwt{n}")

    return "ey" + "J" + seg(30) + ".ey" + "J" + seg(60) + "." + seg(43)


def db_password() -> str:
    return "Pq7" + rand(13)
