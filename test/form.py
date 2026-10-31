"""Reads Keycloak's registration page for test/e2e.sh.

    python3 -I form.py action <page.html>        prints the registration form's action URL
    python3 -I form.py email-error <page.html>   prints the message shown on the email field, or "-"
    python3 -I form.py has-text <page.html> <text>   exits 0 when the page's visible text contains <text>
"""

import html
import re
import sys


def main() -> int:
    what, path = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8") as f:
        page = f.read()
    if what == "action":
        form = re.search(r'<form[^>]*id="kc-register-form"[^>]*>', page)
        if not form:
            print("no registration form on the page", file=sys.stderr)
            return 1
        action = re.search(r'action="([^"]+)"', form.group(0))
        print(html.unescape(action.group(1)))
        return 0
    if what == "email-error":
        # keycloak.v2 renders a field's errors in <span id="input-error-email" ...>...</span>.
        m = re.search(r'id="input-error-email"[^>]*>(.*?)</span>', page, re.S)
        text = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip() if m else ""
        print(re.sub(r"\s+", " ", text) or "-")
        return 0
    if what == "has-text":
        text = html.unescape(re.sub(r"<[^>]+>", " ", page))
        return 0 if sys.argv[3] in re.sub(r"\s+", " ", text) else 1
    print(f"unknown command {what}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
