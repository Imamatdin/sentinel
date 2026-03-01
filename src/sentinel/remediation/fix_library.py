"""
Fix Library — Curated before/after code snippets for common vulnerability categories.

Provides framework-specific fix patterns that serve as both LLM prompt guidance
and developer-facing remediation examples.
"""

FIX_SNIPPETS: dict[tuple[str, str], dict[str, str]] = {
    ("injection", "django"): {
        "before": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")",
        "after": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", [user_id])",
        "imports": "",
    },
    ("injection", "express"): {
        "before": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
        "after": "db.query('SELECT * FROM users WHERE id = $1', [req.params.id])",
        "imports": "",
    },
    ("injection", "flask"): {
        "before": "db.execute(f\"SELECT * FROM users WHERE id = {uid}\")",
        "after": "db.execute(\"SELECT * FROM users WHERE id = :uid\", {\"uid\": uid})",
        "imports": "",
    },
    ("injection", "generic"): {
        "before": "query = \"SELECT * FROM users WHERE id = \" + user_id",
        "after": "query = \"SELECT * FROM users WHERE id = ?\"; params = [user_id]",
        "imports": "",
    },
    ("xss", "express"): {
        "before": "res.send(`<p>Hello ${req.query.name}</p>`)",
        "after": "const escaped = escapeHtml(req.query.name); res.send(`<p>Hello ${escaped}</p>`)",
        "imports": "const escapeHtml = require('escape-html');",
    },
    ("xss", "generic"): {
        "before": "output = '<p>' + user_input + '</p>'",
        "after": "output = '<p>' + html_escape(user_input) + '</p>'",
        "imports": "from html import escape as html_escape",
    },
    ("auth_bypass", "django"): {
        "before": "@api_view(['GET'])\ndef admin_panel(request):\n    return Response(data)",
        "after": "@api_view(['GET'])\n@permission_classes([IsAdminUser])\ndef admin_panel(request):\n    return Response(data)",
        "imports": "from rest_framework.permissions import IsAdminUser",
    },
    ("auth_bypass", "generic"): {
        "before": "if user.role == 'admin': allow()",
        "after": "if user.is_authenticated and user.has_permission('admin'): allow()",
        "imports": "",
    },
    ("idor", "generic"): {
        "before": "record = db.get(request.params['id'])",
        "after": "record = db.get(request.params['id'])\nif record.owner_id != current_user.id:\n    raise Forbidden()",
        "imports": "",
    },
    ("ssrf", "generic"): {
        "before": "response = requests.get(user_url)",
        "after": "parsed = urlparse(user_url)\nif parsed.hostname in ALLOWED_HOSTS:\n    response = requests.get(user_url)",
        "imports": "from urllib.parse import urlparse",
    },
}


def get_fix_snippet(
    category: str, framework: str
) -> dict[str, str] | None:
    """Look up a fix snippet by category and framework.

    Falls back to generic framework if no specific match exists.
    Returns None if no snippet is available.
    """
    key = (category.lower(), framework.lower())
    snippet = FIX_SNIPPETS.get(key)
    if snippet:
        return snippet
    # Fallback to generic
    generic_key = (category.lower(), "generic")
    return FIX_SNIPPETS.get(generic_key)
