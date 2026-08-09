"""Detection rules.

Every rule pairs a regex with a plain-English explanation and a
ready-to-paste fix prompt for the user's AI coding tool (Cursor, Claude
Code, Lovable, Bolt, ...). The placeholders {path} and {line} are filled
in per finding.

Severities: critical > high > medium > low > info.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import FrozenSet, Optional

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Points subtracted from the 100-point Vibe Score per finding.
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}

JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html"})
PY = frozenset({".py"})
JS_PY = frozenset(JS | PY)

# If the matched text itself looks like a placeholder, it isn't a leak.
PLACEHOLDER_HINTS = (
    "example",
    "your_",
    "your-",
    "yourkey",
    "placeholder",
    "xxxx",
    "<",
    ">",
    "${",
    "process.env",
    "os.environ",
    "import.meta",
    "dummy",
    "insert_",
    "replace_",
    "_here",
)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: "re.Pattern[str]"
    description: str
    fix_prompt: str
    extensions: Optional[FrozenSet[str]] = None  # None = any scannable file
    is_secret: bool = False  # redact the matched text in reports; skipped inside .env files
    frontend_boost: bool = False  # bump severity one level in browser-served files
    frontend_only: bool = False  # only fires in browser-served files


def looks_like_placeholder(matched_text: str) -> bool:
    lowered = matched_text.lower()
    return any(hint in lowered for hint in PLACEHOLDER_HINTS)


# Special rule handled by the scanner: hardcoded JWTs get their payload
# decoded, and Supabase service_role vs anon keys are reported differently.
JWT_RULE_ID = "hardcoded-jwt"

SUPABASE_SERVICE_ROLE = Rule(
    id="supabase-service-role-key",
    title="Supabase service_role key exposed",
    severity="critical",
    pattern=re.compile(r"(?!x)x"),  # never matched directly; produced by the scanner
    description=(
        "This is a Supabase service_role key. It bypasses ALL of your Row Level "
        "Security rules — anyone holding it can read, change, or delete every row "
        "in your database. It must only ever live in server-side environment "
        "variables, never in code or anything shipped to the browser."
    ),
    fix_prompt=(
        "A Supabase service_role key is hardcoded in {path} on line {line}. Remove it "
        "from the code, move any queries that need it into a server-side route or edge "
        "function that reads it from an environment variable named "
        "SUPABASE_SERVICE_ROLE_KEY, and make sure client code only ever uses the anon "
        "key with Row Level Security enabled. Remind me to rotate this key in the "
        "Supabase dashboard (Settings > API) because it has been exposed."
    ),
    is_secret=True,
)

SUPABASE_ANON_INFO = Rule(
    id="supabase-anon-key",
    title="Supabase anon key found (check RLS)",
    severity="info",
    pattern=re.compile(r"(?!x)x"),  # never matched directly; produced by the scanner
    description=(
        "This looks like a Supabase anon key. That key is designed to be public, so "
        "this is not a leak by itself — but it means your only protection is Row "
        "Level Security. If RLS is off or misconfigured on any table, anyone can "
        "read or write your data using this key."
    ),
    fix_prompt=(
        "My app uses a Supabase anon key (seen in {path} line {line}). Review every "
        "table in my Supabase project and confirm Row Level Security is enabled with "
        "explicit policies for select, insert, update and delete. List any table that "
        "has RLS disabled or a policy that allows public access it shouldn't."
    ),
    is_secret=True,
)


RULES = [
    # ------------------------------------------------------------------
    # Hardcoded secrets and API keys
    # ------------------------------------------------------------------
    Rule(
        id="anthropic-api-key",
        title="Anthropic API key hardcoded",
        severity="high",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}"),
        description=(
            "An Anthropic API key is written directly in your code. Anyone who can "
            "see this file — or your site's source, if it ships to the browser — can "
            "use the key and run up your bill."
        ),
        fix_prompt=(
            "An Anthropic API key is hardcoded in {path} on line {line}. Move every "
            "Anthropic API call to server-side code that reads the key from an "
            "environment variable named ANTHROPIC_API_KEY, delete the hardcoded value, "
            "and add a .env entry locally. Remind me to rotate the key at "
            "console.anthropic.com because it has been exposed."
        ),
        is_secret=True,
        frontend_boost=True,
    ),
    Rule(
        id="openai-api-key",
        title="OpenAI API key hardcoded",
        severity="high",
        pattern=re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}"),
        description=(
            "An OpenAI API key is written directly in your code. Anyone who can see "
            "this file can spend your OpenAI credits."
        ),
        fix_prompt=(
            "An OpenAI API key is hardcoded in {path} on line {line}. Move the OpenAI "
            "calls to server-side code that reads the key from an environment variable "
            "named OPENAI_API_KEY and delete the hardcoded value. Remind me to rotate "
            "the key at platform.openai.com because it has been exposed."
        ),
        is_secret=True,
        frontend_boost=True,
    ),
    Rule(
        id="stripe-live-key",
        title="Stripe LIVE secret key exposed",
        severity="critical",
        pattern=re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{16,}"),
        description=(
            "This is a LIVE Stripe secret key. Anyone who has it can create charges, "
            "issue refunds, and read customer data on your real Stripe account. This "
            "is about as serious as a leak gets."
        ),
        fix_prompt=(
            "A live Stripe secret key is hardcoded in {path} on line {line}. Move all "
            "Stripe API calls to server-side code that reads the key from an "
            "environment variable named STRIPE_SECRET_KEY, and make sure only the "
            "publishable key (pk_live_...) ever appears in browser code. Remind me to "
            "roll this key immediately in the Stripe dashboard (Developers > API keys) "
            "because it has been exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id="stripe-test-key",
        title="Stripe test secret key hardcoded",
        severity="low",
        pattern=re.compile(r"\b[sr]k_test_[0-9a-zA-Z]{16,}"),
        description=(
            "This is a Stripe TEST key, so no real money is at risk — but hardcoding "
            "it is the same habit that leaks live keys later. Fix the pattern now, "
            "before you switch to live mode."
        ),
        fix_prompt=(
            "A Stripe test secret key is hardcoded in {path} on line {line}. Refactor "
            "so the key is read from an environment variable named STRIPE_SECRET_KEY, "
            "so that switching to the live key later doesn't put a secret in the code."
        ),
        is_secret=True,
    ),
    Rule(
        id="aws-access-key-id",
        title="AWS access key ID hardcoded",
        severity="high",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        description=(
            "This looks like an AWS access key ID. If the matching secret key is "
            "nearby, an attacker can use your AWS account — spinning up servers on "
            "your card or stealing data from S3."
        ),
        fix_prompt=(
            "An AWS access key appears in {path} on line {line}. Remove it, load AWS "
            "credentials from environment variables or an IAM role instead, and remind "
            "me to deactivate this key pair in the AWS IAM console because it has been "
            "exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id="google-api-key",
        title="Google API key hardcoded",
        severity="high",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"),
        description=(
            "A Google API key is written in your code. Depending on which APIs it can "
            "call, someone could run up charges on your Google Cloud account. Some "
            "Google keys (like Maps browser keys) are meant to be public, but only if "
            "they're locked down with referrer and API restrictions."
        ),
        fix_prompt=(
            "A Google API key appears in {path} on line {line}. If it's used "
            "server-side, move it to an environment variable. If it must be public "
            "(e.g. a Maps browser key), remind me to add HTTP-referrer and "
            "API restrictions to it in the Google Cloud console so it can't be abused."
        ),
        is_secret=True,
    ),
    Rule(
        id="github-token",
        title="GitHub token hardcoded",
        severity="high",
        pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,}"),
        description=(
            "A GitHub token is written in your code. Anyone with it may be able to "
            "read or push to your repositories as you."
        ),
        fix_prompt=(
            "A GitHub token is hardcoded in {path} on line {line}. Remove it, read it "
            "from an environment variable instead, and remind me to revoke this token "
            "at github.com/settings/tokens because it has been exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id="slack-token",
        title="Slack token hardcoded",
        severity="high",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
        description=(
            "A Slack token is written in your code. Anyone with it can read or post "
            "messages in your Slack workspace as your app or as you."
        ),
        fix_prompt=(
            "A Slack token is hardcoded in {path} on line {line}. Remove it, read it "
            "from an environment variable instead, and remind me to revoke and "
            "regenerate it in the Slack app settings because it has been exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id="telegram-bot-token",
        title="Telegram bot token hardcoded",
        severity="high",
        pattern=re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
        description=(
            "A Telegram bot token is written in your code. Anyone with it can fully "
            "control your bot — read its messages and send messages as the bot."
        ),
        fix_prompt=(
            "A Telegram bot token is hardcoded in {path} on line {line}. Remove it and "
            "read it from an environment variable instead. Remind me to revoke the "
            "token with @BotFather (/revoke) because it has been exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id="private-key-block",
        title="Private key file committed",
        severity="critical",
        pattern=re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        description=(
            "This is a cryptographic private key sitting in your project. Private "
            "keys are the master credential for whatever they protect — TLS, SSH, "
            "service accounts — and must never be in a repository."
        ),
        fix_prompt=(
            "A private key is committed at {path}. Remove the file from the "
            "repository, add its filename and common key patterns (*.pem, *.key) to "
            ".gitignore, and load the key from a secret store or environment variable "
            "at runtime. Remind me to rotate/reissue this key because it has been "
            "exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id="mongodb-uri-credentials",
        title="MongoDB connection string with password",
        severity="high",
        pattern=re.compile(r"mongodb(?:\+srv)?://[^\s:/@\"']+:[^\s@\"']{4,}@"),
        description=(
            "A MongoDB connection string containing a username and password is "
            "written in your code. Anyone who sees it can connect directly to your "
            "database."
        ),
        fix_prompt=(
            "A MongoDB connection string with embedded credentials is hardcoded in "
            "{path} on line {line}. Move it to an environment variable named "
            "MONGODB_URI and read it from there. Remind me to change the database "
            "user's password because it has been exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id="postgres-uri-credentials",
        title="Postgres connection string with password",
        severity="high",
        pattern=re.compile(r"postgres(?:ql)?://[^\s:/@\"']+:[^\s@\"']{4,}@"),
        description=(
            "A Postgres connection string containing a username and password is "
            "written in your code. Anyone who sees it can connect directly to your "
            "database."
        ),
        fix_prompt=(
            "A Postgres connection string with embedded credentials is hardcoded in "
            "{path} on line {line}. Move it to an environment variable named "
            "DATABASE_URL and read it from there. Remind me to change the database "
            "user's password because it has been exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id=JWT_RULE_ID,
        title="Hardcoded JWT token",
        severity="medium",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{4,}"),
        description=(
            "A JSON Web Token is written directly in your code. Tokens grant access "
            "to whatever issued them, and they don't belong in source files."
        ),
        fix_prompt=(
            "A JWT is hardcoded in {path} on line {line}. Work out what issued it, "
            "move it to an environment variable if it's a long-lived credential, and "
            "remind me to revoke or rotate it because it has been exposed."
        ),
        is_secret=True,
    ),
    Rule(
        id="jwt-secret-hardcoded",
        title="JWT signing secret hardcoded",
        severity="high",
        pattern=re.compile(
            r"(?i)\bjwt[_-]?secret\s*[:=]\s*[\"'][^\"']{6,}[\"']"
            r"|jwt\.sign\([^)\n]*,\s*[\"'][^\"']{6,}[\"']"
        ),
        description=(
            "The secret used to sign your login tokens is written in the code. "
            "Anyone who reads it can forge a valid login token for ANY user of your "
            "app, including admins."
        ),
        fix_prompt=(
            "The JWT signing secret is hardcoded in {path} on line {line}. Read it "
            "from an environment variable named JWT_SECRET instead, generate a new "
            "long random value for production, and remove the hardcoded string. Note "
            "that changing the secret will log out existing sessions, which is the "
            "correct thing to do after a leak."
        ),
        is_secret=True,
        extensions=JS_PY,
    ),
    Rule(
        id="hardcoded-password",
        title="Hardcoded password",
        severity="medium",
        pattern=re.compile(r"(?i)\b(?:password|passwd|db_pass(?:word)?|admin_pass(?:word)?)\s*[:=]\s*[\"'][^\"']{6,}[\"']"),
        description=(
            "A password appears to be written directly in the code. If this is a "
            "real credential, anyone with access to the code has it too."
        ),
        fix_prompt=(
            "A password looks hardcoded in {path} on line {line}. If it's a real "
            "credential, move it to an environment variable and change the password "
            "wherever it's used. If it's test data, rename it so it's obviously fake "
            "(e.g. 'test-password-not-real')."
        ),
        is_secret=True,
        extensions=JS_PY,
    ),
    Rule(
        id="public-env-var-holds-secret",
        title="Secret in a PUBLIC env variable",
        severity="high",
        pattern=re.compile(r"\b(?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE)[A-Z0-9_]*"),
        description=(
            "Environment variables prefixed VITE_, NEXT_PUBLIC_, REACT_APP_ or "
            "EXPO_PUBLIC_ are compiled INTO your frontend bundle — they are public by "
            "definition. This one's name suggests it holds a secret, which means the "
            "secret ships to every visitor's browser."
        ),
        fix_prompt=(
            "The environment variable referenced in {path} on line {line} uses a "
            "public prefix (VITE_/NEXT_PUBLIC_/REACT_APP_/EXPO_PUBLIC_) but appears to "
            "hold a secret. Move the secret to a server-only environment variable "
            "(no public prefix), move the code that uses it into a server-side route "
            "or API handler, and rotate the secret since it has shipped to browsers."
        ),
    ),
    # ------------------------------------------------------------------
    # Architecture and configuration mistakes
    # ------------------------------------------------------------------
    Rule(
        id="dangerously-allow-browser",
        title="LLM SDK running in the browser",
        severity="critical",
        pattern=re.compile(r"dangerouslyAllowBrowser\s*:\s*true"),
        description=(
            "dangerouslyAllowBrowser: true means the AI SDK runs in the visitor's "
            "browser — which means your API key is shipped to every visitor. The "
            "flag is named 'dangerously' for exactly this reason. Anyone can open "
            "DevTools, copy your key, and spend your credits."
        ),
        fix_prompt=(
            "My app calls an LLM API directly from the browser using "
            "dangerouslyAllowBrowser: true ({path} line {line}). Create a server-side "
            "API route that makes the LLM call using an environment-variable key, "
            "change the frontend to call that route instead, remove the "
            "dangerouslyAllowBrowser flag, and add basic rate limiting to the new "
            "route. Remind me to rotate the API key because it has shipped to "
            "browsers."
        ),
        extensions=JS,
    ),
    Rule(
        id="llm-api-call-in-frontend",
        title="LLM API called from frontend code",
        severity="high",
        pattern=re.compile(r"api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis\.com"),
        description=(
            "Your frontend talks to an LLM API directly. Browser code can't keep a "
            "secret, so the API key that authorizes these calls is visible to every "
            "visitor via DevTools."
        ),
        fix_prompt=(
            "My frontend calls an LLM API directly ({path} line {line}). Create a "
            "server-side API route that proxies the LLM call using a key from an "
            "environment variable, update the frontend to call that route, and add "
            "basic rate limiting so strangers can't drain my credits through it."
        ),
        frontend_only=True,
    ),
    Rule(
        id="flask-debug-enabled",
        title="Debug mode enabled",
        severity="medium",
        pattern=re.compile(r"\.run\([^)\n]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True", re.MULTILINE),
        description=(
            "Debug mode is switched on. In production this shows full error pages "
            "with your code and variables to visitors, and Flask's debugger even "
            "allows running arbitrary code on your server."
        ),
        fix_prompt=(
            "Debug mode is enabled in {path} on line {line}. Make debug mode depend "
            "on an environment variable that defaults to off (e.g. "
            "debug=os.environ.get('FLASK_DEBUG') == '1') so production never runs "
            "with it enabled."
        ),
        extensions=PY,
    ),
    Rule(
        id="cors-allow-all",
        title="CORS allows every website",
        severity="medium",
        pattern=re.compile(r"Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*|origin\s*:\s*[\"']\*[\"']|\bcors\(\s*\)"),
        description=(
            "Your API accepts requests from any website on the internet. Combined "
            "with cookie-based login, a malicious site can make requests to your API "
            "as your logged-in users."
        ),
        fix_prompt=(
            "CORS is configured to allow all origins in {path} on line {line}. "
            "Restrict it to my actual frontend domain(s), e.g. cors({{ origin: "
            "['https://myapp.com'] }}), and keep localhost only for development."
        ),
        extensions=frozenset(JS_PY),
    ),
    Rule(
        id="tls-verification-disabled",
        title="TLS certificate checking disabled",
        severity="high",
        pattern=re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"),
        description=(
            "Your code turns off TLS certificate verification, which silently "
            "removes the protection HTTPS provides. Anyone between your server and "
            "the API it calls can read or alter the traffic — including API keys in "
            "headers."
        ),
        fix_prompt=(
            "TLS verification is disabled in {path} on line {line}. Remove this "
            "setting and fix the underlying certificate problem properly (usually a "
            "missing CA bundle or wrong hostname) instead of turning verification "
            "off."
        ),
        extensions=JS_PY,
    ),
    Rule(
        id="sql-string-building",
        title="SQL built by string interpolation",
        severity="high",
        pattern=re.compile(
            r"\.execute\(\s*f[\"']"
            r"|\.execute\([^,)\n]*[\"']\s*\+"
            r"|\.execute\([^,)\n]*%\s"
            r"|\.query\(\s*`[^`\n]*\$\{"
        ),
        description=(
            "A database query is being built by pasting values into the SQL string. "
            "If any of those values comes from a user, they can inject their own SQL "
            "— reading, changing, or deleting anything in your database."
        ),
        fix_prompt=(
            "A SQL query is built with string interpolation in {path} on line "
            "{line}. Rewrite it to use parameterized queries (placeholders like ? or "
            "$1 with values passed separately), and check the rest of the file for "
            "the same pattern."
        ),
        extensions=JS_PY,
    ),
    Rule(
        id="shell-command-interpolation",
        title="Shell command built from variables",
        severity="high",
        pattern=re.compile(r"os\.system\(\s*f[\"']|\bexecSync?\(\s*`[^`\n]*\$\{"),
        description=(
            "A shell command is being built by pasting variables into the command "
            "string. If any variable comes from user input, an attacker can run "
            "their own commands on your server."
        ),
        fix_prompt=(
            "A shell command is built from variables in {path} on line {line}. "
            "Replace it with an API that passes arguments as a list (e.g. "
            "subprocess.run([...]) or execFile) so user input can never be "
            "interpreted as part of the command."
        ),
        extensions=JS_PY,
    ),
    Rule(
        id="subprocess-shell-true",
        title="subprocess with shell=True",
        severity="low",
        pattern=re.compile(r"\bshell\s*=\s*True"),
        description=(
            "Running subprocesses with shell=True is risky if any part of the "
            "command can be influenced by user input. Worth a look even if it's "
            "currently safe."
        ),
        fix_prompt=(
            "subprocess is called with shell=True in {path} on line {line}. If the "
            "command includes any variable data, rewrite it as "
            "subprocess.run([...]) with a list of arguments and shell=False."
        ),
        extensions=PY,
    ),
    Rule(
        id="innerhtml-assignment",
        title="HTML built from strings (XSS risk)",
        severity="medium",
        pattern=re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML"),
        description=(
            "Setting innerHTML (or dangerouslySetInnerHTML) with anything derived "
            "from user input lets attackers inject scripts into your page — stealing "
            "sessions or defacing your app for other users."
        ),
        fix_prompt=(
            "innerHTML is assigned in {path} on line {line}. If the content includes "
            "any user-provided data, switch to textContent, or sanitize the HTML "
            "with a library like DOMPurify before inserting it."
        ),
        extensions=JS,
    ),
    Rule(
        id="eval-usage",
        title="eval() used",
        severity="low",
        pattern=re.compile(r"(?<![A-Za-z0-9_.])eval\s*\("),
        description=(
            "eval() executes whatever string it's given as code. If that string can "
            "be influenced by user input, it's full code execution in your app."
        ),
        fix_prompt=(
            "eval() is used in {path} on line {line}. Replace it with a safer "
            "alternative (JSON.parse for data, a lookup table for dynamic behavior). "
            "If it must stay, confirm the input can never contain user-provided "
            "text."
        ),
        extensions=JS_PY,
    ),
]

# Repo-level finding produced by the scanner, not by a regex.
ENV_NOT_IGNORED = Rule(
    id="env-file-not-gitignored",
    title=".env file is not protected by .gitignore",
    severity="high",
    pattern=re.compile(r"(?!x)x"),  # never matched directly; produced by the scanner
    description=(
        "Your project has a .env file (where secrets belong) but .gitignore does "
        "not exclude it. That means one 'git push' — by you or your AI tool — "
        "publishes every secret in it."
    ),
    fix_prompt=(
        "My project's {path} file is not covered by .gitignore. Add '.env' and "
        "'.env.*' to .gitignore, then check whether the file was ever committed "
        "(git log --all -- {path}); if it was, remind me to rotate every credential "
        "inside it and rewrite it out of git history."
    ),
)
