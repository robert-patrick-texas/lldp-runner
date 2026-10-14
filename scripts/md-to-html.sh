#!/usr/bin/env bash

# Convert project Markdown documentation into standalone HTML pages.
#
# Markdown files are discovered recursively beneath the project directory and
# published into one flat web directory.  Local Markdown links are rewritten
# to the generated flat HTML names so documentation navigation keeps working.
#
# Last updated October 13, 2026.
#
# Prerequisite (Ubuntu/Debian):
#
#   sudo apt update
#   sudo apt install -y pandoc

set -euo pipefail

# Example production/shared-install defaults.  Uncomment or export overrides
# when the project is not located next to this script.
# PROJECT_DIR="${PROJECT_DIR:-/opt/lldp-runner}"
# WEB_ROOT="${WEB_ROOT:-/var/www/html}"
# PROJECT_NAME="${PROJECT_NAME:-lldp-runner}"

# By default, locate the project from this script and derive the web directory
# from the project directory name.  WEB_DOCS_DIR may override the final path.
script_reference="${BASH_SOURCE[0]}"
if [[ "$script_reference" != */* ]]; then
    script_reference="$(command -v -- "$script_reference" || true)"
fi

if [[ -z "$script_reference" ]]; then
    printf 'Error: unable to determine script location.\n' >&2
    exit 1
fi

script_path="$(readlink -f -- "$script_reference")"
script_dir="$(dirname -- "$script_path")"

PROJECT_DIR="${PROJECT_DIR:-${script_dir}/..}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"
PROJECT_NAME="${PROJECT_NAME:-}"
WEB_DOCS_DIR="${WEB_DOCS_DIR:-}"
PANDOC_BIN="${PANDOC_BIN:-pandoc}"

# An explicitly set REPO_URL, even an empty one, overrides pyproject.toml.
repo_url_overridden=0
[[ -z "${REPO_URL+x}" ]] || repo_url_overridden=1
REPO_URL="${REPO_URL-}"

usage()
{
    cat <<'USAGE'
Usage: scripts/md-to-html.sh [options]

Recursively convert project Markdown files to standalone HTML in a flat web
output directory and generate index.html.

Options:
  --project-dir PATH     Python/project source directory.
  --web-root PATH        Web root used with PROJECT_NAME.
  --project-name NAME    Published project directory name.
  --output-dir PATH      Explicit output directory; overrides --web-root/name.
  --repo-url URL         Source repository linked from index.html.  Defaults
                         to [project.urls] Repository in pyproject.toml; an
                         empty value omits the link.
  -h, --help             Show this help.

Environment overrides:
  PROJECT_DIR
  WEB_ROOT
  PROJECT_NAME
  WEB_DOCS_DIR
  PANDOC_BIN
  REPO_URL

Default output:
  /var/www/html/<project-directory-name>/
USAGE
}

die()
{
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --project-dir)
            (($# >= 2)) || die "--project-dir requires a value"
            PROJECT_DIR="$2"
            shift 2
            ;;
        --web-root)
            (($# >= 2)) || die "--web-root requires a value"
            WEB_ROOT="$2"
            shift 2
            ;;
        --project-name)
            (($# >= 2)) || die "--project-name requires a value"
            PROJECT_NAME="$2"
            shift 2
            ;;
        --output-dir)
            (($# >= 2)) || die "--output-dir requires a value"
            WEB_DOCS_DIR="$2"
            shift 2
            ;;
        --repo-url)
            (($# >= 2)) || die "--repo-url requires a value"
            REPO_URL="$2"
            repo_url_overridden=1
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

[[ -d "$PROJECT_DIR" ]] || die "project directory does not exist: $PROJECT_DIR"
PROJECT_DIR="$(cd -- "$PROJECT_DIR" && pwd -P)"

if [[ -z "$PROJECT_NAME" ]]; then
    PROJECT_NAME="$(basename -- "$PROJECT_DIR")"
fi

[[ -n "$PROJECT_NAME" ]] || die "project name is empty"
[[ "$PROJECT_NAME" != */* ]] || die "project name must not contain '/'"

if [[ -z "$WEB_DOCS_DIR" ]]; then
    WEB_DOCS_DIR="${WEB_ROOT%/}/${PROJECT_NAME}"
fi

[[ "$WEB_DOCS_DIR" = /* ]] || die "output directory must be an absolute path"
[[ "$WEB_DOCS_DIR" != "/" ]] || die "refusing to publish directly into /"

# Read a plain one-line Repository = "URL" entry from [project.urls].  This
# deliberately avoids a TOML parser dependency; other forms are ignored.
pyproject_repository_url()
{
    awk '
        /^[[:space:]]*\[/ {
            in_urls = ($0 ~ /^[[:space:]]*\[project\.urls\][[:space:]]*(#.*)?$/)
            next
        }
        in_urls {
            line = $0
            if (sub(/^[[:space:]]*"?Repository"?[[:space:]]*=[[:space:]]*"/, "", line) &&
                sub(/".*$/, "", line)) {
                print line
                exit
            }
        }
    ' "$1"
}

if ((!repo_url_overridden)) && [[ -f "${PROJECT_DIR}/pyproject.toml" ]]; then
    REPO_URL="$(pyproject_repository_url "${PROJECT_DIR}/pyproject.toml")"
fi

if [[ -n "$REPO_URL" ]]; then
    [[ "$REPO_URL" =~ ^https?://[^[:space:]]+$ ]] || \
        die "repository URL must be an http:// or https:// URL: $REPO_URL"
fi

command -v -- "$PANDOC_BIN" >/dev/null 2>&1 || \
    die "'${PANDOC_BIN}' was not found in PATH; install pandoc first"

# Do not publish Markdown that belongs to source-control internals, project
# virtual environments, caches, or build outputs.  These directories may
# contain third-party package documentation unrelated to the project itself.
mapfile -d '' markdown_files < <(
    find "$PROJECT_DIR" \
        \( -type d \( \
            -name .git -o \
            -name .venv -o \
            -name .pytest_cache -o \
            -name __pycache__ -o \
            -name build -o \
            -name dist \
        \) -prune \) -o \
        \( -type f -name '*.md' -print0 \) |
        sort -z
)

((${#markdown_files[@]} > 0)) || \
    die "no Markdown files were found beneath: $PROJECT_DIR"

if ! mkdir -p -- "$WEB_DOCS_DIR"; then
    die "unable to create output directory: $WEB_DOCS_DIR"
fi

[[ -w "$WEB_DOCS_DIR" ]] || \
    die "output directory is not writable: $WEB_DOCS_DIR"

build_dir="$(mktemp -d --tmpdir="$WEB_DOCS_DIR" .mdhtml-build.XXXXXX)"
trap 'rm -rf -- "$build_dir"' EXIT

manifest_name=".markdown-html-manifest"
manifest_path="${build_dir}/${manifest_name}"
: > "$manifest_path"

declare -A output_for_source=()
declare -A source_for_output=()

sanitize_flat_name()
{
    local rel_path="$1"
    local stem="${rel_path%.md}"
    local flat_name

    # Preserve a root-level Markdown basename as-is. For files below the
    # project root, flatten every directory separator to a hyphen so the
    # directory path remains visible in the published name. For example,
    # docs/CLI.md becomes docs-CLI.html.
    flat_name="${stem//\//-}"
    flat_name="$(printf '%s' "$flat_name" | sed 's/[^A-Za-z0-9._-]/_/g')"

    if [[ -z "$flat_name" ]]; then
        flat_name="document"
    fi

    printf '%s.html\n' "$flat_name"
}

for md_file in "${markdown_files[@]}"; do
    rel_path="${md_file#${PROJECT_DIR}/}"

    [[ "$rel_path" != *$'\n'* ]] || \
        die "Markdown filenames containing newlines are not supported"

    html_name="$(sanitize_flat_name "$rel_path")"

    if [[ -n "${source_for_output[$html_name]+x}" ]]; then
        path_hash="$(
            printf '%s' "$rel_path" |
                sha256sum | awk '{print substr($1,1,8)}'
        )"
        html_name="${html_name%.html}-${path_hash}.html"
    fi

    output_for_source["$rel_path"]="$html_name"
    source_for_output["$html_name"]="$rel_path"
done

# Build a small Pandoc Lua filter that rewrites links to local .md files.  The
# map is generated from the same filenames used for output, so flattened names
# and collision suffixes remain consistent everywhere.
lua_filter="${build_dir}/rewrite-md-links.lua"
{
    cat <<'LUA_HEAD'
local mapping = {
LUA_HEAD

    for rel_path in "${!output_for_source[@]}"; do
        lua_key="${rel_path//\\/\\\\}"
        lua_key="${lua_key//\"/\\\"}"
        lua_value="${output_for_source[$rel_path]//\\/\\\\}"
        lua_value="${lua_value//\"/\\\"}"
        printf '  ["%s"] = "%s",\n' "$lua_key" "$lua_value"
    done

    cat <<'LUA_BODY'
}

local source = os.getenv("LLDP_DOC_SOURCE_REL") or ""

local function dirname(path)
  return path:match("^(.*)/[^/]*$") or ""
end

local function normalize(path)
  local parts = {}

  for part in path:gmatch("[^/]+") do
    if part == ".." then
      if #parts > 0 then
        table.remove(parts)
      end
    elseif part ~= "." and part ~= "" then
      table.insert(parts, part)
    end
  end

  return table.concat(parts, "/")
end

function Link(link)
  local target = link.target

  if target:match("^%a[%w+.-]*:") or
     target:sub(1, 1) == "#" or
     target:sub(1, 1) == "/" then
    return link
  end

  local path, suffix = target:match("^([^#?]+)(.*)$")
  if not path or not path:lower():match("%.md$") then
    return link
  end

  local candidates = {}
  local source_dir = dirname(source)

  if source_dir ~= "" then
    table.insert(candidates, normalize(source_dir .. "/" .. path))
  else
    table.insert(candidates, normalize(path))
  end

  -- Also try a project-root-relative interpretation.  This is useful for
  -- README-style links such as docs/INSTALL.md.
  table.insert(candidates, normalize(path))

  for _, candidate in ipairs(candidates) do
    if mapping[candidate] then
      link.target = mapping[candidate] .. suffix
      return link
    end
  end

  return link
end
LUA_BODY
} > "$lua_filter"

# Shared presentation rules.  Preformatted text intentionally disables font
# ligatures and preserves whitespace so ASCII diagrams stay aligned.  Tables
# and long code blocks scroll horizontally rather than destroying page width.
html_head="${build_dir}/html-head.html"
cat > "$html_head" <<'HTML_HEAD'
<style>
  html {
    background: #ffffff;
    color: #24292f;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    max-width: 1100px;
    margin: 2rem auto;
    padding: 0 1.5rem 3rem;
    line-height: 1.6;
  }
  nav.doc-nav {
    margin: 0 0 1.5rem;
    padding-bottom: 0.75rem;
    border-bottom: 1px solid #d0d7de;
    font-size: 0.95rem;
  }
  h1, h2, h3, h4, h5, h6 {
    line-height: 1.25;
    margin-top: 1.5em;
  }
  h1, h2 {
    padding-bottom: 0.3em;
    border-bottom: 1px solid #d8dee4;
  }
  a {
    color: #0969da;
  }
  code, pre, kbd, samp {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
      "Liberation Mono", "Courier New", monospace;
    font-variant-ligatures: none;
  }
  :not(pre) > code {
    padding: 0.15em 0.35em;
    border-radius: 4px;
    background: #f6f8fa;
  }
  pre {
    overflow-x: auto;
    padding: 1rem;
    border: 1px solid #d8dee4;
    border-radius: 6px;
    background: #f6f8fa;
    line-height: 1.45;
    tab-size: 4;
    white-space: pre;
  }
  pre code {
    white-space: pre;
  }
  table {
    display: block;
    width: max-content;
    max-width: 100%;
    overflow-x: auto;
    border-collapse: collapse;
    margin: 1rem 0;
  }
  th, td {
    padding: 0.45rem 0.7rem;
    border: 1px solid #d0d7de;
    vertical-align: top;
  }
  th {
    background: #f6f8fa;
    font-weight: 600;
  }
  blockquote {
    margin-left: 0;
    padding-left: 1rem;
    border-left: 0.25rem solid #d0d7de;
    color: #57606a;
  }
  img {
    max-width: 100%;
    height: auto;
  }
</style>
HTML_HEAD

before_body="${build_dir}/before-body.html"
cat > "$before_body" <<'BEFORE_BODY'
<nav class="doc-nav"><a href="index.html">Documentation index</a></nav>
BEFORE_BODY

html_escape()
{
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g'
}

printf 'Publishing Markdown documentation from %s\n' "$PROJECT_DIR"
printf 'Output directory: %s\n\n' "$WEB_DOCS_DIR"

for md_file in "${markdown_files[@]}"; do
    rel_path="${md_file#${PROJECT_DIR}/}"
    html_name="${output_for_source[$rel_path]}"
    output_path="${build_dir}/${html_name}"

    printf 'Converting: %s -> %s\n' "$rel_path" "$html_name"

    LLDP_DOC_SOURCE_REL="$rel_path" \
        "$PANDOC_BIN" "$md_file" \
            --from=gfm \
            --to=html5 \
            --standalone \
            --wrap=none \
            --highlight-style=pygments \
            --lua-filter="$lua_filter" \
            --include-in-header="$html_head" \
            --include-before-body="$before_body" \
            --resource-path="$(dirname -- "$md_file"):${PROJECT_DIR}" \
            --variable="pagetitle:${PROJECT_NAME}: ${rel_path}" \
            --output="$output_path"

    printf '%s\n' "$html_name" >> "$manifest_path"
done

# Generate the flat documentation index after all output names are known.
index_path="${build_dir}/index.html"
{
    cat <<EOF_INDEX_HEAD
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(html_escape "$PROJECT_NAME") documentation</title>
EOF_INDEX_HEAD
    cat "$html_head"
    cat <<'EOF_INDEX_BODY'
</head>
<body>
<h1>Documentation Index</h1>
<p>Generated from Markdown files in the project source tree.</p>
EOF_INDEX_BODY

    if [[ -n "$REPO_URL" ]]; then
        printf '<p>Source repository: <a href="%s">%s</a></p>\n' \
            "$(html_escape "$REPO_URL")" \
            "$(html_escape "$REPO_URL")"
    fi

    printf '<ul>\n'

    for md_file in "${markdown_files[@]}"; do
        rel_path="${md_file#${PROJECT_DIR}/}"
        html_name="${output_for_source[$rel_path]}"
        printf '  <li><a href="%s">%s</a></li>\n' \
            "$(html_escape "$html_name")" \
            "$(html_escape "$rel_path")"
    done

    cat <<'EOF_INDEX_TAIL'
</ul>
</body>
</html>
EOF_INDEX_TAIL
} > "$index_path"
printf '%s\n' "index.html" >> "$manifest_path"

# Remove only files previously generated by this script.  Unknown files in the
# destination are left untouched so publishing documentation cannot erase
# unrelated web content accidentally.
old_manifest="${WEB_DOCS_DIR}/${manifest_name}"
if [[ -f "$old_manifest" ]]; then
    while IFS= read -r generated_name; do
        [[ -n "$generated_name" ]] || continue
        [[ "$generated_name" != */* ]] || \
            die "unsafe path found in old manifest: $generated_name"
        rm -f -- "${WEB_DOCS_DIR}/${generated_name}"
    done < "$old_manifest"
fi

# Publish only after every Pandoc conversion has succeeded.  This leaves the
# previous generated site in place if an earlier conversion fails.
while IFS= read -r generated_name; do
    [[ -n "$generated_name" ]] || continue
    mv -f -- "${build_dir}/${generated_name}" "${WEB_DOCS_DIR}/${generated_name}"
done < "$manifest_path"

cp -- "$manifest_path" "$old_manifest"

printf '\nConversion complete.\n'
printf 'Index: %s/index.html\n' "$WEB_DOCS_DIR"
