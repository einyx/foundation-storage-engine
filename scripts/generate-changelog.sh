#!/usr/bin/env bash

set -euo pipefail

tag="${1:-}"
output_file="${2:-CHANGELOG.md}"

if [[ -z "${tag}" ]]; then
  echo "Usage: $0 <tag> [output_file]" >&2
  exit 1
fi

previous_tag=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | grep -v "^${tag}$" | head -n1 || true)

{
  echo "# Changelog"
  echo
  echo "## ${tag} - $(date -u '+%Y-%m-%d')"
  echo
  if [[ -n "${previous_tag}" ]]; then
    git log "${previous_tag}..HEAD" --pretty='- %s (%h)'
  else
    git log --pretty='- %s (%h)'
  fi
  echo
} > "${output_file}"
