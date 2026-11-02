#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Answers two questions from the Image Vulnerability Scan's code scanning
# alerts:
#   1. Does main have a fixable critical or high finding? (fix it now)
#   2. Does a released image have one? (if main is clean, cut a release)
#
# The scan files each image's findings under the branch that produced it: the
# main-built images under main, and each component's release that `latest`
# carries under that release's branch. This script takes the release branch
# from the scan's own uploads, so the two cannot disagree about which release
# is current, reads the open Grype alerts per branch and counts them by
# severity. A branch is reported clean only when every one of its categories
# was scanned recently: no alerts on an image that was never scanned means
# nothing.
#
# Code scanning alerts need write access to the repository, so this is a
# maintainer tool, and its output is meant for a terminal, not for a public log.
set -euo pipefail

REPO="${REPO:-NVIDIA/nodewright}"
# The scan runs daily; a result older than this is reported as stale, not clean.
STALE_AFTER_HOURS="${STALE_AFTER_HOURS:-36}"

for tool in gh jq; do
  command -v "${tool}" >/dev/null || { echo "vuln-status: ${tool} is required" >&2; exit 1; }
done

# The newest Grype uploads, newest first. The daily scan makes about ten, so one
# page covers more than a week.
analyses="$(gh api "repos/${REPO}/code-scanning/analyses?tool_name=Grype&per_page=100")"

# last_scan <ref> <category...>: the oldest of the categories' newest successful
# uploads on <ref>, or "never" when any category has none.
last_scan() {
  local ref="$1"
  shift
  jq -r --arg ref "${ref}" '
    [ $ARGS.positional[] as $c
      | [ .[] | select(.ref == $ref and .category == $c and (.error // "") == "") | .created_at ] | max ]
    | if any(. == null) then "never" else min end' --args "$@" <<< "${analyses}"
}

# release_ref <category...>: the release branch the scan last filed these
# categories under.
release_ref() {
  jq -r '
    [ .[] | select(.ref != "refs/heads/main" and (.category as $c | $ARGS.positional | index($c))) ]
    | max_by(.created_at) | .ref // empty' --args "$@" <<< "${analyses}"
}

# freshness <timestamp|never>: prints nothing for a recent scan, otherwise why
# the counts cannot be trusted.
freshness() {
  if [ "$1" = never ]; then
    echo "not scanned"
  elif [ "$(jq -rn --arg t "$1" '(now - ($t | fromdateiso8601)) / 3600 | floor')" -ge "${STALE_AFTER_HOURS}" ]; then
    echo "stale: last scanned $1"
  fi
}

# counts <ref> <category...>: prints "<critical> <high> <other>" for open Grype
# alerts on <ref> whose most recent instance is in one of the categories.
#
# The severity is grype's own, the one the release gate's --fail-on reads, taken
# from the rule's short description ("<id> <severity> vulnerability for ...").
# GitHub's security_severity_level is not it: grype derives the security-severity
# it is computed from out of the CVSS score when there is one, so a finding grype
# rates high can show up there as medium. The SARIF level is grype's severity
# too, but merges critical and high into "error", so it is only the fallback.
counts() {
  local ref="$1" alerts
  shift
  alerts="$(gh api --paginate "repos/${REPO}/code-scanning/alerts?state=open&tool_name=Grype&ref=${ref}&per_page=100")"
  jq -rs '
    def severity:
      (try (.rule.description | capture("^\\S+ (?<s>[A-Za-z]+) vulnerability for ").s | ascii_downcase) catch null)
      // (if .rule.severity == "error" then "high" else "other" end);
    [ .[][] | select(.most_recent_instance.category as $c | $ARGS.positional | index($c)) | severity ]
    | [ (map(select(. == "critical")) | length),
        (map(select(. == "high")) | length),
        (map(select(. != "critical" and . != "high")) | length) ]
    | @tsv' --args "$@" <<< "${alerts}"
}

row() {
  printf '%-24s %-9s %5s %5s %6s  %s\n' "$@"
}

row REF IMAGE CRIT HIGH OTHER VERDICT

for component in operator agent; do
  categories=("grype-${component}" "grype-${component}-arm64")
  stale="$(freshness "$(last_scan refs/heads/main "${categories[@]}")")"
  result="$(counts refs/heads/main "${categories[@]}")"
  read -r crit high other <<< "${result}"
  if [ -n "${stale}" ]; then
    verdict="unknown (${stale})"
    printf -v "main_state_${component}" unknown
  elif [ $((crit + high)) -gt 0 ]; then
    verdict="fix on main"
    printf -v "main_state_${component}" blocked
  else
    verdict="clean"
    printf -v "main_state_${component}" clean
  fi
  row main "${component}" "${crit}" "${high}" "${other}" "${verdict}"
done

for component in operator agent cli; do
  if [ "${component}" = cli ]; then
    categories=(grype-cli grype-cli-windows)
  else
    categories=("grype-${component}" "grype-${component}-arm64")
  fi
  ref="$(release_ref "${categories[@]}")"
  if [ -z "${ref}" ]; then
    row - "${component}" - - - "unknown (no release scanned)"
    continue
  fi
  stale="$(freshness "$(last_scan "${ref}" "${categories[@]}")")"
  result="$(counts "${ref}" "${categories[@]}")"
  read -r crit high other <<< "${result}"
  main_var="main_state_${component}"
  if [ -n "${stale}" ]; then
    verdict="unknown (${stale})"
  elif [ $((crit + high)) -eq 0 ]; then
    verdict="clean"
  elif [ "${component}" = cli ]; then
    # The CLI is only built from tags, so there is no main-built CLI to compare.
    verdict="check main before releasing"
  elif [ "${!main_var}" = clean ]; then
    verdict="fixed on main: release ${component}"
  elif [ "${!main_var}" = blocked ]; then
    verdict="also on main: fix first"
  else
    verdict="main unknown: check it first"
  fi
  row "${ref#refs/heads/}" "${component}" "${crit}" "${high}" "${other}" "${verdict}"
done

echo
echo "Alerts: https://github.com/${REPO}/security/code-scanning?query=is%3Aopen+tool%3AGrype"
