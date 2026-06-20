#!/usr/bin/env bash
# FEROXSEI OSINT — Leak Query Script
# Usage: ./query.sh <search_term> [data_dir]
# Searches email:password files for a matching email, domain, or keyword.
# Returns matching lines to stdout (one per line).
# Exit 0 = results found, Exit 1 = no results, Exit 2 = error.

QUERY="${1}"
DATA_DIR="${2:-$(dirname "$0")/data}"

if [[ -z "${QUERY}" ]]; then
    echo "Usage: $0 <query> [data_dir]" >&2
    exit 2
fi

if [[ ! -d "${DATA_DIR}" ]]; then
    echo "Data directory not found: ${DATA_DIR}" >&2
    exit 2
fi

QUERY_LOWER=$(echo "${QUERY}" | tr '[:upper:]' '[:lower:]')
FOUND=0

# If query looks like an email, try the first-letter bucket file first for speed
FIRST="${QUERY_LOWER:0:1}"
if [[ -f "${DATA_DIR}/${FIRST}.txt" ]]; then
    while IFS= read -r line; do
        LINE_LOWER=$(echo "${line}" | tr '[:upper:]' '[:lower:]')
        if [[ "${LINE_LOWER}" == *"${QUERY_LOWER}"* ]]; then
            echo "${line}"
            FOUND=1
        fi
    done < "${DATA_DIR}/${FIRST}.txt"
fi

# Also scan all other files for domain/keyword queries
for f in "${DATA_DIR}"/*.txt; do
    BASENAME=$(basename "${f}" .txt)
    if [[ "${BASENAME}" == "${FIRST}" ]]; then
        continue
    fi
    while IFS= read -r line; do
        LINE_LOWER=$(echo "${line}" | tr '[:upper:]' '[:lower:]')
        if [[ "${LINE_LOWER}" == *"${QUERY_LOWER}"* ]]; then
            echo "${line}"
            FOUND=1
        fi
    done < "${f}"
done

exit $((FOUND == 0 ? 1 : 0))
