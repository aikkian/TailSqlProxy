#!/bin/bash
# Example retention job for TailSqlProxy audit logs.
#
# Serilog rolls daily-named files (audit-YYYYMMDD.log, audit-json-YYYYMMDD.log)
# but never deletes them. This script gzips files older than COMPRESS_AFTER_DAYS
# and deletes files (raw or .gz) older than DELETE_AFTER_DAYS.
#
# Tune the two values below to match your retention policy. Typical defaults
# below assume "fast grep for the last week, keep a month of history".
set -euo pipefail

LOGDIR="${LOGDIR:-/var/log/tailsqlproxy}"
COMPRESS_AFTER_DAYS="${COMPRESS_AFTER_DAYS:-7}"
DELETE_AFTER_DAYS="${DELETE_AFTER_DAYS:-30}"

find "$LOGDIR" -type f \
    \( -name 'audit-*.log' -o -name 'audit-json-*.log' \) \
    -mtime "+${COMPRESS_AFTER_DAYS}" \
    -exec gzip -- {} +

find "$LOGDIR" -type f \
    \( -name 'audit-*.log' -o -name 'audit-*.log.gz' \
       -o -name 'audit-json-*.log' -o -name 'audit-json-*.log.gz' \) \
    -mtime "+${DELETE_AFTER_DAYS}" \
    -delete
