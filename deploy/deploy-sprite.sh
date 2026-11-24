#!/usr/bin/env bash
# Deploy fly-watchdog to a Sprite. Run from the repo root on the machine holding your Sprites credentials.
#   deploy/deploy-sprite.sh SPRITE CONFIG_JSON KEY_FILE
# Copies sprite/ + common/ (from the committed tree), the config and the HMAC key
# (mode 600) into the Sprite, then (re)creates the `watchdog` service on port 8080.
set -euo pipefail
SPRITE=$1 CONFIG=$2 KEY=$3
API="python3 deploy/sprites_api.py"
git diff --quiet HEAD -- sprite common || { echo "uncommitted changes in sprite/ or common/; commit first" >&2; exit 1; }
SHA=$(git rev-parse --short HEAD)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
git archive HEAD sprite common demo | gzip > "$TMP/code.tgz"
$API exec "$SPRITE" "mkdir -p ~/fly-watchdog/releases/$SHA && tar -xz -C ~/fly-watchdog/releases/$SHA && ln -sfn releases/$SHA ~/fly-watchdog/current && echo unpacked $SHA" "$TMP/code.tgz"
$API exec "$SPRITE" "cat > ~/fly-watchdog/config.json && echo config written" "$CONFIG"
$API exec "$SPRITE" "umask 077; mkdir -p ~/.config/fly-watchdog && cat > ~/.config/fly-watchdog/hmac.key && chmod 600 ~/.config/fly-watchdog/hmac.key && echo key written" "$KEY"
$API exec "$SPRITE" "sprite-env services delete watchdog >/dev/null 2>&1 || true; sprite-env services create watchdog --cmd python3 --args /home/sprite/fly-watchdog/current/sprite/watchdog.py --http-port 8080 && sleep 3 && sprite-env services list && curl -s localhost:8080/healthz"
echo "deployed $SHA to $SPRITE"
