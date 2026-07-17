#!/usr/bin/env bash
# Reproducible test run for Media Shield — no Gradle, no JUnit.
#   tests/LogicTests.java       — detection, placeholder, data-URI/base64 rewrite, CSV, metadata
#   tests/RealWebSocketTest.java — stands up a real RFC-6455 server, connects with the JDK's real
#                                  WebSocket client, pushes real image bytes, and verifies the
#                                  shipped shield turns them orange (pixel-checked) end-to-end.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== building main classes + fetching deps (via build.sh) =="
./build.sh >/dev/null

TESTS_OUT="build/tests"
CP="build/classes:.deps/metadata-extractor.jar"
rm -rf "$TESTS_OUT"; mkdir -p "$TESTS_OUT"
javac -d "$TESTS_OUT" -cp "$CP" tests/*.java

echo
echo "############## Logic tests ##############"
java -cp "$TESTS_OUT:$CP" LogicTests

echo
echo "########## Real WebSocket test ##########"
java -cp "$TESTS_OUT:$CP" RealWebSocketTest
