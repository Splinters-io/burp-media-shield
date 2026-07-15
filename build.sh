#!/usr/bin/env bash
# Build the Media Shield fat jar without Gradle — plain javac + jar.
# Downloads the Montoya API (compile-only) and the bundled runtime libs to ./.deps.
set -euo pipefail
cd "$(dirname "$0")"

MONTOYA_VER="2026.4"
MEXTRACT_VER="2.19.0"
XMPCORE_VER="6.1.11"
VERSION="1.0.0"

DEPS=".deps"
STAGE="build/stage"
OUT="build/classes"
JAR="build/libs/burp-media-shield-${VERSION}.jar"
CENTRAL="https://repo1.maven.org/maven2"

mkdir -p "$DEPS" build/libs
fetch() { # url dest
  [ -f "$2" ] || { echo "  downloading $(basename "$2")"; curl -fsSL -o "$2" "$1"; }
}
echo "== dependencies =="
fetch "$CENTRAL/net/portswigger/burp/extensions/montoya-api/$MONTOYA_VER/montoya-api-$MONTOYA_VER.jar" "$DEPS/montoya-api.jar"
fetch "$CENTRAL/com/drewnoakes/metadata-extractor/$MEXTRACT_VER/metadata-extractor-$MEXTRACT_VER.jar" "$DEPS/metadata-extractor.jar"
fetch "$CENTRAL/com/adobe/xmp/xmpcore/$XMPCORE_VER/xmpcore-$XMPCORE_VER.jar" "$DEPS/xmpcore.jar"

echo "== compile =="
rm -rf "$OUT" "$STAGE"; mkdir -p "$OUT" "$STAGE"
find src/main/java -name '*.java' > "$DEPS/sources.txt"
javac -d "$OUT" -cp "$DEPS/montoya-api.jar:$DEPS/metadata-extractor.jar" @"$DEPS/sources.txt"

echo "== assemble fat jar =="
cp -r "$OUT"/* "$STAGE"/
cp -r src/main/resources/* "$STAGE"/ 2>/dev/null || true
( cd "$STAGE" && jar xf "../../$DEPS/metadata-extractor.jar" && jar xf "../../$DEPS/xmpcore.jar" )
rm -rf "$STAGE/META-INF/MANIFEST.MF" "$STAGE/META-INF/maven"
find "$STAGE/META-INF" -type f \( -name '*.SF' -o -name '*.RSA' -o -name '*.DSA' \) -delete 2>/dev/null || true
mkdir -p "$STAGE/META-INF/services"
cp src/main/resources/META-INF/services/burp.api.montoya.BurpExtension "$STAGE/META-INF/services/"
jar cf "$JAR" -C "$STAGE" .
echo "== done: $JAR =="
