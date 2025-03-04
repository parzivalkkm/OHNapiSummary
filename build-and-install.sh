#!/bin/bash

set -e

if [[ "$1" != 'nobuild' ]]; then
  bash ./gradlew buildExtension || exit 1
fi

echo Install to "~/.ghidra/.ghidra_10.1.2_PUBLIC/Extensions/OHNativeSummary"
rm -r "~/.ghidra/.ghidra_10.1.2_PUBLIC/Extensions/OHNativeSummary" || true

pushd dist
unset -v latest
for file in ./*; do
  [[ $file -nt $latest ]] && latest=$file
done
echo using $latest
mkdir -p ~/.ghidra/.ghidra_10.1.2_PUBLIC/Extensions/
unzip -o "$latest" -d ~/.ghidra/.ghidra_10.1.2_PUBLIC/Extensions/
#unzip -o "$latest" -d /opt/ghidra_10.1.2_PUBLIC/Ghidra/Extensions/
# 7zz x "$latest" -o~/.ghidra/.ghidra_10.1.2_PUBLIC/Extensions/OHNativeSummary -y
popd
