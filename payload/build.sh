#!/bin/sh
set -eu

tool_prefix=${TOOL_PREFIX:-v850-elf-}
build_dir=build
shellcode_limit=4048
mkdir -p "$build_dir"

for name in probe_pe_cycle; do
  "${tool_prefix}gcc" -Oz -ffreestanding -fno-builtin -fno-stack-protector \
    -fno-tree-loop-distribute-patterns -mno-prolog-function \
    -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
    -c "$name.c" -o "$build_dir/$name.o"
  "${tool_prefix}ld" --gc-sections -Map "$build_dir/$name.map" \
    -T linker.ld "$build_dir/$name.o" -o "$build_dir/$name.elf"
  "${tool_prefix}objcopy" -O binary "$build_dir/$name.elf" "$build_dir/$name.bin"
done

size=$(wc -c < "$build_dir/probe_pe_cycle.bin" | tr -d ' ')
if [ "$size" -gt "$shellcode_limit" ]; then
  echo "probe_pe_cycle payload is $size bytes; limit is $shellcode_limit" >&2
  rm -f "$build_dir/probe_pe_cycle.bin"
  exit 1
fi

gcc_version=$("${tool_prefix}gcc" -dumpfullversion)
binutils_version=$("${tool_prefix}objcopy" --version | sed -n '1s/.* //p')
sha256_file() { sha256sum "$1" | cut -d ' ' -f 1; }
binary_hash=$(sha256_file "$build_dir/probe_pe_cycle.bin")

printf '{\n  "toolchain": {"gcc": "%s", "binutils": "%s"},\n  "sources": {\n' \
  "$gcc_version" "$binutils_version" > "$build_dir/manifest.json"
for source in probe_pe_cycle.c common.h protocol.h dcra.h linker.ld build.sh; do
  comma=,
  [ "$source" = build.sh ] && comma=
  printf '    "%s": "%s"%s\n' "$source" "$(sha256_file "$source")" "$comma" \
    >> "$build_dir/manifest.json"
done
printf '  },\n  "payloads": {\n    "probe_pe_cycle": {"size": %s, "sha256": "%s", "entrypoint": "0xfebf0000"}\n  }\n}\n' \
  "$size" "$binary_hash" >> "$build_dir/manifest.json"

find "$build_dir" -type f ! -name probe_pe_cycle.bin ! -name manifest.json -delete
