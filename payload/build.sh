#!/bin/sh
set -eu

tool_prefix=${TOOL_PREFIX:-v850-elf-}
build_dir=build
shellcode_limit=4048
mkdir -p "$build_dir"

for name in probe_pe_cycle crc_probe crc_intermediate crc_verify write_target_candidate write_crc_candidate; do
  "${tool_prefix}gcc" -Oz -ffreestanding -fno-builtin -fno-stack-protector \
    -fno-tree-loop-distribute-patterns -mno-prolog-function \
    -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
    -c "$name.c" -o "$build_dir/$name.o"
  linker=linker.ld
  if [ "$name" = write_target_candidate ] || [ "$name" = write_crc_candidate ]; then
    linker=linker_intent.ld
  fi
  "${tool_prefix}ld" --gc-sections -Map "$build_dir/$name.map" \
    -T "$linker" "$build_dir/$name.o" -o "$build_dir/$name.elf"
  "${tool_prefix}objcopy" -O binary "$build_dir/$name.elf" "$build_dir/$name.bin"
  size=$(wc -c < "$build_dir/$name.bin" | tr -d ' ')
  if [ "$size" -gt "$shellcode_limit" ]; then
    echo "$name payload is $size bytes; limit is $shellcode_limit" >&2
    rm -f "$build_dir/$name.bin"
    exit 1
  fi
done

gcc_version=$("${tool_prefix}gcc" -dumpfullversion)
binutils_version=$("${tool_prefix}objcopy" --version | sed -n '1s/.* //p')
sha256_file() { sha256sum "$1" | cut -d ' ' -f 1; }

printf '{\n  "toolchain": {"gcc": "%s", "binutils": "%s"},\n  "sources": {\n' \
  "$gcc_version" "$binutils_version" > "$build_dir/manifest.json"
sources='probe_pe_cycle.c crc_probe.c crc_intermediate.c crc_verify.c write_target_candidate.c write_crc_candidate.c common.h protocol.h dcra.h patch_common.h patch_protocol.h crc_runtime.h candidate_writer.h faci_dual.h linker.ld linker_intent.ld build.sh'
last_source=build.sh
for source in $sources; do
  comma=,
  [ "$source" = "$last_source" ] && comma=
  printf '    "%s": "%s"%s\n' "$source" "$(sha256_file "$source")" "$comma" \
    >> "$build_dir/manifest.json"
done
printf '  },\n  "payloads": {\n' >> "$build_dir/manifest.json"
for name in probe_pe_cycle crc_probe crc_intermediate crc_verify write_target_candidate write_crc_candidate; do
  size=$(wc -c < "$build_dir/$name.bin" | tr -d ' ')
  digest=$(sha256_file "$build_dir/$name.bin")
  comma=,
  [ "$name" = write_crc_candidate ] && comma=
  if [ "$name" = probe_pe_cycle ]; then
    printf '    "%s": {"size": %s, "sha256": "%s", "entrypoint": "0xfebf0000"}%s\n' \
      "$name" "$size" "$digest" "$comma" >> "$build_dir/manifest.json"
  else
    printf '    "%s": {"size": %s, "sha256": "%s"}%s\n' \
      "$name" "$size" "$digest" "$comma" >> "$build_dir/manifest.json"
  fi
done
printf '  }\n}\n' >> "$build_dir/manifest.json"

find "$build_dir" -type f \
  ! -name probe_pe_cycle.bin \
  ! -name crc_probe.bin \
  ! -name crc_intermediate.bin \
  ! -name crc_verify.bin \
  ! -name write_target_candidate.bin \
  ! -name write_crc_candidate.bin \
  ! -name manifest.json \
  -delete
