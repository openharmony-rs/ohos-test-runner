#!/usr/bin/env bash
set -euo pipefail

image_dir="${1:-}"
connect_key="${2:-127.0.0.1:55555}"

if [ -z "$image_dir" ]; then
  echo "Usage: $0 <oniro-emulator-images-dir> [host:port]" >&2
  exit 1
fi

if [[ "$connect_key" != *:* ]]; then
  echo "Error: expected connect key in host:port form, got '$connect_key'." >&2
  exit 1
fi

forward_host="${connect_key%:*}"
forward_port="${connect_key##*:}"

if [ -z "$forward_host" ] || [ -z "$forward_port" ]; then
  echo "Error: expected connect key in host:port form, got '$connect_key'." >&2
  exit 1
fi

if [[ ! "$forward_port" =~ ^[0-9]+$ ]]; then
  echo "Error: expected numeric port in connect key, got '$connect_key'." >&2
  exit 1
fi

required_files=(
  "bzImage"
  "ramdisk.img"
  "updater.img"
  "system.img"
  "vendor.img"
  "userdata.img"
)

for required_file in "${required_files[@]}"; do
  if [ ! -f "$image_dir/$required_file" ]; then
    echo "Error: expected $image_dir/$required_file" >&2
    exit 1
  fi
done

cd "$image_dir"

# Based on the Oniro emulator release script, but adapted for CI:
# no KVM, no display stack, no audio device.
exec qemu-system-x86_64 \
  -machine q35 \
  -accel tcg,thread=multi \
  -cpu max \
  -smp 4 \
  -m 4096M \
  -boot c \
  -nographic \
  -vga none \
  -rtc base=utc,clock=host \
  -initrd ramdisk.img \
  -kernel bzImage \
  -drive if=none,file=updater.img,format=raw,id=updater,index=0 \
  -device virtio-blk-pci,drive=updater \
  -drive if=none,file=system.img,format=raw,id=system,index=1 \
  -device virtio-blk-pci,drive=system \
  -drive if=none,file=vendor.img,format=raw,id=vendor,index=2 \
  -device virtio-blk-pci,drive=vendor \
  -drive if=none,file=userdata.img,format=raw,id=userdata,index=3 \
  -device virtio-blk-pci,drive=userdata \
  -append "ip=dhcp loglevel=4 console=ttyS0,115200 init=init root=/dev/ram0 rw ohos.boot.hardware=x86_general ohos.required_mount.system=/dev/block/vdb@/usr@ext4@ro,barrier=1@wait,required ohos.required_mount.vendor=/dev/block/vdc@/vendor@ext4@ro,barrier=1@wait,required ohos.required_mount.misc=/dev/block/vda@/misc@none@none=@wait,required" \
  -netdev "user,id=net0,hostfwd=tcp:${forward_host}:${forward_port}-:55555" \
  -device virtio-net-pci,netdev=net0
