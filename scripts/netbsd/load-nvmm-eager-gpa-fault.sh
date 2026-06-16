#!/bin/sh
set -eu

usage() {
	echo "usage: $0 [--build-only]" >&2
	exit 2
}

load_module=1
case "${1:-}" in
"")
	;;
--build-only)
	load_module=0
	;;
*)
	usage
	;;
esac

if [ "$(uname -s)" != "NetBSD" ]; then
	echo "error: this script must run on a NetBSD host" >&2
	exit 1
fi

if [ "$(id -u)" != "0" ]; then
	echo "error: this script must run as root" >&2
	exit 1
fi

case "$0" in
/*)
	script_path=$0
	;;
*)
	script_path=$(pwd)/$0
	;;
esac
script_dir=$(dirname "$script_path")

src=${CARRICK_NETBSD_SRC:-/usr/src}
patch_file=${CARRICK_NVMM_PATCH:-"$script_dir/nvmm-eager-gpa-fault.patch"}
nvmm_c=$src/sys/dev/nvmm/nvmm.c
module_dir=$src/sys/modules/nvmm
backup=$nvmm_c.carrick-stock
stock_source=${CARRICK_NETBSD_STOCK_NVMM:-}

if [ ! -f "$patch_file" ]; then
	echo "error: patch file not found: $patch_file" >&2
	exit 1
fi
if [ ! -f "$nvmm_c" ]; then
	echo "error: NetBSD source tree not found at $src" >&2
	echo "set CARRICK_NETBSD_SRC=/path/to/src if syssrc is elsewhere" >&2
	exit 1
fi
if [ ! -d "$module_dir" ]; then
	echo "error: NVMM module directory not found: $module_dir" >&2
	exit 1
fi

if [ -n "$stock_source" ]; then
	if [ ! -f "$stock_source" ]; then
		echo "error: stock nvmm.c not found: $stock_source" >&2
		exit 1
	fi
	if grep -Eq "Carrick's nested NetBSD/NVMM|Carrick/NVMM nested-SVM" "$stock_source"; then
		echo "error: stock source appears patched: $stock_source" >&2
		exit 1
	fi
	cp "$stock_source" "$backup"
	cp "$stock_source" "$nvmm_c"
fi

if [ ! -f "$backup" ]; then
	if grep -Eq "Carrick's nested NetBSD/NVMM|Carrick/NVMM nested-SVM" "$nvmm_c"; then
		echo "error: $nvmm_c already appears patched and $backup is absent" >&2
		echo "restore a stock nvmm.c or set CARRICK_NETBSD_SRC to a clean source tree" >&2
		exit 1
	fi
	cp "$nvmm_c" "$backup"
fi
if grep -Eq "Carrick's nested NetBSD/NVMM|Carrick/NVMM nested-SVM" "$backup"; then
	echo "error: backup appears patched: $backup" >&2
	echo "restore a stock backup before rerunning" >&2
	exit 1
fi

cp "$backup" "$nvmm_c"
if ! patch -C -d "$src" -p0 < "$patch_file"; then
	cp "$backup" "$nvmm_c"
	echo "error: patch preflight failed; restored $nvmm_c from $backup" >&2
	exit 1
fi
cp "$backup" "$nvmm_c"
if ! patch -d "$src" -p0 < "$patch_file"; then
	cp "$backup" "$nvmm_c"
	echo "error: patch apply failed; restored $nvmm_c from $backup" >&2
	exit 1
fi

jobs=${JOBS:-}
if [ -z "$jobs" ]; then
	jobs=$(sysctl -n hw.ncpu 2>/dev/null || echo 2)
fi

(cd "$module_dir" && make USETOOLS=no -j"$jobs")

if [ "$load_module" -eq 0 ]; then
	echo "built $module_dir/nvmm.kmod"
	exit 0
fi

if /sbin/modstat | awk '$1 == "nvmm" { found = 1 } END { exit found ? 0 : 1 }'; then
	/sbin/modunload nvmm
fi
/sbin/modload "$module_dir/nvmm.kmod"
/sbin/modstat | awk '$1 == "nvmm" { print }'
echo "loaded transient Carrick NVMM eager-GPA-fault module"
