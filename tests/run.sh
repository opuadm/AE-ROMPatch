#!/bin/sh
set -u

here=$(cd "$(dirname "$0")" && pwd)
bin=${AEROMPATCH:-$here/../aerompatch}
work=${TMPDIR:-/tmp}/aerompatch-tests.$$
pass=0
fail=0

for tool in python3 mke2fs lz4; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "skipping tests: $tool not found"
        exit 0
    fi
done

python3 "$here/fixtures.py" "$work" || { echo "fixture generation failed"; exit 1; }

t() {
    name=$1
    shift
    if "$@" >"$work/$name.log" 2>&1; then
        pass=$((pass + 1))
        echo "ok    $name"
    else
        fail=$((fail + 1))
        echo "FAIL  $name"
        sed 's/^/      /' "$work/$name.log" | tail -n 25
    fi
}

not() { ! "$@"; }

t info-classic "$bin" info "$work/fw"
t info-classic-warns sh -c "'$bin' info '$work/fw' 2>&1 | grep -q 'symlinks point outside'"
t info-mips-fails not "$bin" info "$work/mips"
t info-sar sh -c "'$bin' info '$work/sarfw' | grep -q 'system-as-root'"
t info-rejects-patch-opts not "$bin" info --density 200 "$work/fw"
t rejects-zip sh -c "printf 'PK\003\004xxxx' > '$work/x.zip'; ! '$bin' info '$work/x.zip'"

t patch-classic "$bin" patch -o "$work/classic.tar" --density 213 --enable no-bootanim,etc-alias \
    --set-prop persist.test=yes --del-prop ro.build.id --remove-app Bloat --remove-app Weather \
    --remove '/system/media/*.bin' --disable-service qseecomd --disable-service already \
    --disable-service rmt_storage "$work/fw"
t verify-classic python3 "$here/verify.py" classic "$work/classic.tar" "$work"

t patch-sar "$bin" patch -o "$work/sar.tar.gz" --set-prop ro.secure=0 "$work/sarfw"
t verify-sar python3 "$here/verify.py" sar "$work/sar.tar.gz"
t sar-trap-warning sh -c "'$bin' info '$work/sarfw' 2>&1 | grep -q 'big.zip'"

t patch-unchanged-boot "$bin" patch -q -o "$work/same.tar" --disable etc-alias,sanitize \
    --system "$work/system.raw" --boot "$work/fw/boot.img"
t verify-unchanged-boot python3 "$here/verify.py" unchanged_boot "$work/same.tar" "$work/fw/boot.img"

t patch-indirect "$bin" patch -q -o "$work/ind.tar" --system "$work/ind.img"
t verify-indirect python3 "$here/verify.py" indirect "$work/ind.tar" "$work"

t patch-folder "$bin" patch -q -o "$work/folder.tar" --root "$work/tree"
t refuses-overwrite not "$bin" patch -q -o "$work/folder.tar" --root "$work/tree"
t dry-run sh -c "'$bin' patch -n --remove-app Bloat '$work/fw' | grep -q 'Dry run' && [ ! -e '$work/none.tar' ]"
t bad-output-name not "$bin" patch -q -o "$work/out.rar" "$work/fw"

python3 "$here/zipfixtures.py" "$work" || { echo "zip fixture generation failed"; exit 1; }
t zip-cwm "$bin" patch -o "$work/cwm-ae.zip" --remove-app Bloat "$work/cwm.zip"
t verify-zip-cwm python3 "$here/verify.py" cwm "$work/cwm-ae.zip"
t zip-blockota "$bin" patch -q -o "$work/ota-ae.zip" --enable fake-battery "$work/blockota.zip"
t verify-zip-blockota python3 "$here/verify.py" blockota "$work/ota-ae.zip" "$work"
t zip-payload "$bin" patch -o "$work/ab-ae.zip" "$work/payload.zip"
t verify-zip-payload python3 "$here/verify.py" abota "$work/ab-ae.zip" "$work"
t zip-factory "$bin" patch -q -o "$work/fac-ae.zip" "$work/factory.zip"
t verify-zip-factory python3 "$here/verify.py" factory "$work/fac-ae.zip"
t zip-incremental-rejected sh -c "! '$bin' info '$work/incremental.zip' 2>&1 >/dev/null | grep -q never; '$bin' info '$work/incremental.zip' 2>&1 | grep -q 'incremental OTA'"
t unzip-test sh -c "! command -v unzip >/dev/null || unzip -tq '$work/cwm-ae.zip'"

python3 "$here/fwfixtures.py" "$work" || { echo "firmware fixture generation failed"; exit 1; }
t info-super sh -c "'$bin' info '$work/super.img' | grep -qi 'android 7'"
t samsung-zip "$bin" patch -o "$work/sam-ae.zip" "$work/SM-G991B_EUX_G991BXXU5CVF1_fac.zip"
t verify-samsung-zip python3 "$here/verify.py" samsung "$work/sam-ae.zip" "$work"
t samsung-dir "$bin" patch -q -o "$work/samdir-ae.zip" "$work/samsung-dir"
t verify-samsung-dir python3 "$here/verify.py" samsung "$work/samdir-ae.zip" "$work"
t samsung-tars "$bin" patch -q -o "$work/samtar-ae.zip" "$work/samsung-dir/AP_G991B.tar.md5" "$work/samsung-dir/CSC_OXM_G991B.tar.md5"
t verify-samsung-tars python3 "$here/verify.py" samsung "$work/samtar-ae.zip" "$work"
t samsung-old "$bin" patch -q -o "$work/samold-ae.zip" "$work/I9300XXUGNA7.tar.md5"
t verify-samsung-old python3 "$here/verify.py" tarimg "$work/samold-ae.zip"
t samsung-rfs-rejected sh -c "'$bin' info '$work/I9000XXJVU.tar.md5' 2>&1 | grep -q RFS"
t xiaomi-tgz "$bin" patch -q -o "$work/tgz-ae.zip" "$work/mido_global_images_V12.tgz"
t verify-xiaomi-tgz python3 "$here/verify.py" abota "$work/tgz-ae.zip" "$work"
if [ ! -e "$work/no-crypto" ]; then
    t ozip-whole "$bin" patch -q -o "$work/ozw-ae.zip" --remove-app Bloat "$work/CPH1607EX_11_OTA.ozip"
    t verify-ozip-whole python3 "$here/verify.py" cwm "$work/ozw-ae.zip"
    t ozip-member "$bin" patch -q -o "$work/ozm-ae.zip" --enable fake-battery "$work/RMX1851_member.ozip.zip"
    t verify-ozip-member python3 "$here/verify.py" blockota "$work/ozm-ae.zip" "$work"
    t ozip-mode2 "$bin" patch -q -o "$work/oz2-ae.zip" "$work/CPH1909_mode2.zip"
    t verify-ozip-mode2 python3 "$here/verify.py" abota "$work/oz2-ae.zip" "$work"
    t ozip-unknown-key sh -c "'$bin' info '$work/unknown-key.zip' 2>&1 | grep -q 'published OPPO'"
fi
mkdir -p "$work/oemh/system" "$work/oemh/vendor/etc/vintf" "$work/oemh/vendor/bin/hw" "$work/oemh/odm"
printf 'ro.build.version.sdk=28\nro.build.version.release=9\nro.product.system.brand=samsung\n' > "$work/oemh/system/build.prop"
printf '<manifest version="1.0" type="device">\n    <hal format="hidl">\n        <name>android.hardware.health</name>\n        <transport>hwbinder</transport>\n        <version>2.0</version>\n    </hal>\n    <hal format="hidl">\n        <name>vendor.samsung.hardware.exthealth</name>\n        <transport>hwbinder</transport>\n        <version>1.0</version>\n        <interface>\n            <name>IExtHealth</name>\n            <instance>exthealth</instance>\n        </interface>\n    </hal>\n</manifest>\n' > "$work/oemh/vendor/etc/vintf/manifest.xml"
printf '\177ELF0000000000000000000000000000000000000000000000000000000000000_ZN6vendor7samsung8hardware9exthealth4V1_010IExtHealth\n' > "$work/oemh/vendor/bin/hw/android.hardware.health@2.0-service.samsung"
ln -s /vendor/odm/etc "$work/oemh/odm/etc"
t oem-health "$bin" patch -q -o "$work/oemh.tar" --root "$work/oemh"
t verify-oem-health sh -c "tar xOf '$work/oemh.tar' vendor/odm/etc/vintf/manifest.xml > '$work/oemh.xml' && grep -q '<instance>exthealth</instance>' '$work/oemh.xml' && ! grep -q 'android.hardware.health<' '$work/oemh.xml' && tar xOf '$work/oemh.tar' odm.tar | tar tv | grep -q 'odm/etc -> /vendor/odm/etc'"
t oem-health-old-api sh -c "sed -i 's/sdk=28/sdk=27/' '$work/oemh/system/build.prop' && '$bin' patch -q -o '$work/oemh27.tar' --root '$work/oemh' && ! tar tf '$work/oemh27.tar' | grep -q odm/etc/vintf"
python3 "$here/elffixture.py" gen "$work/exy" || { echo "elf fixture generation failed"; exit 1; }
t exynos-gralloc sh -c "'$bin' patch -o '$work/exy.tar' --root '$work/exy' | grep -q 'Exynos buffer-handle check'"
t verify-exynos-gralloc python3 "$here/elffixture.py" check "$work/exy.tar"
t exynos-gralloc-off sh -c "'$bin' patch -q -o '$work/exy0.tar' --disable exynos-gralloc --root '$work/exy' && ! python3 '$here/elffixture.py' check '$work/exy0.tar' 2>/dev/null"
mkdir -p "$work/mh/system" "$work/mh/vendor/etc/sensors" && printf 'ro.build.version.sdk=28\nro.build.version.release=9\nro.product.cpu.abi=arm64-v8a\n' > "$work/mh/system/build.prop" && printf '/system/vendor/lib64/sensors.sensorhub.so\n/system/vendor/lib64/sensors.grip.so\n' > "$work/mh/vendor/etc/sensors/hals.conf"
t sensor-multihal sh -c "'$bin' patch -o '$work/mh.tar' --root '$work/mh' | grep -q 'sensors.sensorhub.so, sensors.grip.so' && ! tar tf '$work/mh.tar' | grep -q hals.conf"
t sensor-multihal-off sh -c "'$bin' patch -q -o '$work/mh0.tar' --disable sensor-multihal --root '$work/mh' && tar tf '$work/mh0.tar' | grep -q vendor/etc/sensors/hals.conf"
python3 -c "import re,sys; open(sys.argv[2],'wb').write(bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]{2})',open(sys.argv[1]).read())))" "$here/../src/patches/sensorhal.h" "$work/shal.so"
t sensor-hal sh -c "'$bin' patch -o '$work/sh.tar' --enable sensor-hal --root '$work/mh' | grep -q 'sensor-hal: added' && tar xOf '$work/sh.tar' odm.tar | tar xO odm/lib64/hw/sensors.aerompatch.so | cmp - '$work/shal.so' && tar xOf '$work/sh.tar' system/build.prop | grep -q '^ro.hardware.sensors=aerompatch'"
t sensor-hal-off sh -c "'$bin' patch -q -o '$work/sh0.tar' --disable sensor-hal --root '$work/mh' && ! tar tf '$work/sh0.tar' | grep -q sensors.aerompatch"
t sensor-multihal-old-api sh -c "sed -i 's/sdk=28/sdk=25/' '$work/mh/system/build.prop' && '$bin' patch -q -o '$work/mh25.tar' --root '$work/mh' && tar tf '$work/mh25.tar' | grep -q vendor/etc/sensors/hals.conf"
python3 "$here/elffixture.py" gen-sensor "$work/sret" || { echo "sensor fixture generation failed"; exit 1; }
t sensor-retry sh -c "'$bin' patch -o '$work/sret.tar' --root '$work/sret' | grep -q 'retries a failed sensor poll'"
t verify-sensor-retry python3 "$here/elffixture.py" check-sensor "$work/sret.tar"
t sensor-retry-again sh -c "mkdir -p '$work/sret2' && tar xf '$work/sret.tar' -C '$work/sret2' && ! '$bin' patch -o '$work/sret2.tar' --root '$work/sret2' 2>&1 | grep -q -e 'sensor-retry' -e 'retries a failed'"
t sensor-retry-off sh -c "'$bin' patch -q -o '$work/sret0.tar' --disable sensor-retry --root '$work/sret' && ! python3 '$here/elffixture.py' check-sensor '$work/sret0.tar' 2>/dev/null"
python3 "$here/elffixture.py" gen-hidl "$work/shidl" || { echo "hidl fixture generation failed"; exit 1; }
t sensor-hidl-guard sh -c "'$bin' patch -o '$work/shidl.tar' --root '$work/shidl' | grep -q '1 checks, 1 value asserts'"
t verify-sensor-hidl-guard python3 "$here/elffixture.py" check-hidl "$work/shidl.tar"
t sensor-hidl-guard-again sh -c "mkdir -p '$work/shidl2' && tar xf '$work/shidl.tar' -C '$work/shidl2' && ! '$bin' patch -o '$work/shidl2.tar' --root '$work/shidl2' 2>&1 | grep -q 'no longer aborts'"
t sensor-hidl-guard-off sh -c "'$bin' patch -q -o '$work/shidl0.tar' --disable sensor-retry --root '$work/shidl' && ! python3 '$here/elffixture.py' check-hidl '$work/shidl0.tar' 2>/dev/null"
mkdir -p "$work/res/system/etc" && printf 'ro.build.version.sdk=28\n' > "$work/res/system/build.prop" && printf '<?xml version="1.0" encoding="UTF-8" standalone="no" ?>\n<SecFloatingFeatureSet>\n    <SEC_FLOATING_FEATURE_COMMON_CONFIG_DYN_RESOLUTION_CONTROL>WQHD,FHD,HD</SEC_FLOATING_FEATURE_COMMON_CONFIG_DYN_RESOLUTION_CONTROL>\n    <SEC_FLOATING_FEATURE_LCD_SUPPORT_AMOLED_DISPLAY>TRUE</SEC_FLOATING_FEATURE_LCD_SUPPORT_AMOLED_DISPLAY>\n</SecFloatingFeatureSet>\n' > "$work/res/system/etc/floating_feature.xml"
t fixed-resolution sh -c "'$bin' patch -o '$work/res.tar' --root '$work/res' | grep -q 'resolution switch (WQHD,FHD,HD)'"
t verify-fixed-resolution sh -c "tar xOf '$work/res.tar' system/etc/floating_feature.xml > '$work/res.xml' && ! grep -q DYN_RESOLUTION '$work/res.xml' && grep -q AMOLED_DISPLAY '$work/res.xml' && grep -q '</SecFloatingFeatureSet>' '$work/res.xml'"
t fixed-resolution-off sh -c "'$bin' patch -q -o '$work/res0.tar' --disable fixed-resolution --root '$work/res' && tar xOf '$work/res0.tar' system/etc/floating_feature.xml | grep -q DYN_RESOLUTION"
mkdir -p "$work/hcm/system/framework/oat/arm64" && printf 'ro.build.version.sdk=28\n' > "$work/hcm/system/build.prop" && printf x > "$work/hcm/system/framework/hcm.jar" && printf x > "$work/hcm/system/framework/oat/arm64/hcm.odex" && printf x > "$work/hcm/system/framework/oat/arm64/hcm.vdex" && printf x > "$work/hcm/system/framework/oat/arm64/services.odex"
t no-hcm sh -c "'$bin' patch -o '$work/hcm.tar' --root '$work/hcm' | grep -q 'Samsung HCM service'"
t verify-no-hcm sh -c "! tar tf '$work/hcm.tar' | grep -q hcm && tar tf '$work/hcm.tar' | grep -q services.odex"
t no-hcm-off sh -c "'$bin' patch -q -o '$work/hcm0.tar' --disable no-hcm --root '$work/hcm' && tar tf '$work/hcm0.tar' | grep -q hcm.jar"
t sim-info sh -c "'$bin' info '$work/cwm.zip' | grep -q 'SIM'"

rm -rf "$work"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
