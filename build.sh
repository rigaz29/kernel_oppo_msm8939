
#!/bin/bash
BUILD_START=$(date +"%s")
tcdir=${HOME}/android/TOOLS/GCC

[ -d "out" ] && rm -rf out && mkdir -p out || mkdir -p out

# 1. Hapus sisa file kernel, dt, dan modul lama di folder anykernel3
rm -f anykernel3/Image anykernel3/Image.gz anykernel3/Image.gz-dtb anykernel3/zImage* anykernel3/dt anykernel3/dt.img anykernel3/dtb
rm -rf anykernel3/modules

make O=out ARCH=arm64 lineageos_a37f_defconfig

# 2. Compile Image (mentah), dtbs, dan modules
PATH="$tcdir/los-4.9-64/bin:$tcdir/los-4.9-32/bin:${PATH}" \
make -j$(nproc --all) O=out \
    ARCH=arm64 \
    CC="ccache $tcdir/los-4.9-64/bin/aarch64-linux-android-gcc" \
    CROSS_COMPILE=aarch64-linux-android- \
    CROSS_COMPILE_ARM32=arm-linux-androideabi- \
    CONFIG_NO_ERROR_ON_MISMATCH=y \
    CONFIG_DEBUG_SECTION_MISMATCH=y \
    Image dtbs modules || exit 1
    
# 3. Generate dt.img baru menggunakan dtbtool.c (QCDT v2)
if [ -f "anykernel3/dtbtool.c" ]; then
    gcc -O2 -o anykernel3/dtbtool anykernel3/dtbtool.c
    DTB_DIR=$(find out/arch/arm64/boot/dts -name "*.dtb" -printf "%h\n" | head -n 1)
    if [ -n "$DTB_DIR" ]; then
        echo "Menjalankan dtbtool pada direktori: $DTB_DIR"
        ./anykernel3/dtbtool -2 -s 2048 -o out/arch/arm64/boot/dt.img -p out/scripts/dtc/ "$DTB_DIR/"
    else
        echo "ERROR: File .dtb tidak ditemukan di out/arch/arm64/boot/dts!"
        exit 1
    fi
    rm -f anykernel3/dtbtool
else
    echo "ERROR: anykernel3/dtbtool.c tidak ditemukan!"
    exit 1
fi

# 4. Pastikan Image (mentah) dan dt.img berhasil dibuat
if [ ! -f "out/arch/arm64/boot/Image" ] || [ ! -f "out/arch/arm64/boot/dt.img" ]; then
    echo "ERROR: Image atau dt.img gagal dibuat!"
    exit 1
fi

# Salin Image mentah dan dt.img / dt ke anykernel3
cp out/arch/arm64/boot/Image anykernel3/
cp out/arch/arm64/boot/dt.img anykernel3/dt.img
cp out/arch/arm64/boot/dt.img anykernel3/dt

# 5. Salin modul .ko (seperti wlan.ko / pronto_wlan.ko) jika dihasilkan oleh defconfig
mkdir -p anykernel3/modules/system/lib/modules
find out/ -name "*.ko" -exec cp {} anykernel3/modules/system/lib/modules/ \;

echo "Isi folder anykernel3 sebelum di-zip:"
ls -lh anykernel3/
ls -lh anykernel3/modules/system/lib/modules/

( cd anykernel3; zip -r ../out/A37F_KERNEL_LOS22_$(date +%d.%m.%Y).zip * -x 'LICENSE' 'README.md' 'dtbtool.c' )

BUILD_END=$(date +"%s")
DIFF=$(($BUILD_END - $BUILD_START))
echo -e "\e[1;32mBuild completed in $(($DIFF / 60)) minute(s) and $(($DIFF % 60)) seconds.\e[0m"
