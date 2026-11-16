# AnyKernel3 Ramdisk Mod Script
# osm0sis @ xda-developers
properties() { '
kernel.string=OPPO A37f Kernel by Sanditiana26
do.devicecheck=0
do.modules=1
do.systemless=0
do.cleanup=1
do.cleanuponabort=0
device.name1=A37
device.name2=A37f
device.name3=a37f
device.name4=
device.name5=
supported.versions=
'; }

block=/dev/block/bootdevice/by-name/boot;
is_slot_device=0;
ramdisk_compression=auto;

. tools/ak3-core.sh;

dump_boot;

ui_print "*******************************************"
ui_print "Updating Kernel & DTB for OPPO A37f..."
ui_print "Built by Sanditiana26 (LineageOS 23.2)"
ui_print "*******************************************"

write_boot;
