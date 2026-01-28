sudo mkdir -p /dev/shm/vpp
sudo chown vpp:vpp /dev/shm/vpp 


sudo systemctl restart vpp

sudo modprobe vfio-pci

echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode


# 1. Ensure the directory is created on every boot
echo "d /dev/shm/vpp 0755 vpp vpp -" | sudo tee /etc/tmpfiles.d/vpp.conf

# 2. Load the driver on boot
echo "vfio-pci" | sudo tee /etc/modules-load.d/vpp.conf

# 3. Enable the unsafe mode for the driver
echo "options vfio enable_unsafe_noiommu_mode=Y" | sudo tee /etc/modprobe.d/vfio.conf