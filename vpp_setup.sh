sudo mkdir -p /dev/shm/vpp
sudo chown vpp:vpp /dev/shm/vpp 


sudo systemctl restart vpp

sudo modprobe vfio-pci

echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
