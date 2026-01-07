# Log va socket kataloglarini yaratish va ruxsat berish
sudo mkdir -p /var/log/vpp
sudo mkdir -p /run/vpp
sudo chown -R vpp:vpp /var/log/vpp
sudo chown -R vpp:vpp /run/vpp
sudo chmod -R 775 /run/vpp

# Stats socket uchun ruxsat
sudo chown root:vpp /dev/shm/vpp/stats.sock
sudo chmod 770 /dev/shm/vpp/stats.sock