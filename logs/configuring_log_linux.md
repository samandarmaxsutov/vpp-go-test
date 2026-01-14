1-bosqich: VPP xizmatini logni faylga yo'naltiradigan qilib sozlash
Avval VPP xizmati o'z chiqishini (output) biz xohlagan faylga yozishini ta'minlaymiz.

sudo systemctl edit --full vpp                                  ====>>>> buyrug'ini kiriting.

ExecStart qismini quyidagicha o'zgartiring (e'tibor bering, biz debug binar faylini va log yo'naltirishni ishlatamiz):


ExecStart=/bin/sh -c "/home/mitigator/vpp/build-root/install-vpp_debug-native/vpp/bin/vpp -c /etc/vpp/startup.conf 2>&1 | ts '[%%Y-%%m-%%d %%H:%%M:%%S]' >> /home/mitigator/vpp-go-test/logs/acl.log"

Loglar uchun papka yarating va huquqlarni bering:



mkdir -p /home/mitigator/vpp_logs
sudo chown -R mitigator:mitigator /home/mitigator/vpp-go-test/logs/




Xizmatni qayta ishga tushiring:



sudo systemctl daemon-reload
sudo systemctl restart vpp


==============================================================================================================================================================


2-bosqich: Logrotate konfiguratsiyasini yaratish
Endi Linuxga ushbu faylni har kuni yangilab turishni o'rgatamiz.

Yangi konfiguratsiya faylini yarating:



sudo nano /etc/logrotate.d/vpp-acl

Ichiga quyidagi matnni nusxalab joylang:



/home/mitigator/vpp_logs/acl.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    dateext
    dateformat -%Y-%m-%d
    copytruncate
    create 0644 mitigator mitigator
    su mitigator mitigator
}



--------------------------------------------------------------------------------------------------------------------------------------------------------------
Bu sozlamalar nima qiladi?

daily: Logni har kuni yangi faylga ko'chiradi.

rotate 7: Oxirgi 7 kunlik loglarni saqlaydi (eski loglar avtomatik o'chadi, disk to'lmaydi).

compress: Joy tejash uchun eski loglarni .gz formatida siqadi.

dateext & dateformat: Fayl nomiga siz xohlagandek sanani qo'shadi (masalan: acl.log-2026-01-14).

copytruncate: VPPni to'xtatmasdan log faylini tozalash imkonini beradi (VPP ishlashda davom etaveradi).



==============================================================================================================================================================

4-qadam: Qayta tekshirish
Endi buyruqni qayta ishga tushiring:



sudo logrotate -f /etc/logrotate.d/vpp-acl

Xatolik chiqmasa, demak hammasi to'g'ri. Endi natijani ko'rish uchun papkani tekshiring:



ls -l /home/mitigator/vpp_logs/

Siz u yerda acl.log (yangi va bo'sh) va acl.log-2026-01-14.gz (siqilgan eski log) fayllarini ko'rishingiz kerak.
















==============================================================================================================================================================

2. Linux "ts" (Timestamp) vositasidan foydalanish (Eng ishonchli usul)
VPP o'zi vaqt qo'sha olmasa, biz buni Linux darajasida hal qilamiz. Bu VPP kodiga yoki konfiguratsiyasiga bog'liq bo'lmagan eng barqaror usul.

Vositani o'rnating:



sudo apt-get update
sudo apt-get install moreutils



3. Natijani tekshirish
Xizmatni qayta ishga tushiring:



sudo systemctl daemon-reload
sudo systemctl restart vpp
Endi logingiz quyidagicha ko'rinishda bo'ladi: [2026-01-14 10:55:01] vpp[171168]: acl_plugin: ACL_DROP: interface:1...