# Perbaikan startup volume

Log terbaru menunjukkan `sqlite3.OperationalError: unable to open database file`. Validasi kunci enkripsi telah terlewati. Penyebab paling mungkin adalah volume yang dimount memiliki ownership root sedangkan proses aplikasi lama berjalan sebagai UID 10001.

Dockerfile sekarang menjalankan entrypoint yang menyiapkan ownership DATA_DIR dan file database aplikasi sebelum menurunkan hak akses ke UID/GID 10001. Tidak ada penghapusan database, migrasi destruktif, penggantian kunci, atau fallback ke penyimpanan sementara.

Deploy ulang sumber dari ZIP ini. Pertahankan seluruh ENV yang valid, `DATA_DIR=/data`, dan volume lama dengan mount path `/data`. Gunakan ENTRYPOINT Dockerfile bawaan, jangan override dengan perintah `python app.py` yang melewatkan penyiapan izin. Jangan hapus volume.

Validasi lokal mencakup permintaan perubahan ownership yang tepat (mock karena filesystem pengujian tidak mendukung chown UID lain), izin file, penolakan direktori sistem, pelestarian baris database, dan pengujian alur aplikasi. Perubahan ownership nyata serta deploy pada Railway pengguna belum diuji langsung; Docker runtime tidak tersedia di lingkungan pengujian.
