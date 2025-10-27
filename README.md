# APK/IPA Permission Analyzer

## Cara Pakai

1. Pastikan MobSF sudah berjalan di `http://localhost:5001` dan sudah ada endpoint `/api/v1/permissions_pdf`.
2. Pastikan sudah install dependensi Python (lihat `requirements.txt`).
3. Jalankan analisis APK/IPA dan dapatkan PDF permission-only:

```bash
bash scripts/analyze_permissions.sh /path/to/file.apk
```

- Hasil PDF permission-only akan tersimpan di `pdf_output/permission_report_<nama_file>.pdf`
- Hasil JSON lengkap akan tersimpan di `full_output/`

## Kebutuhan
- MobSF dengan endpoint `/api/v1/permissions_pdf`
- Python 3.10+
- wkhtmltopdf (untuk PDF rendering)
