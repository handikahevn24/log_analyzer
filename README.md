
# Log Analyzer

Log Analyzer adalah sebuah tool untuk menganalisis file log dari Laravel, Apache, dan Access log. Tool ini memudahkan pengguna dalam membaca, memfilter, dan menyimpan hasil analisis log dalam format JSON, yang dapat membantu dalam debugging dan monitoring.

## Fitur

- **Mendukung Laravel, Apache, dan Access Logs**: Dapat menganalisis berbagai jenis log dengan format yang berbeda.
- **Filter Berdasarkan Kriteria**: Dapat memfilter log berdasarkan tanggal, level error, status HTTP, dan metode HTTP.
- **Output dalam Format JSON**: Hasil analisis log dapat disimpan dalam file JSON yang rapi dan mudah dibaca.
- **CLI Support**: Memanfaatkan command line interface untuk fleksibilitas penggunaan.

## Instalasi

Untuk menggunakan Log Analyzer, Anda harus memiliki Rust terinstal di sistem Anda. Jika belum, Anda dapat menginstalnya dari [rustup.rs](https://rustup.rs/).

1. Clone repositori ini:

   ```bash
   git clone https://github.com/username/log-analyzer.git
   ```

2. Masuk ke direktori proyek:

   ```bash
   cd log-analyzer
   ```

3. Build proyek dengan Cargo:

   ```bash
   cargo build --release
   ```

4. Jalankan executable yang dihasilkan:

   ```bash
   ./target/release/log-analyzer
   ```

## Penggunaan

Tool ini bekerja melalui command line. Anda dapat menentukan jenis log yang ingin dianalisis serta filter opsional.

### Sintaks Dasar

```bash
log-analyzer [OPTIONS] <log_path>
```

### Contoh Penggunaan

1. **Menganalisis Laravel Log**

   ```bash
   log-analyzer --laravel /path/to/laravel.log --date="2024-08-22" --type="ERROR"
   ```

   Ini akan menganalisis Laravel log di path yang ditentukan, memfilter entri berdasarkan tanggal `2024-08-22` dan level error `ERROR`.

2. **Menganalisis Apache Log**

   ```bash
   log-analyzer --apache /path/to/apache.log --date="2024-08-22" --type="WARN"
   ```

   Ini akan menganalisis Apache log, memfilter berdasarkan tanggal dan tipe log `WARN`.

3. **Menganalisis Access Log**

   ```bash
   log-analyzer --access /path/to/access.log --status="404" --method="GET"
   ```

   Ini akan menganalisis Access log, memfilter hanya entri dengan status HTTP `404` dan metode `GET`.

## Opsi

- `--laravel`: Menandakan bahwa log yang dianalisis adalah Laravel log.
- `--apache`: Menandakan bahwa log yang dianalisis adalah Apache log.
- `--access`: Menandakan bahwa log yang dianalisis adalah Access log.
- `--log_path <log_path>`: Path ke file log yang akan dianalisis (wajib).
- `--date <date>`: Memfilter log berdasarkan tanggal (format: YYYY-MM-DD).
- `--type <type>`: Memfilter log berdasarkan level error (misalnya: ERROR, WARN).
- `--status <status>`: Memfilter Access logs berdasarkan status HTTP (misalnya: 200, 404).
- `--method <method>`: Memfilter Access logs berdasarkan metode HTTP (misalnya: GET, POST).

## Output

Hasil analisis log akan ditampilkan di terminal dalam format JSON dan dapat disimpan dalam file JSON di direktori :
- Pada Windows, file JSON akan disimpan di lokasi di mana Anda menjalankan tool log_analyzer.
- Pada Linux, file JSON akan disimpan di ~/logs/ (misalnya, /home/username/logs/).

## Kontribusi

Kontribusi selalu diterima! Silakan buat pull request atau buka issue untuk saran perbaikan atau fitur baru.

## Lisensi

Proyek ini dilisensikan di bawah lisensi MIT. Lihat file `LICENSE` untuk informasi lebih lanjut.

## Kontak

Dikembangkan oleh [Handika]. Untuk pertanyaan atau saran, hubungi [handikahevn24@gmail.com].
