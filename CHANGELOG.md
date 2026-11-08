# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versi mengikuti [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `tests/rule_parsing.rs` — 10 tes unit untuk lapisan parsing (`parse_line`,
  `split_options`, `unquote`, `find_sid_loose`, `Action`). Sebelumnya lapisan
  ini hanya teruji tidak langsung lewat dua berkas fixture.

### Fixed

- `find_sid_loose` menerima spasi setelah titik dua (`sid: 123`). Cabang ini
  hanya dipakai saat pass ketat gagal menemukan SID, jadi toleransi tambahan
  tidak mengubah hasil untuk ruleset yang valid — tapi menutup celah rule yang
  ditulis tangan dengan format longgar.

### Changed

- `CITATION.cff` ditambahkan agar artefak bisa disitasi (CFF 1.2.0).
- CI berjalan pada push ke `master`/`main`, pull request, dan `workflow_dispatch`.

## [0.1.0] — 2026-11-08

Rilis pertama. Dua pertanyaan yang benar-benar ditanyakan analis ke sebuah
ruleset, masing-masing jadi satu subperintah:

### Added

- `rulebench check` — validasi internal ruleset: header 7-field, `sid`/`rev`
  numerik, duplikat SID, `classtype` yang tidak dikenal, rule nonaktif (`#`).
- `rulebench coverage` — silang ruleset dengan `eve.json`: rule mati (tidak
  pernah menyala), SID tak dikenal, dan rasio rule mati.
- Laporan teks dan JSON (`report`), termasuk `top-N` rule paling sering menyala.
- Pembacaan `eve.json`/`eve.json.*` yang tahan baris rusak (`eve::read_eve`).
- Pemisahan opsi yang sadar-kutip, sehingga `msg:"a;b"` tidak memecah opsi.
- 3 tes integrasi CLI atas fixture ruleset dan `eve.json` contoh.

[Unreleased]: https://github.com/afiqandico/rulebench/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/afiqandico/rulebench/releases/tag/v0.1.0
