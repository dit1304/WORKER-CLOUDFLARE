# Cloudflare Workers VPN Deployment

Auto-deploy Bot Telegram + VPN Worker (VLESS/Trojan) ke Cloudflare Workers menggunakan GitHub Actions.

## Struktur File

```
.
├── bot.js                          # Telegram Bot Worker
├── vltr.js                         # VPN Worker (VLESS/Trojan)
├── users.json                      # Daftar user bot (untuk KV BOT_USERS)
├── domains.json                    # Daftar wildcard domain (route ke vltr worker)
├── .github/
│   └── workflows/
│       └── deploy.yml              # GitHub Actions workflow
└── README.md
```

## Setup

### 1. Fork / Clone Repository

```bash
git clone https://github.com/dit1304/CLOUDFLARE-WORKER.git
cd CLOUDFLARE-WORKER
```

### 2. Tambahkan GitHub Secrets

Buka **Settings** > **Secrets and Variables** > **Actions** di repository GitHub, lalu tambahkan secrets berikut:

| Secret Name | Deskripsi |
|---|---|
| `CF_API_TOKEN` | Cloudflare API Token |
| `CF_ACCOUNT_ID` | Cloudflare Account ID |
| `CF_ZONE_ID` | Cloudflare Zone ID |
| `BOT_TOKEN` | Token Bot Telegram (dari @BotFather) |
| `ADMIN_USERNAME` | Username admin Telegram (contoh: @username) |
| `SERVER_VLESS` | Domain server VLESS |
| `SERVER_TROJAN` | Domain server Trojan |
| `SERVER_WILDCARD` | Domain server Wildcard |
| `PASS_UID` | UUID/Password VPN |
| `API_URL` | URL API backup |
| `KV_NAMESPACE_ID` | Cloudflare KV Namespace ID |
| `GH_TOKEN` | GitHub Personal Access Token (untuk auto-sync users) |
| `GITHUB_REPO` | Nama repository GitHub (contoh: `dit1304/CLOUDFLARE-WORKER`) |

### 3. Deploy

Push ke branch `main` untuk trigger deployment otomatis:

```bash
git add .
git commit -m "Initial deploy"
git push origin main
```

Atau jalankan workflow manual dari tab **Actions** di GitHub.

### 4. Migrasi ke Akun CF Baru

1. Buka **Settings** > **Secrets** di GitHub
2. Update `CF_API_TOKEN`, `CF_ACCOUNT_ID`, `CF_ZONE_ID`
3. Buat KV Namespace baru di akun baru, update `KV_NAMESPACE_ID`
4. Re-run workflow dari tab **Actions**

## Workers

- **vpn-bot**: Bot Telegram untuk manage VPN (VLESS/Trojan)
- **vpn-vltr**: VPN proxy worker yang handle koneksi VLESS & Trojan

## Auto-Sync User

Bot otomatis menyinkronkan daftar user ke `users.json` di GitHub setiap ada user baru yang mendaftar atau dihapus. Untuk mengaktifkan fitur ini:

1. Buat **Personal Access Token** di GitHub (**Settings** > **Developer Settings** > **Personal Access Tokens** > **Fine-grained tokens**)
2. Beri permission **Contents: Read and Write** untuk repository ini
3. Simpan token sebagai secret `GH_TOKEN` di GitHub Actions
4. Simpan nama repo sebagai secret `GITHUB_REPO` (format: `username/repo-name`)

## Wildcard Domains

File `domains.json` berisi daftar domain wildcard yang otomatis di-route ke vltr worker saat deploy. Format file:

```json
[
  "bug.wildcard.com",
  "cdn.wildcard.com",
  "speed.wildcard.com"
]
```

**Cara menambah domain baru:**
1. Edit file `domains.json` di GitHub (tambah domain baru ke array)
2. Commit & push, atau re-run workflow dari tab Actions
3. Domain otomatis ter-route ke vltr worker di Cloudflare

**Catatan penting:**
- Pastikan domain sudah ditambahkan di Cloudflare DNS (CNAME atau A record, proxy aktif/awan oranye)
- Setiap domain akan di-route dengan pattern `domain/*` ke vltr worker
- Zone ID dari GitHub Secrets `CF_ZONE_ID` digunakan untuk routing

## Catatan

- Semua token dan secrets disimpan aman di GitHub Secrets
- Tidak ada informasi sensitif yang tersimpan di kode
- Deploy otomatis setiap push ke branch `main`
- User baru yang daftar di bot otomatis ter-sync ke GitHub
- Wildcard domain di-route otomatis dari `domains.json`
- Untuk manual deploy, gunakan tab Actions > Run workflow
