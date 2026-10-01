# Watari

Watari は、内部マイクロサービスや関門HQ他サービス（Kura/Portico等）から外部 SaaS（Stripe, SendGrid, Twilio, OpenAI等）へ出る**アウトバウンド（Egress）トラフィックを、安全・一元的に保護・制御・監査する超軽量リバースプロキシ**です。

---

## 1. コア機能

1. **Dynamic Secret Injection**:
   - アプリケーションは外部 SaaS の API キーを直接保持せず、`X-Tenant-ID` などの識別ヘッダーのみを送信。
   - Watari がテナント・プロバイダー設定に対応する外部 API キー（`Authorization: Bearer sk_live_...` 等）をストレージから取得し、動的注入して転送。
2. **Egress SSRF & Domain Allowlist**:
   - 事前登録された許可ドメイン（FQDN: 例 `api.stripe.com`）以外へのアウトバウンド通信を即時遮断 (`403 Forbidden`)。
   - DNS 解決後の内部/プライベート IP レンジへのアクセスや DNS rebinding を多層防御。
3. **同期型レート制御（Token Bucket + Micro-Delay）**:
   - `tenant_id` × `provider_id` 単位で外部 SaaS ごとの呼び出し上限（RPM/Burst）を管理（`governor`）。
   - スパイク時は微小スリープ（Micro-delay）で平滑化し、上限超過時は `429 Too Many Requests` を返却。
4. **インフライト自動リトライ & 指数バックオフ**:
   - 上流（外部 SaaS）から `429` や `503` を受信した際、`Retry-After` ヘッダーまたは Jitter 付き指数バックオフでインメモリ非同期スリープ後、裏で自動再送（最大N回）。
5. **相互認証（Shared Secret Validation） & キーローテーション**:
   - `X-Gateway-Secret` を定数時間比較（`subtle`）で検証。
   - `GATEWAY_SHARED_SECRET_PREVIOUS` による無停止シークレットローテーションをサポート。
6. **Prometheus メトリクス & ヘルスチェック**:
   - `/healthz`（統合）、`/livez`（Liveness）、`/readyz`（Readiness）
   - `/metrics`（Prometheus テキスト形式）

---

## 2. エンドポイント規約

| メソッド | パス | 説明 |
|---|---|---|
| `GET` | `/healthz` | 統合ヘルスチェック（`/livez` エイリアス） |
| `GET` | `/livez` | プロセス生存確認（Liveness probe） |
| `GET` | `/readyz` | トラフィック受信準備確認（Readiness probe） |
| `GET` | `/metrics` | Prometheus 形式メトリクス |
| `ANY` | `/v1/providers/{provider_id}/*path` | プロキシエンドポイント（関門標準） |
| `ANY` | `/u/{upstream}/{*path}` | プロキシエンドポイント（後方互換） |
| `GET` | `/admin/v1/providers` | プロバイダー設定一覧取得 |
| `POST` | `/admin/v1/providers` | プロバイダー設定登録・更新 |
| `DELETE` | `/admin/v1/providers/{tenant_id}/{provider_id}` | プロバイダー設定削除 |

---

## 3. クイックスタート

### ローカルでの起動（`cargo run`）

```bash
# 1. 必須設定
export HTTP_PORT="8080"
export GATEWAY_SHARED_SECRET="dev-gateway-shared-secret-local"
export ADMIN_API_KEY="dev-admin-api-key-local"
export STORAGE_BACKEND="memory"
export MEMORY_SEED_FILE="./examples/tenants.yaml"
export SECRET_BACKEND="env"

# 2. テナント用シークレット（examples/tenants.yaml に対応）
export STRIPE_KEY_TENANT_A="sk_test_mock_stripe_key_tenant_a_12345"
export SENDGRID_KEY_TENANT_A="SG.mock_sendgrid_key_tenant_a_67890"

# 3. 起動
cargo run
```

### コンテナでの起動（Docker Compose / `nerdctl`）

```bash
nerdctl compose up --build
```

---

## 4. 利用例

### 1. プロキシリクエスト（シークレット自動注入）

```bash
curl -X GET http://localhost:8080/v1/providers/stripe/v1/charges \
  -H "X-Tenant-ID: tenant-a" \
  -H "X-Gateway-Secret: dev-gateway-shared-secret-local"
```

### 2. 管理 API（プロバイダー設定の追加）

```bash
curl -X POST http://localhost:8080/admin/v1/providers \
  -H "Authorization: Bearer dev-admin-api-key-local" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-b",
    "upstream": "openai",
    "base_url": "https://api.openai.com",
    "inject": [{
      "header": "Authorization",
      "template": "Bearer {secret}",
      "secret_ref": "OPENAI_KEY_TENANT_B",
      "version": "latest"
    }],
    "rate_limit": {
      "rpm": 300,
      "burst": 30
    },
    "timeout_secs": 60
  }'
```

---

## 5. 環境変数一覧（関門HQ標準準拠）

| 環境変数名 | 既定値 | 必須 | 説明 |
|---|---|:---:|---|
| `HTTP_PORT` | `8080` | | Watari の受付ポート番号 |
| `LISTEN_ADDR` | `0.0.0.0:{HTTP_PORT}` | | HTTP 待受アドレス（指定時は優先） |
| `GATEWAY_SHARED_SECRET` | — | **必須** | 上流からの相互認証用シークレット（定数時間比較） |
| `GATEWAY_SHARED_SECRET_PREVIOUS` | — | | ローテーション用旧シークレット |
| `INSECURE_NO_GATEWAY_AUTH` | `false` | | 【開発専用】`true` の場合、相互認証をスキップ |
| `ADMIN_API_KEY` | — | | 管理 API (`/admin/v1/*`) の認証キー |
| `STORAGE_BACKEND` | `memory` | | 設定ストア種別 (`memory` / `sqlite` / `dynamodb`) |
| `SQLITE_PATH` | `/data/watari.db` | | SQLite 使用時の DB ファイルパス |
| `DYNAMODB_TABLE_NAME` | `watari_configs` | | DynamoDB 使用時のテーブル名 |
| `MEMORY_SEED_FILE` | `./examples/tenants.yaml` | | `memory` ストレージ用初期設定 YAML ファイル |
| `SECRET_BACKEND` | `env` | | シークレットストア種別 (`env` / `file` / `aws` / `gcp` / `azure`) |
| `SECRET_FILE_DIR` | — | | `file` バックエンド利用時のシークレット格納ディレクトリ |
| `SECRET_CACHE_TTL_SECS` | `300` | | シークレットキャッシュ有効期間（秒） |
| `SECRET_MAX_STALE_SECS` | `900` | | バックエンド障害時の stale シークレット最大許容期間（秒） |
| `TENANT_CACHE_TTL_SECS` | `60` | | テナント設定キャッシュ有効期間（秒） |
| `TENANT_CACHE_MAX_ENTRIES` | `10000` | | テナント設定キャッシュ最大エントリ数 |
| `MAX_RETRIES` | `3` | | 上流 429/503 受信時の最大インフライトリトライ回数 |
| `RETRY_BASE_BACKOFF_MS` | `100` | | 指数バックオフの基準時間（ミリ秒） |
| `LOG_LEVEL` | `info` | | ログレベル (`trace`, `debug`, `info`, `warn`, `error`) |
| `LOG_FORMAT` | `json` | | ログ出力フォーマット (`json` / `text`) |
| `ALLOW_PRIVATE_IPS` | `false` | | 【開発・テスト専用】SSRF ガードでプライベート IP 宛先を許可 |
| `ALLOW_INSECURE_UPSTREAM` | `false` | | 【開発・テスト専用】HTTP (非HTTPS) 上流への接続を許可 |

---

## 6. ライセンス

Apache-2.0
