# Watari

Watari は、内部マイクロサービスから外部 SaaS（Stripe, SendGrid, Twilio, GitHub 等）への**アウトバウンド（Egress）通信を保護・制御するリバースプロキシ型エグレスプロキシ**です。

## 1. コア機能

1. **Dynamic Secret Injection**: アプリケーションは外部 SaaS の API キーを保持せず、`X-Tenant-ID` などの識別ヘッダーのみ送信します。Watari がテナント・upstream 設定に応じたシークレットを取得・注入して安全に上流へ転送します。
2. **Egress SSRF Guard & Allowlist**: 事前登録された名前付き upstream 宛先のみ通信を許可し、DNS名前解決後の内部/プライベートIPレンジへのアクセスや DNS rebinding を遮断します。
3. **Outbound Rate Limiting**: `tenant_id` × `upstream` 単位でローカル流量制御を実施（`governor`）。
4. **Streaming Forwarding**: リクエスト／レスポンスの本文をメモリに全体バッファリングせずストリーミング転送。

---

## 2. クイックスタート

### 起動方法

```bash
# 共有シークレットを設定
export GATEWAY_SHARED_SECRET="super-secret-gateway-token"
export STORAGE_BACKEND="memory"
export MEMORY_SEED_FILE="./examples/tenants.yaml"
export SECRET_BACKEND="env"

# テナントのAPIキーを環境変数に設定
export STRIPE_KEY_TENANT_A="sk_test_123456789"

# 起動
cargo run
```

### curl での利用例

```bash
curl -X POST http://localhost:8080/u/stripe/v1/charges \
  -H "X-Tenant-ID: tenant-a" \
  -H "X-Gateway-Secret: super-secret-gateway-token" \
  -d "amount=100&currency=jpy"
```

---

## 3. 設定（環境変数一覧）

| 環境変数名 | 既定値 | 必須 | 説明 |
|---|---|:---:|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` | | HTTP待受アドレス |
| `GATEWAY_SHARED_SECRET` | — | **必須** | `X-Gateway-Secret` 検証用共有シークレット（定数時間比較） |
| `STORAGE_BACKEND` | `memory` | | テナント設定ストレージ (`memory` / `sqlite`) |
| `SQLITE_PATH` | `./watari.db` | | SQLite データベースファイルのパス |
| `MEMORY_SEED_FILE` | `./tenants.yaml` | | `memory` ストレージ用初期設定 YAML ファイル |
| `SECRET_BACKEND` | `env` | | シークレットストア種別 (`env` / `file` / `aws`) |
| `SECRET_FILE_DIR` | — | | `file` バックエンド利用時のシークレット格納ディレクトリ |
| `SECRET_CACHE_TTL_SECS` | `300` | | シークレットキャッシュ有効期間（秒） |
| `SECRET_MAX_STALE_SECS` | `900` | | バックエンド障害時の stale シークレット最大許容期間（秒） |
| `TENANT_CACHE_TTL_SECS` | `60` | | テナント設定キャッシュ有効期間（秒） |
| `TENANT_CACHE_MAX_ENTRIES` | `10000` | | テナント設定キャッシュ最大エントリ数 |
| `LOG_LEVEL` | `info` | | ログレベル (`trace`, `debug`, `info`, `warn`, `error`) |
| `LOG_FORMAT` | `json` | | ログ出力フォーマット (`json` / `text`) |
| `ALLOW_PRIVATE_IPS` | `false` | | 【開発・テスト専用】SSRF ガードでプライベート IP 宛先を許可 |
| `ALLOW_INSECURE_UPSTREAM` | `false` | | 【開発・テスト専用】HTTP (非HTTPS) 上流への接続を許可 |

---

## 4. セキュリティモデル

### Watari が防ぐ脅威

- **アプリケーション層からのシークレット漏洩**: アプリケーションコード内に外部APIキーを持たせないため、アプリのログ漏洩や侵害時のシークレット流出を低減。
- **DNS Rebinding / SSRF (Server-Side Request Forgery)**:
  - 宛先は登録済み `base_url` ホストに限定。
  - DNS 解決後の IP を検証し、ループバック (`127.0.0.0/8`, `::1`)、プライベート (`10/8`, `172.16/12`, `192.168/16`)、リンクローカル (`169.254/16`, `fe80::/10`)、クラウドメタデータエンドポイント等の不正な宛先を遮断。
- **クライアントヘッダー改変・偽装**:
  - クライアントが送信した `Authorization`, `Cookie`, `Proxy-Authorization`, `Host`, hop-by-hop ヘッダーを強制削除。
  - `X-Gateway-Secret` は `subtle` クレートによる定数時間比較でタイミング攻撃を防ぐ。
- **ログへの機密情報混入防止**:
  - 構造化ログには `request_id`, `tenant_id`, `upstream`, `status`, `latency_ms` のみ出力し、リクエスト／レスポンス本文やヘッダー値は記録しない。
  - メモリ上では `secrecy::SecretString` および `HeaderValue::set_sensitive(true)` を使用。

### Watari が防がないもの（インフラ側で担保すべき事項）

- **外向き通信の固定グローバル IP 保持**: Watari は NAT ゲートウェイや固定 Egress IP を提供するものではなく、固定IP化は AWS NAT Gateway 等のインフラ側で設定します。
- **内部ネットワーク間の mTLS / ネットワーク分離**: アプリケーションから Watari への通信経路の暗号化・認証は、サービスメッシュまたは内部ネットワーク境界で担保してください。

---

## 5. Dependencies

Watari は OpenSSL に依存せず、Pure Rust / Rustls 実装により musl 静的リンクが可能です。

| クレート | 用途と選定理由 |
|---|---|
| `tokio` | 非同期ランタイム |
| `axum`, `tower`, `tower-http` | 高速かつ柔軟な HTTP サーバーおよびミドルウェア構築 |
| `reqwest` (`rustls-tls`, `stream`) | 非同期 HTTP クライアント。ストリーミング転送とカスタム DNS リゾルバによる SSRF ガードをサポート |
| `moka` (`future`) | 非同期メモリキャッシュ（テナント設定およびシークレットの single-flight / stale fallback キャッシュ） |
| `governor` | `tenant_id` × `upstream` 単位の高精度ローカルレート制限（GCRA アルゴリズム） |
| `sqlx` (`sqlite`, `runtime-tokio`) | SQLite ストレージバックエンド（Pure Rust / C 静的リンク対応） |
| `secrecy`, `zeroize` | メモリ内での機密情報の保護、意図しないログ出力防止、メモリゼロクリア |
| `subtle` | ゲートウェイ共有シークレットの定数時間検証（タイミング攻撃対策） |
| `tracing`, `tracing-subscriber` | JSON/Text 出力対応の構造化ロギング |
| `clap` (`derive`, `env`) | 環境変数バインディングおよび設定管理 |
| `url` | パス走査・ホスト改変を防ぐ厳格な URL 組み立て |
| `uuid` | 各リクエストの `X-Request-ID` 生成 |
| `ipnet` | SSRF ガードにおける CIDR レンジおよび特殊 IP の厳格な判定 |
