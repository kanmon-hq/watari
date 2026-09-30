# Contributing to Watari

Watari プロジェクトへの貢献に感謝します。本ドキュメントでは、開発環境のセットアップ、コード規約、セキュリティ方針、プルリクエストの作成手順について説明します。

---

## 1. 前提要件とツールチェーン

- **Rust**: `1.80` 以上（Edition 2021 / stable）
- **mise**（推奨）または **rustup**
- C コンパイラ / リンカー（Linux: `gcc`/`musl-tools`, macOS: Xcode Command Line Tools, Windows: `MinGW` または `MSVC`）

### mise を利用した環境構築

```bash
mise install
```

---

## 2. 開発ワークフロー

### コードのフォーマット

コミット前に必ず `cargo fmt` を実行してコードスタイルを統一してください。

```bash
cargo fmt
# チェックのみ
cargo fmt --check
```

### 静的解析（Lint）

すべての警告（Warnings）をエラーとして扱います。

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### テスト実行

単体テストおよびモック上流を用いた統合テストを実行します。

```bash
cargo test --all-targets --all-features
```

---

## 3. コーディング・設計規約

1. **`#![forbid(unsafe_code)]`**:
   - 安全性を最優先とするため、すべてのクレートおよびモジュールで unsafe コードを禁止します。
2. **エラーハンドリング**:
   - ライブラリ層（`src/`）では `unwrap()` / `expect()` を禁止し、`thiserror` による型安全なエラー（`AppError` / `StoreError` / `SecretError`）を定義・伝播させてください。
   - `main.rs` のみ `anyhow::Context` を利用可能です。
3. **ストリーミング転送の維持**:
   - プロキシリクエストおよびレスポンスの本文をメモリに全体バッファリングしてはなりません。ストリーミング（`reqwest::Body::wrap_stream` / `Body::from_stream`）を維持してください。
4. **ドキュメントコメント**:
   - 公開 trait、構造体、関数、設定項目には必ず `///` による doc コメントを付与してください。

---

## 4. セキュリティ方針（妥協不可）

1. **シークレット管理**:
   - メモリ上での機密情報の保持には `secrecy::SecretString` を使用し、`Debug` / `Display` / ログ / エラーレスポンスに値を出力してはなりません。
   - 外部送信ヘッダーに注入する際は `HeaderValue::set_sensitive(true)` を適用してください。
   - コード内にデフォルトの API キーや共有シークレットをハードコード（フォールバック）してはなりません（未設定時は Fail-Fast で起動エラーとすること）。
2. **SSRF ガード & DNS Rebinding 対策**:
   - クライアントが宛先ホストを直接指定できるインターフェースを追加してはなりません。
   - 内部/プライベート IP（`10/8`, `172.16/12`, `192.168/16`）、ループバック（`127/8`, `::1`）、リンクローカル（`169.254/16`, `fe80::/10`）、クラウドメタデータエンドポイントへの外向き通信は resolver 層で遮断してください。
3. **認証コンテキストの保護**:
   - クライアント指定の `Authorization`, `Cookie`, `Proxy-Authorization`, `Host`, hop-by-hop ヘッダーはプロキシ転送前に削除してください。
   - `X-Gateway-Secret` 等の認証トークン比較は `subtle` クレートによる定数時間比較を行ってください。

---

## 5. プルリクエスト（PR）手順

1. `main` ブランチから機能ごとにトピックブランチを作成。
2. 変更内容に対する単体テストまたは統合テスト（`tests/`）を追加。
3. `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --all-targets --all-features` がすべて Green であることを確認。
4. PR を作成し、変更理由とセキュリティ上の考慮点を明記。
