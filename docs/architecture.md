# パッケージ構成

- `internal/identity` はユーザー、パスキー、ログインセッション、利用者番号を扱う。モデル、サービス、保存処理を同じドメインに置く。
- `internal/consent`、`internal/oauth`、`internal/authorization`、`internal/audit` はそれぞれ同意、OAuth / OIDC、業務認可、監査を扱う。
- `internal/database` は DB 接続と、各ドメインにまたがる GORM AutoMigrate を担当する。
- `handlers/api` は Gin の HTTP ハンドラー、`config` は設定、`cmd/oauthctl` は管理用 CLI を担当する。

従来の `dao`、`lib`、`models` の実装は上記のパッケージへ移した。HTTP のパス、Cookie、DB テーブル名は変更していない。既存のテーブルを新しい構成で開くテストも維持している。

旧 `dao`、`lib`、`models` を Go パッケージとして直接 import していたコードは、import 先と呼び出しの変更が必要。`internal` パッケージは Go の規則により、このモジュール外から直接 import できない。外部の Gin ルーターに既存 API を取り付ける場合は、`api.NewService` でサービスを作成し、`api.RegisterRoutes` に渡せる。DB は呼び出し元で用意する。
