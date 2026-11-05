# OAuth / OIDC 基盤の構成と運用

## 既存実装の調査

既存のログイン方式は WebAuthn パスキーであり、チャレンジとログインセッションを DB に保存します。セッション Cookie はランダムな不透明値で、DB にはそのハッシュと有効期限を保存します。Cookie の属性は HttpOnly、SameSite=Strict、Secure（HTTPS 時）で、有効期限は 24 時間です。ユーザー主キーには UUID v7 を採用し、WebAuthn は RP ID とユーザーハンドルに紐付きます。改修前の既存コードには、OAuth、OIDC、JWT 発行、外部クライアント管理機能は存在していませんでした。

既存の Gin ルーターは `/api` 配下で認証およびプロフィール API を提供し、DB は GORM AutoMigrate を用いて PostgreSQL と SQLite を管理しています。今回、既存の API とセッション構造を維持したまま、新しいテーブルと OAuth エンドポイントを追加しました。Vite の開発プロキシは、OAuth、Discovery、UserInfo の各リクエストも API へ転送します。なお、`api.RegisterRoutes` は DB を受け取らない既存の埋め込み用ルーティング関数であるため、新規追加した OAuth および同意用 API は `api.NewRouter` 側に登録しています。

SameSite=Strict Cookie は、外部サイトからの初回遷移時に送信されない場合があります。その対策として、認可要求を一時的にサーバー側に保持し、同一オリジンのログインページで既存セッションを確認してから認可処理を再開する構成としました。Web アプリの `/login/` と API は同一の公開オリジンに配置し、リバースプロキシを介して `/.well-known/*` と `/api/*` を Go サーバーへ転送し、`/oauth2/v1/auth` は Web アプリへ転送します。

HTTPS 環境での OAuth 認証には、サブドメインからの Cookie 上書きを防ぐため `__Host-sharelib_session` Cookie を使用します。既存 API 用の Cookie も並行して維持されますが、本改修前にログイン済みで新 Cookie を未保持のユーザーは、OAuth 利用時に一度パスキーでの再ログインが必要です。

## 実装機能

* **認可・認証機能**: Fosite v0.49.0 を採用し、Authorization Code Flow with PKCE (S256)、RS256 ID Token、UserInfo（GET / POST）、OIDC / OAuth Discovery、JWKS、Token、Revocation、Introspection エンドポイントを実装しました。Implicit、password、client credentials の各グラントタイプは提供しません。
* **入力制限とセキュリティ**: Fosite の HMAC トークン解析における[過大入力によるメモリ消費の問題（#882）](https://github.com/ory/fosite/issues/882)への緩和策として、OAuth POST のリクエストボディ、各パラメーター、認証ヘッダーの長さを制限しています。継続的な依存ライブラリの更新とセキュリティ情報の監視が必要です。
* **検証とアクセストークン**: 登録済みクライアント、完全一致する redirect URI、スコープ、リソース、利用目的を検証します。業務スコープの要求時には、認可エンドポイントで登録済みの Resource Indicator を 1 つ指定する必要があり、トークン交換時のリソース変更は許可しません。アクセストークンは不透明形式（有効期限 5 分）であり、Resource Server は認証付き Introspection を通じて自身宛てのトークンのみを検証できます。
* **同意管理**: 認証用スコープと業務データの同意を分離して管理します。業務スコープごとに同意を記録し、利用目的やポリシーバージョンが変更された場合は再同意を要求します。また、画面表示内容と POST 内容を照合することで、認可要求・ブラウザー・ユーザー・CSRF 値を紐付けます。同意拒否時は `access_denied` を返却します。
* **同意撤回とトークン失効**: 同意を撤回すると、該当の同意に関連する認可コード、アクセストークン、リフレッシュトークンを失効させます。複数の同意に依存するトークンは全体が失効しますが、依存関係のない他の同意は保持されます。発行および撤回処理は PostgreSQL の行ロックにより直列化されます。リフレッシュトークンはローテーションされ、再利用を検出した場合は関連するすべてのトークンを失効します。
* **権限の縮小と分離**: リフレッシュトークン交換時に `scope` を指定することで、元の権限範囲内でアクセストークンを縮小可能です。ローテーション後のリフレッシュトークンも元の Scope と同意の関連性を維持します。なお、同意の部分撤回は関連トークンの失効を引き起こすため、トークンの権限縮小処理とは明確に区別されます。
* **オフラインアクセス**: `offline_access` は業務データの同意と紐付けた場合のみ許可し、要求時には毎回、継続アクセスの同意画面を表示します。リフレッシュトークンの有効期限は 24 時間で、ユーザーは同意撤回によって関連するリフレッシュトークンを停止できます。
* **アクセス制御モデル**: Resource Server の認証情報を使用する `/internal/authorize/check` と、Casbin による RBAC 共通ポリシーを実装しました。Scope の許可は業務ポリシーの許可を意味しないため、注文やプロジェクトなど個別リソースへの最終的なアクセス制御は Resource Server 側で行います。
* **監査イベント**: `/internal/audit/events` エンドポイントで、認証済み Resource Server から業務アクセスイベントを受信します。同一送信元かつ同一イベント ID の再送は重複排除され、内容が異なる場合は 409、保存失敗時は 5xx を返します。`/api/me/access-events` は本人のイベントのみを返し、カーソルペジネーションに対応しています。送信側は保存成功が確認できるまでイベントを保持・再送する必要があります。
* **セキュリティイベントとログ出力**: ログイン成功、認可、同意、トークンの発行・失効といったセキュリティイベントを、業務 API のアクセスログとは分けて記録します。`/api/me/security-events` は本人向けイベントのみを返し、カーソルペジネーションに対応します（未認証の認可要求などは管理者向け DB 履歴に限定保存）。トークン、認可コード、クライアントシークレットは記録しません。Gin の URL クエリログ無効化および GORM の SQL ログのパラメーター伏せ字化を行っていますが、リバースプロキシ側でも OAuth クエリや Authorization ヘッダーをログ出力しない設定が必要です。

## 設定

OAuth 機能はデフォルトで無効化されています。有効化するには PostgreSQL の設定に加え、公開する認証オリジンおよび鍵の指定が必要です（ホスト名は固定されていません）。Issuer は WebAuthn の公開オリジンと厳密に一致させる必要があり、末尾に `/` を含めてはなりません。HTTP 通信は localhost の開発環境のみ許可されます。

```toml
[OAUTH]
ENABLED = true
ISSUER = "https://auth.example.com"
SIGNING_KEY_FILE = "/secure/path/oidc-private.pem"
SIGNING_KEY_ID = "signing-key-2026"
# ローテーション時に古い公開鍵を保持する場合
PREVIOUS_JWKS_FILE = "/secure/path/previous-public-jwks.json"

```

署名鍵には、2048 ビット以上の RSA 秘密鍵 PEM（PKCS#1 または PKCS#8）を使用し、サービス実行ユーザーのみが参照できるパーミッションで保管します。さらに、暗号学的に安全な 32 バイト以上のランダム値をパディングなし base64url 形式で生成し、環境変数 `OAUTH_HMAC_SECRET` に設定します。起動時に設定値と鍵の妥当性を検証し、不備がある場合は OAuth を有効化せずに起動を中断します。

鍵をローテーションする際は、新しい秘密鍵と key ID を設定し、**旧公開鍵のみ** を `PREVIOUS_JWKS_FILE`（JWKS 形式）に保持します。旧公開鍵は、以前発行した ID Token が失効するまで保持してください。HMAC 鍵を更新する場合は、旧鍵を `OAUTH_HMAC_PREVIOUS_SECRETS` にカンマ区切り（base64url）で指定し、旧リフレッシュトークンの許容期間終了後に削除します。鍵の配布および削除の運用管理は運用者が担当します。

ブラウザーへ返却される ID Token は認証結果の証明用であり、業務 API の認可には使用できません。OAuth クライアント側で `state`、必要に応じた `nonce`、ID Token の署名・Issuer・Audience・有効期限を検証する必要があります。Resource Server 側は、リクエストごとに Introspection を実行し、`active` 状態、`iss`、自アセットの `aud`、必要な Scope および業務権限を確認してください。なお、Introspection 結果のキャッシュはトークン撤回反映の遅延につながる点に留意してください。

アクセストークンは Bearer Token であるため、漏えい時には有効期限切れまたは撤回まで不正利用されるリスクがあります。短期間の有効期限設定、Audience 制限、TLS の適用、サーバー側での安全な保管、都度の Introspection 実行によりリスクを低減させています（DPoP や mTLS による Sender-Constrained Tokens には未対応です）。

## 登録と権限管理

`cmd/oauthctl` は、信頼された運用者が DB を直接操作するための CLI ツールです。標準入力から 1 つの JSON オブジェクトを受け取って実行します。各コマンド実行時には `-config /path/to/config.toml` フラグで設定ファイルを指定できます。

```sh
printf '%s\n' '{"id":"b","identifier":"https://b.example.com/api","name":"B"}' | go run ./cmd/oauthctl resource
printf '%s\n' '{"id":"orders-read","resource_id":"b","name":"b.orders.read","description":"注文履歴の参照","purpose_code":"orders","policy_version":1}' | go run ./cmd/oauthctl scope
printf '%s\n' '{"id":"c-web","name":"C","public":true,"redirect_uris":["https://c.example.com/callback"],"grant_types":["authorization_code","refresh_token"],"scopes":["openid","offline_access","b.orders.read"],"audience":["https://b.example.com/api"]}' | go run ./cmd/oauthctl client

```

機密クライアントを登録する際は、暗号学的に安全なランダム値で作成した 32〜72 バイトのシークレット（例: 32 バイトのパディングなし base64url 文字列）を環境変数 `OAUTH_CLIENT_SECRET` に設定します。Resource Server 用の認証情報を登録する `resource-credential` コマンドには `{"id":"b-server","resource_id":"b"}` を渡し、同様に `OAUTH_RESOURCE_SECRET` にシークレットを設定します。シークレットは DB 内に bcrypt ハッシュ値として保存されます。環境変数、鍵ファイル、DB 接続情報は、プロセスやログに漏出しないよう厳重に保護してください。

`client-update` コマンドは `client` と同様の形式で登録情報を上書きし、既存の認可セッションを無効化します（機密クライアント更新時もシークレットの再指定が必要です）。`status` コマンドは `{"kind":"client|resource|scope|resource-credential","id":"...","status":"active|disabled"}` を受け付けます。クライアントやリソースを無効化すると対象セッションは即時失効し、再有効化しても自動復元はされません。スコープの無効化や `scope-policy` による説明・目的の変更時はポリシーバージョンが加算され、旧同意に基づくトークンは無効化されます。

`role-binding` は `resource_id`、UUID 形式の `user_id`、`role`、`status` を受け取り、`policy` は `resource_id`、`role`、`object`、`action`、`status` を受け取ります。例えば `resource_id: b`、`object: orders`、`action: read` の組み合わせは `b.orders` 権限の判定に使用され、一致するルールが存在しない場合はアクセスを拒否します。

## 検証と未実装事項

* **テストとビルド**: PostgreSQL のテストを実行する際は、環境変数 `TEST_POSTGRES_DSN` にテスト用 DB の DSN を設定して `go test ./...` を実行します（テスト用 DB ロールにはスキーマの作成・削除権限が必要です）。Web フロントエンドは `pnpm run build` でビルドします。
* **依存関係の更新**: Go 標準ライブラリのセキュリティパッチを適用するため、Go の要求バージョンを 1.27.2 から 1.27.3 へ更新しました。また、PostgreSQL ドライバー、JOSE、OpenTelemetry などのライブラリも更新済みです。実行・開発環境には Go 1.27.3 以降を用意してください。
* **現在の対応範囲**: 単一リソースの Resource Indicator、`openid` / `offline_access` スコープ、RS256 署名、およびパブリック/共有シークレットによるクライアント認証に対応しています。
* **未対応の機能**:
* `profile` や `email` 等の UserInfo 属性追加
* 単一トークンへの複数リソース情報の包含要求
* RFC 9396 Rich Authorization Requests (RAR)
* 動的クライアント登録 (Dynamic Client Registration)
* 管理画面 UI
* 鍵の自動ローテーション（未対応の機能は Discovery ドキュメントに掲載していません）


* **同意条件と拡張性**: 同意レコードには将来的な詳細条件指定用のフィールドが確保されていますが、判定ロジックは未実装です。未知の条件が含まれる同意を使用したトークンの発行・検証は拒否されます。将来 RFC 9396 に対応する際は、条件の検証・画面表示・Resource Server への伝達ロジックの実装が必要です。
* **運用上の制限と注意点**:
* **監査イベント**: 監査イベントの送信キューおよびリトライ制御は Resource Server 側の責務であり、中央サーバー側に送信キューは存在しません。
* **CLI 操作ログ**: CLI（`oauthctl`）による登録やポリシー変更は管理者向け履歴に記録されますが、実行した OS ユーザー情報は保持されないため、実行環境（OS）側の操作ログと併用して監査してください。
* **未実装の運用機能**: 二次利用イベント専用スキーマ、期限切れレコードの自動削除タスク、履歴の保持期間・バックアップ方針の策定、運用者向けセキュリティ監査画面は未実装です。
* **DB マイグレーション**: GORM AutoMigrate はスキーマ差分のバージョン管理や本番バックアップの代用にはなりません。
* **標準準拠認定**: 本実装は、公式の認証・認可テストスイートによる正式な Conformance 認証を受けていません。
