# 管理者設定

auth-service は `roles` と `user_roles` でユーザのロールを管理します。
`admin` ロールは起動時のマイグレーションで作成されます。既存ユーザと新規登録ユーザには自動付与されません。
このロールは auth-service 自体の管理権限です。repository-service のロールや、業務リソース向けの `authorization_role_bindings` とは独立しています。

## 最初の admin を付与する

1. 通常の登録フローでユーザを作成します。
2. そのユーザでログインし、`GET /api/users/me` の `ID` を確認します。
3. サーバの設定ファイルとデータベースを利用できる運用環境で、次を実行します。`<USER_UUID>` は対象ユーザの ID に置き換えます。

```bash
go run ./cmd/oauthctl -config ./config.toml grant-admin <<'JSON'
{"user_id":"<USER_UUID>"}
JSON
```

コンテナには `oauthctl` が含まれているため、同じ JSON を標準入力に渡して `/app/oauthctl -config /path/to/config.toml grant-admin` を実行できます。
このコマンドは設定の `HOSTNAME` に属するユーザだけを対象とし、同じユーザへの再実行も可能です。

付与後に画面を再読み込みすると、マイページとメニューに「管理者設定」が表示されます。`/admin` から直接開くこともできます。
以後は管理画面で別のユーザに admin を付与・解除できます。ロールの変更は次の API リクエストから既存のログインセッションにも反映されます。

## 管理画面

- **ユーザ管理**：ユーザ名・表示名・メールアドレスで検索し、ユーザ情報とロールを確認・編集できます。ユーザ ID と図書館 ID は変更できません。
- **ロール管理**：ロールの追加、名称変更、未使用ロールの削除ができます。追加ロールには管理権限はありません。`admin` 自体の削除と最後の admin の解除は拒否されます。
- **OAuth Client 設定**：クライアントを一覧表示し、追加・設定変更・有効化・無効化ができます。Client ID、名称、Public / Confidential、Redirect URI、許可スコープ、Audience、リフレッシュトークンの許可、シークレットを設定できます。

ユーザ編集は読み込んだ更新日時を照合します。他の編集と競合した場合は「最新の情報を読み込む」で再取得してから編集し直してください。

Confidential クライアントのシークレットは 32〜72 バイトで指定し、bcrypt ハッシュだけを保存します。画面でランダム生成することもできます。保存後の再表示はできません。
既存の Confidential クライアントの編集時にシークレットを空欄にすると既存の値を保持します。Public から Confidential に変更する場合は新しいシークレットが必要です。
クライアントの設定変更・無効化では、発行済みの関連トークンと認可コードを失効させます。

Audience に指定するリソースや業務スコープは、既存の `oauthctl resource` / `scope` コマンドで事前に登録してください。本人確認用の `openid`、`profile`、`email`、`offline_access` は事前登録不要です。

## 管理 API

すべて `/api/admin` 配下で、ログイン Cookie と `admin` ロールが必要です。未認証は 401、権限不足は 403 を返します。変更リクエストには既存の Origin 検証も適用されます。

| メソッド | パス | 内容 |
| --- | --- | --- |
| GET | `/api/admin/users?q=&limit=25&offset=0` | ユーザ検索。`items` と `total` を返す。limit は 1〜100 |
| GET | `/api/admin/users/:id` | ユーザ情報の確認 |
| PATCH | `/api/admin/users/:id` | `UserName`、`Name`、`Email`、`Roles` を部分更新。取得時の `UpdatedAt` が必須 |
| GET | `/api/admin/roles` | ロール一覧 |
| POST | `/api/admin/roles` | `{ "id": "support", "name": "サポート" }` で追加 |
| PATCH | `/api/admin/roles/:id` | `{ "name": "名称" }` で名称変更 |
| DELETE | `/api/admin/roles/:id` | 未使用ロールを削除 |
| GET | `/api/admin/oauth/clients` | OAuth Client 一覧 |
| GET | `/api/admin/oauth/clients/:id` | OAuth Client 詳細 |
| POST | `/api/admin/oauth/clients` | OAuth Client 追加 |
| PUT | `/api/admin/oauth/clients/:id` | OAuth Client 設定を置換 |
| PATCH | `/api/admin/oauth/clients/:id/status` | `{ "status": "active" }` または `{ "status": "disabled" }` |

OAuth Client の追加・設定変更リクエストは次の形式です。PUT の `id` は URL の ID と一致させます。

```json
{
  "id": "repository-service",
  "name": "リポジトリ管理サーバ",
  "public": false,
  "secret": "<32-to-72-byte-secret>",
  "redirect_uris": ["https://repository.example/auth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "email"],
  "audience": []
}
```

一覧・詳細のレスポンスはシークレットとそのハッシュを含みません。設定変更はセキュリティイベントに記録され、イベントにシークレットやプロフィール値は保存されません。
