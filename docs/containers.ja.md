1. **repository-service の起動手順を開いてください（目安 1 分）。** 両リポジトリを同じ親フォルダーに置き、[コンテナで起動](https://github.com/sharelib-jp/repository-service/blob/main/docs/containers.ja.md) または [コンテナなしで起動](https://github.com/sharelib-jp/repository-service/blob/main/docs/native.ja.md) に従います。全体の設定生成・DB・クライアント登録は repository-service の deploy にまとめています。

2. **このリポジトリの Container ワークフローを確認してください（目安 2 分）。** master への push、`v*` タグ、手動実行で `ghcr.io/sharelib-jp/auth-service` を公開します。Pull Request ではテストとビルドまで実行します。現在の Dockerfile は Go API、ビルド済みフロント、`/app/oauthctl` を１つのイメージに含めます。

3. **設定と秘密鍵を実行時に渡してください（目安 3 分）。** config.toml、README.md、秘密鍵、`.env`、DB はイメージに含めません。設定ファイルは `/app/config.toml` に読み取り専用でマウントし、HMAC シークレットは環境変数で渡します。プロセスは UID/GID 10001 で動くため、署名鍵はこの UID が読める状態にします。

4. **DB → auth-service → クライアント登録の順で起動してください（目安 5 分）。** auth-service が `/.well-known/openid-configuration` を配信できてから、repository-service を起動します。設定変更が必要な場合はサーバーに `-config /path/to/config.toml`、フロントに `-web /path/to/dist` を指定できます。

5. **初回クライアント登録を確認してください（目安 2 分）。** `oauthctl client` に渡す client ID・redirect URI・scope・シークレットを repository-service と一致させます。repository-service の admin ロールは同サービス側で設定します。auth-service のロール設定とは別です。

次に、repository-service の起動手順で設定生成を実行してください。
