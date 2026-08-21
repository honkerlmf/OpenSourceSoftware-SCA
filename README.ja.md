# Open Source Software SCA - ソフトウェアサプライチェーン・オープンソースコンポーネント脆弱性スキャナ

> **無料 · オープンソース · AI支援のソフトウェア構成分析（SCA）ツール**
>
> 🌐 **言語**：[简体中文](README.md) · [English](README.en.md) · [Français](README.fr.md) · [日本語](README.ja.md)

完全無料・オープンソースのソフトウェア構成分析（SCA）ツールで、AI 支援によりソフトウェアサプライチェーンのオープンソースコンポーネントのセキュリティ監査を行います。Swing の GUI から Java / Python / Node.js / Go / Rust / PHP などのコードフォルダを選択すると、プロジェクトの依存コンポーネント設定（pom.xml、build.gradle、package.json、requirements.txt、poetry.lock、go.mod、Cargo.toml、composer.json、lib ディレクトリ内の jar など）を自動認識して読み取り、依存コンポーネントの Excel 一覧を生成し、全コンポーネントについて CVE 脆弱性とライセンスを個別に照会して Excel に結果を書き戻し、最後に完了ダイアログを表示して Excel を直接開くことができます。

**4言語対応（i18n）**：インターフェース、ログ出力、Excel 出力（シート名・ヘッダー・ステータス値）は、簡体字中国語・English・Français・日本語の間で即時に切り替わります。選択した言語は自動的に保存され、次回起動時に復元されます。

## 主な機能

- **多言語化（i18n）**：インターフェース、ログ領域、Excel 出力（シート名 / ヘッダー / ステータス値）は簡体字中国語・English・Français・日本語の4言語に対応。メニューバーの「言語 / Language」メニューでいつでも切り替え可能。選択内容は自動保存されます。
- **AI モデル API 設定**：「外部 AI モデル API」と「内部 AI モデル API」（OpenAI 互換プロトコル）を個別に設定でき、任意の baseUrl / apiKey / モデル名に対応。ワンクリックの接続テスト機能付き。
- **AI プロジェクト分析**：AI がコードフォルダの構成と依存一覧を読み取り、プロジェクト分析レポートを出力し、解析ルールでカバーされない依存コンポーネントを補完します。
- **3つの依存スキャンモード**：
  1. **コードプロジェクト全体をスキャン** — 依存設定を自動認識し「コンポーネント（packageId）/ バージョン / 言語 / 導入方法」を抽出：
     - Java：`pom.xml`（`${property}` バージョン変数の解決を含む）、`build.gradle`、`lib` ディレクトリのコンパイル済み jar（META-INF/maven の pom.properties / pom.xml を読取）
     - Node.js：`package.json`（dependencies / devDependencies など）
     - Python：`requirements.txt`、`Pipfile`、`poetry.lock`
     - Go：`go.mod`；Rust：`Cargo.toml`；PHP：`composer.json`
  2. **単一の lib フォルダを選択** — 選択したフォルダ内の jar を直接スキャン。
  3. **jar/war アーカイブを読取** — アーカイブ内の lib フォルダ（`WEB-INF/lib`、`BOOT-INF/lib`）の jar を解析。
- **外部 Excel コンポーネント一覧**：本ツールまたは他ツールが生成したコンポーネント一覧 Excel（コンポーネント名列が必要）をインポート可能。解析後、キーワード絞り込みとチェックボックス付きのコンポーネント選択ダイアログを表示（デフォルト全選択）。
- **4つの CVE 照会チャネル**（任意選択、失敗時は自動フォールバック）：
  1. **OSV.dev（推奨）**：Google が管理する公開脆弱性データベース。無料・トークン不要。GitHub Advisory / NVD などの公式ソースを集約
  2. **OSS Index**：Sonatype の公開コンポーネントデータベース（POST /api/v3/component-report）
  3. **mvnrepository**：`https://mvnrepository.com/artifact/{groupId}/{artifactId}/{version}` の Vulnerabilities テーブルを解析
  4. **Sonatype IQ Server**：エンタープライズ向け API（POST /api/v2/components/details）。PAT トークンを使用
- **Excel への脆弱性書き戻し**：脆弱性の有無、CVE ID 一覧、最大深刻度（緊急 / 高 / 中 / 低）、各 CVE の CVSS スコアと影響/修正バージョン範囲、コンポーネントのライセンス（Maven Central POM / npm registry / PyPI / crates.io / Packagist）。
- **AI 修正提案（公式 API フォールバック）**：脆弱性のあるコンポーネントに対し AI がアップグレード提案を生成（オプション）。AI が利用できない場合は、脆弱性 API が返す公式修正バージョンを自動的に使用。Excel の最終列に提案の取得日（API 読取日）を記録し、後で修正バージョンが変わっても提案の有効性を追跡できます。
- **完了ダイアログ**：分析完了後、「Excel を開く / フォルダを開く / 閉じる」を選択できます。

## Excel 出力について

生成される Excel（`.xlsx`）には3つのワークシートが含まれます：

| ワークシート | 内容 |
| --- | --- |
| 依存コンポーネント一覧 | コンポーネント（packageId）、バージョン、言語、導入方法、脆弱性の有無、脆弱性数、最大深刻度、CVE ID 一覧、ライセンス、AI 修正提案、公式 API 修正提案、提案日、照会方法、ステータス（深刻度に応じて行を赤/緑で色分け） |
| CVE 脆弱性明細 | 各脆弱性の CVE ID、タイトル、説明、CVSS スコア、深刻度、影響を受けるバージョン範囲、参照リンク |
| AI プロジェクト分析レポート | プロジェクト全体に対する AI の分析結果と修正提案 |

## 動作環境

- JDK 1.8 以上（プロジェクトは Java 8 構文で記述）
- 実行には Maven は不要（同梱 jar を使用）。再ビルドする場合は Maven 3.6+ をインストールしてください

## クイックスタート

### 方法1：直接実行（推奨）

```bat
run.bat
```

または手動で：

```bat
java -jar target\cve-dependency-scanner.jar
```

### 方法2：再ビルド

```bat
mvn package -DskipTests
java -jar target\cve-dependency-scanner.jar
```

## 使い方

1. **AI モデル設定**（1つ目のタブ）：
   - 外部 AI：OpenAI 互換の baseUrl（例：`https://api.openai.com/v1`）、apiKey、モデル名（例：`gpt-4o-mini`）
   - 内部 AI：内部 LLM サービスの URL（例：`http://127.0.0.1:11434/v1`。Ollama の場合は `qwen2.5:14b` を直接指定可）
   - 外部または内部を選択し、「接続テスト」で確認後「設定を保存」
2. **脆弱性照会設定**（2つ目のタブ）：
   - 照会方法を選択（デフォルトは OSV.dev 推奨、その他は必要に応じて）
   - 方法4（IQ Server）はサーバー URL と PAT トークンの入力が必要
   - 任意：「自動フォールバック」「ライセンス解析」を有効化
3. **依存スキャンと分析**（3つ目のタブ）：
   - スキャンモードを選択：① コードプロジェクト全体 / ② 単一の lib フォルダ / ③ jar/war アーカイブ、次に対象を選択
   - 任意：外部コンポーネント一覧 Excel のインポート、出力 Excel パスの設定
   - 任意：「AI プロジェクト分析」「AI 修正提案」にチェック
   - 順にクリック：「① 依存をスキャンして一覧を生成」→「② 脆弱性を照会して Excel に書込み」→「③ ワンクリック実行」（ワンクリックでスキャン+照会+レポートを自動実行）
4. 分析が完了すると**完了ダイアログ**が表示されます。「Excel を開く」をクリックすると脆弱性一覧を確認できます。
5. **言語切替**：メニューバーの「言語 / Language」メニューで、簡体字中国語 / English / Français / 日本語 をいつでも切替可能。UI・ログ・Excel 出力は即座に反映され、選択は保存されます。

## 設定について

実行時、すべての設定は `config/app-config.json` に保存されます（ウィンドウを閉じると自動保存）：

| 設定キー | 説明 |
| --- | --- |
| language | UI 言語：zh / en / fr / ja |
| externalAi / internalAi | 外部/内部 AI モデルの baseUrl、apiKey、model、タイムアウト秒数 |
| queryMethod | 照会方法：OSV / OSS_INDEX / MVN_REPO / IQ_SERVER |
| iqServerUrl / iqToken | Sonatype IQ Server の URL とトークン |
| fallbackEnabled | 優先方法が失敗した場合に他のチャネルへ自動フォールバックするか |
| licenseEnabled | コンポーネントのライセンスを解析するか |
| aiAnalyze / aiFix | AI プロジェクト分析 / AI 修正提案を有効にするか |

## ディレクトリ構成

```
qcoder/
├── pom.xml                              # Maven ビルド設定（実行可能 jar をパッケージ）
├── run.bat                              # ワンクリック起動スクリプト
├── config/app-config.json               # 実行時設定（自動保存、言語を含む）
├── README.md / README.en.md / README.fr.md / README.ja.md   # 多言語ドキュメント
└── src/main/
    ├── java/com/qcoder/cve/
    │   ├── Main.java                    # エントリポイント
    │   ├── ui/MainFrame.java            # Swing メインウィンドウ（3タブ + 言語メニュー + 完了ダイアログ）
    │   ├── i18n/I18n.java               # i18n ユーティリティ（言語切替 / リソース読込 / ステータス変換）
    │   ├── config/                      # 設定モデルと読み書き
    │   ├── model/                       # 依存コンポーネント / 脆弱性明細モデル
    │   ├── scan/DependencyScanner.java  # 多言語依存スキャナ（3スキャンモード）
    │   ├── cve/                         # 4つの照会チャネル + ライセンス解析 + purl 生成
    │   ├── ai/                          # 外部/内部 AI API クライアントと分析サービス
    │   ├── excel/ExcelReport.java       # POI Excel 一覧と脆弱性書き戻し（多言語出力）
    │   └── util/HttpUtil.java           # HTTP ユーティリティ
    └── resources/i18n/                  # 中/英/仏/日 のリソースファイル
```

## 技術スタック

- JDK 1.8 + Swing（UI）、Apache POI 5.2.5（Excel）、Gson 2.10.1（JSON）、jsoup 1.17.2（HTML 解析）、Maven + shade プラグイン（パッケージング）
- 自作 i18n フレームワーク：UTF-8 properties リソース、再起動不要の実行時切替、キー欠落時は中国語へ自動フォールバック

## ライセンス

本プロジェクトは [GPL-3.0](LICENSE) ライセンスで公開されています。
