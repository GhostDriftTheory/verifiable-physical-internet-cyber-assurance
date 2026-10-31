# VPI Cyber Assurance

[![CI Validation](https://github.com/GhostDriftTheory/verifiable-physical-internet-cyber-assurance/actions/workflows/validate.yml/badge.svg?branch=main)](https://github.com/GhostDriftTheory/verifiable-physical-internet-cyber-assurance/actions/workflows/validate.yml)

**Automated CI Validation:** Ubuntu and Windows (Python 3.11 / 3.13), including runtime assurance tests and Lean 4 formal verification. All five CI jobs passed in the verified release.

**フィジカルインターネットの企業間接続・安全切替え PoC**  
Public Reference · v2.0.0-rc2 · 株式会社AIアシュアランス

フィジカルインターネットの企業間連携を想定し、**誰が、どの条件で操作を許可し、結果不明時にどこで止めるか**を検証する参照実装です。合成企業A・B・Cを別プロセス・別SQLite DB・別署名鍵で動かします。

対象は限定した通知操作 `handoff.notice` の受入れと接続先の切替えです。物流プラットフォーム全体、配送最適化、温度管理、VPN・ルーターの経路制御、実貨物の移動は実装していません。

## 使い方

`dashboard.html` を開くと、同梱した実験結果を閲覧できます。HTMLだけでは通信実験や署名検証は行いません。

Python 3.11以上を使用します。依存は `cryptography` のみです。

```console
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# macOS / Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python demo.py --serve
```

表示されたローカルURLを開くと、実通信の進捗と結果を確認できます。停止は端末で `Ctrl+C`。外部API、APIキー、Docker、クラウドサービスは不要です。依存パッケージとLeanの導入時にはネット接続が必要です。

```console
# 同梱証拠を実行側とは別の検証器で照合
python verifier.py sample.json

# 新しい通信実験。公開可能な結果を run/sample.json に保存
python demo.py --output run
python verifier.py run/sample.json

# 自動テスト・通信実験・有限状態探索・入力照合・Lean状態の確認
python validate.py

# Lean 4.19.0が利用可能な環境で、形式検証も必須にする
python validate.py --require-lean
```

`--require-lean` は、Lean未導入・ビルド失敗のいずれも終了コード2にします。通常の検査は実行系の結果とLeanの状態を分けて報告します。Leanは自動ダウンロードしません。

## 実証すること

| 条件・障害 | 確認する挙動 |
|---|---|
| 通常の通知 | 双方の条件を確認し、受信側DBに1件記録 |
| 送信元の失効・条件変更 | 古い要求の直接再送でも新規許可を発行しない |
| 受信側の失効 | 最終処理直前の再検査で実行を止める |
| 応答消失・プロセス停止・再送 | 保存済み結果を照合し、不明ならHOLD |
| BからCへの切替え | Bの取消し確定後、Cについて新たに承認 |
| 一つの相手の停止 | 条件を満たす無関係な操作は継続 |
| 証拠の改変・欠落 | 署名に加え、両社の記録の対応と状態遷移から検出 |

40の実通信シナリオには、期待した拒否・保留と保証境界の確認を含みます。「試験成功」は「すべての操作を許可した」という意味ではありません。自動テストのうち1件も全40シナリオを実行するため、両方の件数を別々の試験として合算しません。

## プロトコルと停止境界

**承認から実行まで。** Aは操作内容・宛先・条件の版を固定し、Bの承認を取得します。Bは実行直前に、受信側チャレンジに結び付いた短期実行許可をAへ要求します。Aは現在の条件と送信状態を確認します。Bは自社条件と許可期限を再検査し、作用のDB記録・署名付き結果・監査記録を同じトランザクションで確定します。HTTP待機中にDB書込みトランザクションを保持しません。

**失効は瞬時の全社停止ではありません。** 送信元の失効応答が意味するのは、以後の新規実行許可を止めたことです。既発行の有効な許可は実行される可能性があります。応答には未確定操作と遠隔取消し未確認を明示します。許可は最大2,000ミリ秒ですが、期限切れは過去の未実行証明ではなく、物理作用の完了時刻も保証しません。

**結果不明のまま切り替えません。** 受信側の `(source, intent)` の終端結果は `CANCELLED` または `COMMITTED` で固定されます。Bの署名付き取消し結果を取得してからCへ切り替えます。先にBで実行済みなら切替えを拒否し、先に取消しが確定したなら遅延要求を実行しません。Bが応答せず結果を確定できない間はHOLDを維持します。可用性より二重実行の回避を優先する場面があります。

## 証拠と信頼の範囲

`sample.json` に、実験レポート・署名付き証拠・照合用アンカー・実際の検査結果をまとめています。

| キー | 内容 |
|---|---|
| `report` | シナリオ別結果、有限モデル探索、改変試験 |
| `evidence` | 3社の署名付きイベント、結果、チェックポイント |
| `anchors` | 合成実験の公開鍵・チェックポイントの照合値 |
| `validation` | 自動テストの件数とログ、形式検証状態、ソース指紋 |

`verifier.py` は `assurance.py`、`demo.py`、`validate.py` をimportしません。署名とハッシュチェーンに加え、承認・チャレンジ・実行許可・実行結果・取消しと切替えの対応を独自に検査します。共通の仕様誤りまで排除する独立性の証明ではありません。

`CONSISTENT` は、**開示された記録が指定した規則と照合値に整合する**という意味です。社内条件の真偽、すべての履歴の存在、実世界の実行事実を証明しません。レポート本文・試験件数・検査ログは署名対象ではありません。

同梱アンカーは独立した信頼機関の証明ではなく、検証器も `BUNDLED_KEYS_AND_CHECKPOINTS` と表示します。証拠とアンカーをまとめて置き換える攻撃への対策には、公開鍵・チェックポイント・リリースハッシュを別経路で固定する必要があります。別途固定したアンカーファイルは `--anchors パス` で指定できます。

## 検証層

**実行系。** 実HTTP、SQLite、署名、失効、同時再送、取消し競合、応答消失、プロセス停止・再起動、虚偽の署名付き観測値、公開物の検査を含みます。障害注入はローカル試験用に明示的に有効化します。侵入テストや性能ベンチマークではありません。

**有限状態探索。** 送信元1社・固定操作1件・宛先B/C、各社1回の失効／復帰、要求と許可の期限切れ等を明示的に制限したモデルを全探索します。安全条件を外した5種類の負例では反例検出を要求します。探索上限への到達を成功とは扱いません。

**Leanモデル。** `VpiAssurance.lean` は外部ライブラリを使わず、入場判定、取消し済み結果の不変性、取消し後の切替え、任意長の有限遷移列での二重作用回避を記述します。元の有限探索モデルより小さい抽象モデルであり、Python・通信・SQLite・暗号の完全な形式検証ではありません。

**具体入力照合。** 6,144の条件組合せ、38の整数境界、実通信のCOMMIT観測値を、実行側と独立検証器で照合します。Leanの具体入力命題は実行時に生成し、配布物には大量の生成コードを含めません。Python同士の一致とLeanビルド成功は別の結果です。いずれも全入力の実装同値性証明ではありません。

**このRC版のLean状態：未実行。** 作成環境にLeanツールチェーンがなく、定理宣言を機械検証済みとは表示していません。最新の検査状態は `sample.json` の `validation.formal` を参照してください。GitHub ActionsのLinux／Windows試験とLean必須ジョブを収録していますが、設定の存在はCI成功実績ではありません。

## セキュリティ上の前提

すべて同一PCのループバック上で実行します。OS、Python、SQLite、暗号ライブラリ、初期の鍵・接続設定、参加ノードを信頼します。別プロセス・別鍵は別企業の運用分離やOS隔離を意味しません。

対象の作用は、結果・監査記録と同じトランザクション内のSQLite行です。外部API、別DB、実貨物、設備動作には別の統合設計が必要です。mTLS、分散PKI、ハードウェア鍵保護、外部時刻証明、侵害ノードへの耐性、DB巻戻し、実機接続、性能SLAは対象外です。

社内の合成メタデータは外部へ送信しませんが、条件の真偽の証明やゼロ知識証明ではありません。公開ソース中の合成条件は参照可能で、判定結果から情報が推測される場合もあります。

エージェントと画面をインターネットへ公開せず、実データ・運用鍵を入力しないでください。通常実行は秘密鍵・管理トークン・DBを一時領域に置きます。開発用 `--keep-runtime` はそれらを残すため、生成物を公開対象に含めないでください。

脆弱性の報告には、版・再現コマンド・期待結果・実結果と最小の合成再現例を用いてください。実顧客データ、秘密鍵、トークンは公開せず、機密情報はリポジトリ所有者の非公開窓口へ連絡してください。

## 配布構成と再パッケージ

配布物は**14ファイル**です。説明を本READMEに、検査・形式化生成・ZIP作成を `validate.py` に統合しています。

| ファイル | 役割 |
|---|---|
| `README.md` / `NOTICE.md` | 実行方法・仕様・保証境界／著作権と利用条件 |
| `assurance.py` | 3社のHTTPエージェント・固定入場判定 |
| `verifier.py` | 実行側に依存しないオフライン検証器 |
| `demo.py` / `dashboard.html` | 40シナリオの実通信実験／結果画面 |
| `tests.py` / `validate.py` | 自動テスト／探索・入力照合・Lean検査・ZIP作成 |
| `VpiAssurance.lean` / `lean-toolchain` | 抽象モデルと固定ツールチェーン版 |
| `sample.json` | 公開証拠・結果・検査ログ・ソース指紋 |
| `requirements.txt` / `.gitignore` / `.github/workflows/validate.yml` | 依存・除外規則・CI |

```console
# 変更したソースを検査し、同梱結果と画面を更新
python validate.py --refresh-sample

# Lean未実行を明示したRC版として、許可リストの14ファイルのみZIP化
python validate.py --package VPI_Cyber_Assurance_v2.0.0-rc2.zip --allow-pending-formal
```

Leanを実行して成功した場合、ZIP作成の `--allow-pending-formal` は不要です。既知のLeanビルド失敗をこのオプションで通すことはできません。変更後の未検査ソース、改変された保存結果、運用鍵・DBはZIP作成時に拒否します。ソース指紋は改変の照合用で、発行者署名ではありません。

公開範囲は、合成3社・固定操作・その安全条件と証拠の検査です。企業固有の実データ・接続設定・運用秘密鍵は含めません。本番適合、第三者認証、標準適合、実企業との共同検証は主張しません。利用条件は `NOTICE.md` を参照してください。

### English summary

A fixed-scope cyber-assurance reference for inter-company operations in a Physical Internet setting. Three local processes use separate SQLite databases and Ed25519 keys. The PoC binds receiver approval, source admission, operation content and terminal receipts; switching from B to C requires confirmed cancellation at B. Unknown outcomes remain on hold.

Use `python demo.py --serve`, `python verifier.py sample.json`, and `python validate.py`. The independent verifier checks disclosed evidence, not real-world truth or compromised signers. The bundled anchors are not independent provenance. Lean declarations are included but were not executed for this RC; `--require-lean` fails unless the pinned Lean build succeeds. This is not a complete logistics platform or a production security product.
