# NSS修正検証の初回入力（2026-11-02 JST）

新workflow `.github/workflows/mac-native-firefox45-nss-20261102.yml` を専用handoffへ準備します。triggerは新branch `b/qa-fresh45-nss-20261102` の作成pushだけ。before全0・attempt1、認証APIの同run/head/唯一のfresh-firefox45 jobを確認します。macos-15-intel、345分work/360分job、1実行ずつとmanual rerun禁止を維持します。既存workflow・無効prototype・消費済みrunは不変です。

fixtureの全157 source hashesと824 exact IDsを固定し、native preflightは全824成功・skip0を要求します。compile source7dd619742b25567e479eeda97ae071d10542ad0b、harness cbe45a7d7480d713b2c40a9ed348420126e6ccb0、SDK13011079529のschema4/完全profileとproducer41128679337は区別します。SDK期限は2026-11-13T21:08:48Z。起動前と取得前後に正規API/bytesを再照合します。

pipelineは `--fresh-firefox45 --nss-runtime-closure`。実行前/失敗後の暗号化回収は `--nss-origin-20261102 --nss-probes` を明示します。旧profileの交差を拒否し、元8パス＋固定3probe logsだけを64MiB/FD/owner/link制限で認証暗号化します。SDKや自由なファイル、秘密情報を追加しません。

公開verifierは既存scope proofに加え、独立したNSS predicateで固定graph・追加stage/cleanup・実tool・同binary/fixed fixture・NSS PK11操作とRust既知解の完全receiptを要求します。Rust SHA-256だけの成功をNSS load証拠にしません。追加証拠の欠落や差替えを拒否し、固定NSS失敗語彙とhash/件数だけを公開します。45行、first failure、stdout/artifact一致を維持します。実DSO map先や製品資格は未確認です。

隔離検証は関連58件成功、新824-ID全発見/旧816保持、独立NSS正例1＋負例26/秘匿制御、公開射影7、起動正例1＋負例10と構文/flag結合確認です。旧全816回帰は過去の固定sourceの証拠として保持し、現在source全824実行へ換算しません。今回不変766件は再実行していません。

次は新fixture通常CIと同Runtime shadowの終端を確認します。その後、新branch不存在・push0、SDK、両Draft/open/未merge、担当と排他、固有意図を直前照合し、条件が揃った場合だけPOST git/refsを1回送ります。旧run41187440235はfailure、Mac42件はUNVERIFIED＋上流無効3件、executed/passed unknownのままです。詳細はFloorpの `docs/qa/qa-nss-input-freeze-2026-11-02.ja.md`。
