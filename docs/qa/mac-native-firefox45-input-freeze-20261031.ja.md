# Mac42件の初回診断実行の入力凍結

2026-10-31 JST 18時台。M1の新規branch初回1回に限定する。

通常Floorp CI41163418850/attempt1/head `e9c88fbcbfa98da41989fa8656701cfb380cfd19` は全5jobs成功。
docs41163418863のverify、Runtime shadow41163433733/attempt1/head `048529e1773eeb62e2bcfc3949f805ff39f71aca` も成功。
前のCI41128672556/Linux x64 exit1と原因未確定の記録は保持する。成功した別runで書き換えない。

## 固定入力

- Floorp fixture: `e9c88fbcbfa98da41989fa8656701cfb380cfd19`。
- Runtimeコンパイル元: `7dd619742b25567e479eeda97ae071d10542ad0b`。
- App Shim harness: `cbe45a7d7480d713b2c40a9ed348420126e6ccb0`。
- SDK: schema4の `sdk_source-20261031.json`、SHA256 `88ff6c5ea1941d7fc1e18f46e2426441eda04a186a23d79b9b0bc1d169e03f48`。
- 実SDK13011079529/producer41128679337/attempt1/head `032085d9c0176b68d405fb7d3297629df6c1a971`/job124313694921、期限2026-11-13T21:08:48Z。
- SDK profile SHA256 `ce50e72c5aa2d163a39ba6de283c58f1e2930fb5e261a22ddb6160f54edaaf42`、ZIP SHA256 `8d1fc67bc1b130e61c1fd334dcfdadd525a6bf095ad2d50d76a5626950d93aca`。
- 全150 helper hashesと765個の実ID catalogは前回の760成功・実Darwin専用5skipと完全一致。helper変更なし。実Macでは765件/skip0を要求する。
- 公開診断器の7制御とSDK proof5制御を通したコードは同一。上流45 IDsのうち有効42件、manifest無効3件の期待を保持。

09:03Zの最新認証APIでSDK metadata/producer/job/未失効と7時間超の残存期限を確認。
保存した105157519 ZIP bytesのdigestも一致し、全49701メンバーの独立全内容照合を同一bytesに結び直した。
Mac実行時も取得前後の認証API、全圧縮・raw・treeと失効・変更を検査してからSDKを使用する。

## 起動・上限・保存

新しい `.github/workflows/mac-native-firefox45-diagnostics-20261029.yml` は、無効候補から表示名と資格表示だけを変更した。
実行コード・source pins・保存経路は一致。旧実行済みworkflowと無効候補は保存する。
対象は `b/qa-fresh45-diagnostics-20261029` の新規push/attempt1、`macos-15-intel` の `fresh-firefox45` 1job。
新ref不存在・push run0・POST未送信を直前にAPI照合し、排他と操作意図を保存して `POST git/refs` を1回だけ送る。
結果不明は同ref/run/head/attempt/jobを照合し、再送・manual rerunしない。

job360分/work345分を実job起点で適用し、時計を再初期化しない。
query3秒/3samples、profile30秒、source/FD identity、owned cleanup、上流assertions/manifest/planを維持する。
SDKやbuild前にOpenSSL3と暗号化transportを実機probeする。
公開診断と固定8パスの暗号化artifactは失敗時も保持する。公開証明書SHA256は `874ad391d20a7ed468eba7a8da6c5c63542650ca4c1378a98e6e978cf8a6b094`。
復号鍵は担当Bの私有領域だけで保持し、保持期間14日、SDK/環境変数/任意ファイルは回収しない。

Mac42件の実結果と完全scoped logは実行終端後に判定する。実行開始は合格を意味しない。
旧ledgerの42 UNVERIFIED+3 MANIFEST_DISABLEDと旧practicalContinuationを保持し、新結果を別のroadmapContinuationへ記録する。
main変更、merge、release、公開ゲートrequired化、第三者送信、再委任はこの実行に含まない。
