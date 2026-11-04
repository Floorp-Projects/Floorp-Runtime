# Mac QA target verifier の順序候補（2026-11-04）

run 41630387790 / attempt 1 / job 125898143523 は実workflowとして failure のまま保持する。選定上流45件は有効42 PASS・manifest無効3 SKIP。製品の品質認定ではない。

`upstream.prepare` は helpers build、helpers install、inventory を実行し、その後に7つの target build、child/resources が続く。消費済みworkflowの `target_ok` は inventory を7つの target build の後に要求する。候補は upstream の最初の3 stage、7 target stages、残り3 upstream stages の順序をそれぞれ一度ずつ要求し、ほかのチェックは変更しない。

`mac-native-target-order-20261104.patch` は消費済みworkflowからの**参照差分**であり、実行済みworkflowに適用しない。新しいworkflowへの接続、origin・SDK・fixture・期限・pinsの凍結、実機初回実行の準備は未了。今回このpatchによって実workflowは変更していない。

固定157 source hashesと認証済みarchive内summaryのhashを照合し、秘密情報・ネットワークなし隔離環境で元と候補の判定関数を再評価した。元は target proof false、候補は true。別に target graph/assets/smoke、upstream proof、全stageの個別完了、記録されたsummaryの最終判定関数は true。これは過去runの失敗を成功へ変更するものでも、実workflow全体の再実行や後処理・現在の期限再検証を意味するものでもない。task/session全子孫cleanupは未認定。

順序逆転・入替・重複・欠落、cleanup、anchor、asset・graph・inventory receipt・planの差替え、禁止stageなど14負例を拒否。最終summary側のrun・SDK・事前検査・期限・NSS・smoke差替え6負例も拒否。別に公開診断の既存7合成失敗制御で45行と未実行／不明／記録済みの区別、最終stdoutとartifact一致、機密文字列の非出力を確認した。対象helperは変更しておらず、839件を再実行・加算していない。

拡張検査の初回セットアップは、算術式を含む固定定数を `ast.literal_eval` で読めず中止し、復号pipeも早期切断された。隔離内でworkflow定数の代入を評価するよう検査を修正してから正常完了した。検査失敗は実Mac runの成否ではない。

次はこの候補を新しい専用workflowに結び、独自origin・入力来歴・事前制御と期限を再凍結する。実workflowの成功を証明するには、変更条件と固有証拠を先に記録した別のnative実行が必要。元run/branchを再利用しない。
