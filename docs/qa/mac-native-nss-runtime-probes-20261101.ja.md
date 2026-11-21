# 次のMac NSS修正検証候補（2026-11-01 18時台 JST）

Floorp側にopt-inの限定DSO buildと実NSS/stack-fixer probeを追加した。実行済みworkflow・消費済みrun41187440235と無効prototypeは不変。今回は新nativeを開始しない。

新nativeでは、固定generated graphの実宣言と完全hashを確認してから同OBJDIRのsoftoken_softokn3/freebl_freebl3だけを順に追加buildする。既存browser/faster/child resources配置後、同xpcshellでNSS internal PKCS11 slotの32-byte乱数生成とRust SHA-256既知解を独立probeとして確認する。SHA-256単独はRust実装なのでNSS load成功とはみなさない。既存42件のtest・assertions・manifest・planは維持し、probeを42件へ加算しない。

stock stack-fixerはtools取得直後に実wrapperと実toolで最大30秒の確認を行う。NSS probeは最大120秒、どちらも元345分work/360分job内、3秒query/3samples・30秒profile・source/FD identity・owned cleanupを維持する。新summary proofは追加build/stack/probe receiptを要求するが、製品資格・実DSO map先・full-session cleanupは認定しない。

暗号化回収はdefaultの8パスを維持し、新workflowの明示flagでだけ固定3つのprobe logを追加する。総量64MiB、各probe log1MiB、FD/owner/link拒否とCMS認証暗号化を維持。SDK payload・秘密情報を成果に含めない。

次は未使用のbranch/origin（候補b/qa-fresh45-nss-20261101）、実行/回収flag、fixture/headと全pins/catalog、SDK13011079529のAPI/期限/bytes、公開verifierと固有証拠を凍結する。旧origin selectorのままでは今回のflag付き経路を起動しない。必要回帰・公開制御・通常CIが揃ってから、branch不存在・push0を確認し厳密なref作成を初回1回だけ送る。承認済みロードマップ範囲として進め、再承認を求めない。

元runの42 UNVERIFIED+3無効、executed/passed unknownとfirst failure、旧practical/ledgerは維持。詳細はFloorpの `docs/qa/qa-nss-runtime-probes-2026-11-01.ja.md`。
