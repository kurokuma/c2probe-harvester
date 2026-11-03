# mal-sim — ValleyRAT 検体の一括収集・解析パイプライン

[c2probe の判定ルール](https://github.com/kurokuma/c2probe/tree/main/probes)で C2 を叩き、ステージを取得し、難読化を解いて解析可能な PE まで自動で切り出すツールです。送信バイト列・判定・復号はすべて YAML で駆動します。Linux / Python 3.9+、コンパイル不要。

## クイックスタート

C2 の `IP ポート` を並べれば、解析可能な PE が出てくるまでを一発で行います。

```bash
# 1. 導入
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements.txt

# 2. 収集対象を準備(1行1件、"ip port" か "ip:port"、# はコメント)
cat targets.txt
192.0.2.10 6661
192.0.2.11:443

# 3. 一括収集: ダウンロード → 復号 → PE 切り出し
python scripts/harvest.py targets.txt --out harvest/ --download --delay 15

# 4. 解析可能な PE がここに出る
ls harvest/*/carved/*.bin
```

`--download` を付けないとDRY RUN(通信しない)で対象の確認だけ行います。

## 一括収集: harvest.py

各接続先で `probes/valleyrat/vvas.yaml`(判定)と `recipes/body-from-total-length.yaml`(本文取得)を実行してステージを保存し、続けて `extract_sample.py` で復号・PE 切り出しまで行います。

| オプション | 既定 | 意味 |
| --- | --- | --- |
| `--download` | off | 実際に接続する(未指定は dry-run) |
| `--delay` | 10 | 接続先間の待ち秒数(フットプリント抑制) |
| `--timeout` | 5 | 1 接続先あたりの受信待ち秒数 |
| `--total-timeout` | 15 | 1 接続先あたりの全体 timeout 秒数 |
| `--out` | (必須) | 出力ディレクトリ |

### 出力

```
harvest/
  <ip>_<port>/
    sample.bin                  # 取得した難読化ステージ
    metadata.json               # 判定・取得の記録
    carved/
      <sha16>_<machine>.bin     # 復号・切り出した PE(← これを解析する)
      extract-report.json       # 鍵・各 PE の sha256 / imphash / エクスポート
  harvest-summary.json          # 全接続先の結果(逐次書き出し)
```

標準出力は接続先ごとに1行、carve できた PE はインデントで続きます。

```
192.0.2.10:6661 rc=0 xor1 key=36 PEs=2
    i386 <module>.dll missing=0 <sha16>
    i386 <module>.dll missing=0 <sha16>
192.0.2.11:443 rc=1 no sample acquired
```

### 結果の読み方

| 表示 | 意味 |
| --- | --- |
| `rc=0` ＋ PE 行あり | 取得・carve 成功。`carved/` の PE を静的解析へ。モジュール名・エクスポート・imphash は `extract-report.json` 参照 |
| `rc=0` ＋ PE 行なし | ステージは取れたが PE なし。多くは**空ステージ**(本文が単一バイトの繰り返し = 鍵で復号すると全ゼロ。ペイロード未配置) |
| `rc=1 no sample acquired` | 判定不一致・無応答。スキャンの偽陽性や停止の可能性 |
| `missing=N`(N>0) | 宣言サイズに N バイト欠落。ファイル名が `_truncated.bin` |

## 取得した PE を解析する

`carved/*.bin` はそのまま静的解析に回せます(実行はしない)。

```bash
f=harvest/192.0.2.10_6661/carved/*_i386.bin
rabin2 -I  $f           # ヘッダ概要
rabin2 -E  $f           # エクスポート一覧
rabin2 -i  $f           # インポート
r2 -A      $f           # radare2 で解析(pdc @ sym.run など)
python -c "import pefile;print(pefile.PE('$f').get_imphash())"
```

ホスト検知には同梱 `valleyrat_vvas_online_module.yar`(復号後の本体を独自エクスポート名・RTTI クラス名で検知)を使います。

## 復号・PE 切り出しを単体で: extract_sample.py

harvest を使わず、手持ちの `sample.bin` を復号したいとき:

```bash
python scripts/extract_sample.py sample.bin --out carved/
```

難読化鍵は自動検出します。① 単バイト XOR(通常。セッション毎の鍵)→ ② 反復多バイト XOR(単バイトで PE が出ない変種向け。PE 内のゼロ埋めから鍵を復元、`--max-keylen` で探索長変更)。いずれも `pefile` でパースできる PE になることを条件とし、誤検出でゴミを出しません。鍵が分かれば明示できます。

```bash
python scripts/extract_sample.py sample.bin --out carved/ --xor-key 0x36
python scripts/extract_sample.py sample.bin --out carved/ --xor-key-hex 1a2b3c4d
```

RC4 等の**ストリーム暗号は総当たりできません**。どの鍵でも PE が出ないときはバイトエントロピーを添えて報告します(高=ストリーム暗号の可能性、低=空/切り詰め)。切り出した PE は二重クリックで起動できないよう拡張子 `.bin` で保存します。

## 単一接続先: download_sample.py

ルール単位で試す・一覧する:

```bash
python scripts/download_sample.py --list                       # 同梱ルール一覧(通信なし)
python scripts/download_sample.py \
  --rule probes/valleyrat/vvas.yaml \
  --recipe recipes/body-from-total-length.yaml \
  --host 192.0.2.1 --port 1234 --output ./capture --download
```

動作は「ルール実行 → 最後の match 成立かつ reject_if 不成立 → 取得」。判定不一致なら追加要求を送らず出力も作りません。接続先は単一の IP・ポート(`reconnect` がある場合だけ同じ先に再接続)。HTTP の Host / TLS の SNI はルールに従いますが、そこから別ホストへは接続せず redirect も追いません。

終了コード: `0`=取得完了 or dry-run/list 成功、`1`=定義・通信・取得エラー、`2`=判定不一致・reject。失敗時 stderr は `failed:` に続く JSON(`phase` / `operation` / 接続先 / `probe_match` / `received_bytes` / `artifact_bytes`)。

秘密パラメータは `--params-file private-params.yaml`(`parameter.name: "value"` の YAML)で渡します。`--probe-param name=value` でも可。パラメータ値は dry-run や metadata に出しません。

---

## リファレンス

### 取得レシピ(`--recipe`)

判定の一致と検体取得は別です。レシピに保存方法を書きます。未指定なら判定時の受信〜EOF の生データを保存します。

```yaml
# 抽出済みの長さ分を受信(VVAS: 宣言長 307,214 − ヘッダ14 = 本文 307,200)
download_version: 1
artifact: { mode: stream, length: "$stage_size", max_bytes: 1048576 }
```

```yaml
# 受信済み・変換済みのバッファを保存
download_version: 1
artifact: { mode: buffer, source: "$response_body" }
```

- `recipes/body-from-total-length.yaml` … 宣言長がヘッダ込みの総長の場合(VVAS 用、ValleyRAT の既定)。
- `recipes/length-from-register.yaml` … 長さが本文長を表す場合。
- `recipes/save-response-body.yaml` / `save-body.yaml` … バッファ保存の例。
- `recipes/http-get-example.yaml` … 一致後に再接続して GET し本文のみ保存する例(パスは要調整)。

### 対応 DSL

| 分類 | 操作 |
| --- | --- |
| transport | tcp / tls / starttls、prelude_hex、server_name、insecure_tls |
| 要求 | send、send_http、reconnect |
| 受信 | recv_exact、recv_up_to、recv_until、recv_frame、recv_http、peer_certificate |
| データ構築 | literal、pack、concat |
| 抽出 | u8 / u16 / u32 / u64(LE・BE)、crc32、bufferlen、asciidecimal |
| 演算 | add、sub、xor、and、or、shift_left、shift_right(u64 wrapping) |
| 変換 | ascii_hex_decode、base64_decode / encode、RC4、gzip_decompress、msgpack_string |
| 条件 | all、any、not、eq、ne、lt、gt、bytes_eq、bytes_contains、bytes_regex、buffer_starts_with |
| 判定 | match、reject_if、classification、confidence、status、fields |

`headers_only` はヘッダのみ読み、本文を受信しません(宣言 Content-Length は max_body_bytes の対象外。本文受信時のみ上限適用、Content-Length 無しの空本文も許容)。HTTP は chunked・重複ヘッダを拒否。未知の操作・未定義参照は実行前に拒否します。

### 出力ファイルと上限

| ファイル | 内容 |
| --- | --- |
| sample.bin | 取得し終えたバイト列(実行可能性・帰属は未検証) |
| sample.bin.part | 切断・timeout・サイズ超過等で不完全な場合 |
| probe-response.bin | 判定完了時点の受信バイト列 |
| metadata.json | ルール/レシピのパスと SHA-256、接続先、判定、取得サイズ・SHA-256、失敗理由 |

既存の出力ディレクトリは上書きしません。既定上限は受信量・成果物とも 32 MiB、全体 timeout 30 秒、最大 32 接続。`--max-bytes` / `--timeout` / `--total-timeout`(最大300秒)で変更。取得内容の実行・インポートは行いません。