# 明日やること (remedify)

_最終状態: v0.11.2 / テスト159件 全パス / ローカル未コミット_

## 0. まず最初に — リリース作業（未pushぶんを出す）

今日の 0.10.0〜0.11.2 がローカルにしか無い。お手元で:

```bash
cd <remedify>
git add -A
git commit -m "v0.11.2: verify (closed loop), --context, OSV input, endoflife.date (vendored snapshot), schema canary, SECURITY.md, scheduled CI"
git push
source .venv/bin/activate && python3 -m build && python3 -m twine upload dist/remedify-0.11.2* && deactivate
gh release create v0.11.2 --title "v0.11.2 — verify + self-maintaining" --notes-file CHANGELOG.md
```

- push 後、Actions で通常CIと **scheduled.yml が構文的に通るか**を確認（初回は workflow_dispatch で手動実行してみる）
- `peter-evans/create-pull-request` を使うので、リポジトリ設定で
  Settings → Actions → Workflow permissions を「Read and write」+「Allow
  Actions to create PRs」に**要変更**（でないと EOL 自動PRが失敗する）

## 1. 「広める」— レビューの再序列化に沿って（到達 ÷ 保守コスト）

優先順に。詳細は下の「背景」。

- [ ] **90秒デモを README 先頭に**（最高ROI・パッケージングより先）
      before scan → `remedify` → 6コマンドに畳まれる → `verify` で「消えた」を証明。
      asciinema か GIF。実際の脆弱イメージ（例 `nicolaka/netshoot` / `debian:11`）で。
- [ ] **Trivy plugin 化**（唯一「先にやるべき」枠。到達最大・保守最小）
      plugin manifest はリリースを指すだけ。`trivy remedify` で呼べるように。
- [ ] GH Action は **README の composite-action スニペット止まり**で開始
      （いきなり Marketplace publish しない＝製品化の保守負債を先送り）
- [ ] awesome-list / MCP レジストリに一度きりのPR（安いので必ず。流入は過大評価しない）
- [ ] copa への相互言及PR（チャネルではなく CNCF への正統性・関係構築として）
- [ ] Homebrew は後回し（pip で足りる。formula 維持が割に合わない）

## 2. 「使うたびに共有物が生まれる」設計（バイラルの種）

- [ ] フリートサマリを **Slack/PR に貼れる要約**として出す小フラグ or 既存出力の磨き込み
      （「1修正→N workloads」はスクショ映えする＝利用が配布イベントになる）

## 3. 社内②ルート（Sysdig 取り込み）— 証拠を積んでから

- [ ] #product スレッド返信（作成済みドラフトを使う。まず社内数人に触ってもらった後）
- [ ] **雇用/IP境界の事前クリア**（Sに勤めながらSのAPIを叩くOSSを個人メンテ）
      — この相談自体が取り込みの売り込みになる。事前に。
- [ ] 生むべきは機能より**証拠**: 利用実績・「トリアージ時間が減った」の声
- [ ] 位置づけの意思決定: 実証機 / 個人ブランド / AIショーケース の3つは
      Sが取り込むと緊張する。**耐久資産はコードでなく「示した判断力＋ブランド」**
      という前提で、記事・verify・提案を「一つの thesis の証拠」として通す。

## 4. 残りの開発バックログ（ROADMAP 参照）

- [ ] v0.12: オーナー別レポート分割（K8s label / Sysdig Resource Ownership）
      ← 檜垣さんの Resource Ownership 記事と地続き。固有の強み
- [ ] v0.12: エアギャップ・バンドル（`remedify bundle`：.deb/.rpm URL+checksum+install script）
- [ ] v0.12: 提案2（`--group-by disruption` ダウンタイム予算ビュー）
- [ ] v0.12: 提案3（ロールバック手順生成：`pkg=OLD` + `apt-mark hold` / ansible rescue）
- [ ] v1.0: `--format sarif`、GitHub Action 正式版、ベンダーアドバイザリ照合（USN/CSAF）
- [ ] v1.0: copa 互換出力（コンテナ分を copa に渡す）
- [ ] 判断保留中: Go 書き換え（単一バイナリ）はインターフェース安定後

## 5. 記事（未公開ドラフト）

- [ ] Zenn / Qiita / dev.to：公開前に**数字を更新**（テスト159件、入力4スキャナ、verify）
- [ ] セキュリティレビューのくだりは**書かない**方針を維持（まだ穴があるかも前提）
- [ ] verify を記事のフックに格上げ:「スキャナは"何が壊れてるか"、AIは"相談相手"、
      remedify は"手と、答え合わせ"」

## メモ / 未解決の緊張

- **bus factor 1** は自動化では消えない（非定型＝パーサ脆弱性・Python破壊的変更・
  判断を要する脆弱性報告 は人依存）。真に消すのは第二コミッタ or 組織の器のみ。
  当面の緩和は「表面積を小さく保つ＝依存ゼロ」。
- 単一ファイル 1500行超は貢献者の壁になりつつある。分割はまだしないが、
  論理セクションのコメント境界は明示しておく（第二メンテナが乗れる可読性）。
- scheduled CI の Trivy golden は「パースできるか」専用（drift 検知・赤OK）、
  fixture pin の canary は「正しい出力か」（常に緑必須）。この2つは分離済み。
