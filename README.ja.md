# Nagi

バイブコーディングに最適化されたタッチフレンドリーなWebベースターミナル。ハードウェアキーボードなしでiPad/iPhoneからターミナルにアクセスし、ソファ、ベッド、カフェなど、どこからでもコーディングを楽しめます。

tmuxやClaude Codeなどのフルスクリーンアプリケーションに対応。

<img src="images/image1.png" width="400"> <img src="images/iPhone.png" width="200">

<img src="images/image2.png" width="400">

## 特徴

- **タッチ操作対応**: ハードウェアキーボードなしでも操作可能
- **特殊キーボタン**: Ctrl, Alt, Esc, Tab, Enter, 矢印キー等
- **tmuxサポート**: tmux操作用のクイックボタンパネル
- **日本語入力**: テキスト入力モーダルで長文入力に対応
- **自動コマンド実行**: 接続時に指定コマンドを自動実行
- **xterm.js**: フル機能のターミナルエミュレーション

## インストール

### npm (推奨)

```bash
npm install -g nagi-terminal
```

### 手動インストール

```bash
git clone https://github.com/shi3z/nagi.git
cd nagi
uv sync
```

## 使い方

### npm版

```bash
nagi
nagi -p 8080  # ポート指定
nagi -c /path/to/config.json  # 設定ファイル指定
```

### 手動版

```bash
uv run python main.py
```

ブラウザで `http://<サーバーIP>:8765/` にアクセス。

## 設定

`config.json` で設定可能:

```json
{
    "startup_command": "tmux a || tmux new",
    "shell": "/bin/bash",
    "port": 8765
}
```

| 設定 | 説明 | デフォルト |
|------|------|------------|
| `startup_command` | 接続時に自動実行するコマンド | `tmux a \|\| tmux new` |
| `shell` | 使用するシェル | `/bin/bash` |
| `port` | 待ち受けポート | `8765` |

## コントロールパネル

### 基本キー
- **Ctrl** / **Alt**: モディファイアキー（トグル）
- **Esc** / **Tab** / **Enter**: 特殊キー
- **矢印キー**: カーソル移動
- **Home** / **End** / **PgUp** / **PgDn**: ナビゲーション

### ショートカット
- **^C**: 中断 (Ctrl+C)
- **^D**: EOF (Ctrl+D)
- **^Z**: サスペンド (Ctrl+Z)

### tmuxパネル
`tmux`ボタンで展開:
- **c**: 新規ウィンドウ
- **n** / **p**: 次/前のウィンドウ
- **d**: デタッチ
- **%** / **"**: 縦/横分割
- **o**: ペイン切替
- **z**: ズーム
- **[**: コピーモード

### テキスト入力
`Text`ボタンで入力モーダルを開き、長文や日本語をペーストしてターミナルに送信。

## 要件

- Python 3.10+
- FastAPI
- uvicorn
- websockets

## ライセンス

MIT
