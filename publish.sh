#!/bin/bash

# npm publish 自動化スクリプト
# 使い方: ./publish.sh [patch|minor|major]

set -e

# 色の定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# バージョンタイプ（デフォルトはpatch）
VERSION_TYPE=${1:-patch}

# 有効なバージョンタイプかチェック
if [[ ! "$VERSION_TYPE" =~ ^(patch|minor|major)$ ]]; then
    echo -e "${RED}エラー: バージョンタイプは patch, minor, major のいずれかを指定してください${NC}"
    echo "使い方: ./publish.sh [patch|minor|major]"
    exit 1
fi

echo -e "${YELLOW}=== npm publish 自動化スクリプト ===${NC}"
echo ""

# 現在のバージョンを取得
CURRENT_VERSION=$(node -p "require('./package.json').version")
echo -e "現在のバージョン: ${GREEN}$CURRENT_VERSION${NC}"

# 未コミットの変更があるかチェック
if [[ -n $(git status --porcelain) ]]; then
    echo -e "${YELLOW}未コミットの変更があります。先にコミットします...${NC}"
    git add -A
    git status --short
    echo ""
    read -p "コミットメッセージを入力してください: " COMMIT_MSG
    if [[ -z "$COMMIT_MSG" ]]; then
        COMMIT_MSG="Update before version bump"
    fi
    git commit -m "$COMMIT_MSG"
    echo -e "${GREEN}コミット完了${NC}"
fi

# バージョンを上げる
echo ""
echo -e "${YELLOW}バージョンを $VERSION_TYPE で上げます...${NC}"
npm version $VERSION_TYPE --no-git-tag-version

# 新しいバージョンを取得
NEW_VERSION=$(node -p "require('./package.json').version")
echo -e "新しいバージョン: ${GREEN}$NEW_VERSION${NC}"

# 変更をコミット
echo ""
echo -e "${YELLOW}バージョン変更をコミットします...${NC}"
git add package.json
git commit -m "v$NEW_VERSION"

# タグを作成
echo -e "${YELLOW}タグ v$NEW_VERSION を作成します...${NC}"
git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"

# リモートにプッシュ
echo ""
echo -e "${YELLOW}リモートにプッシュします...${NC}"
git push origin main
git push origin "v$NEW_VERSION"

# npm に公開
echo ""
echo -e "${YELLOW}npm に公開します...${NC}"
npm publish

echo ""
echo -e "${GREEN}=== 公開完了! ===${NC}"
echo -e "バージョン: ${GREEN}$NEW_VERSION${NC}"
echo -e "npm: https://www.npmjs.com/package/nagi-terminal"
echo -e "GitHub: https://github.com/shi3z/nagi/releases/tag/v$NEW_VERSION"
