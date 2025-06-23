#!/bin/bash

# Git Cleanup Script - Remove old branches, tags, and releases
# Usage: ./scripts/cleanup-git.sh [options]
# Options:
#   --dry-run         Show what would be deleted without actually deleting
#   --days-branches   Days to keep branches (default: 90)
#   --days-tags       Days to keep tags (default: 30)
#   --keep-tags       Number of recent tags to keep (default: 50)
#   --keep-releases   Number of recent releases to keep (default: 20)
#   --days-releases   Days to keep releases (default: 30)
#   --remote          Remote name (default: origin)

set -euo pipefail

# Default values
DRY_RUN=false
DAYS_BRANCHES=90
DAYS_TAGS=30
KEEP_TAGS=50
KEEP_RELEASES=20
DAYS_RELEASES=30
REMOTE="origin"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --days-branches)
            DAYS_BRANCHES="$2"
            shift 2
            ;;
        --days-tags)
            DAYS_TAGS="$2"
            shift 2
            ;;
        --keep-tags)
            KEEP_TAGS="$2"
            shift 2
            ;;
        --keep-releases)
            KEEP_RELEASES="$2"
            shift 2
            ;;
        --days-releases)
            DAYS_RELEASES="$2"
            shift 2
            ;;
        --remote)
            REMOTE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Git Cleanup Script"
echo "=================="
echo "Remote: $REMOTE"
echo "Dry run: $DRY_RUN"
echo "Keep branches newer than: $DAYS_BRANCHES days"
echo "Keep tags newer than: $DAYS_TAGS days"
echo "Keep at least: $KEEP_TAGS recent tags"
echo "Keep releases newer than: $DAYS_RELEASES days"
echo "Keep at least: $KEEP_RELEASES recent releases"
echo ""

# Function to delete or show what would be deleted
delete_ref() {
    local ref=$1
    local type=$2
    
    if [ "$DRY_RUN" = true ]; then
        echo "[DRY RUN] Would delete $type: $ref"
    else
        echo "Deleting $type: $ref"
        git push "$REMOTE" --delete "$ref" || echo "Failed to delete $ref"
    fi
}

# Fetch latest refs
echo "Fetching latest refs from $REMOTE..."
git fetch --all --prune --tags

# Clean up merged branches
echo ""
echo "=== Cleaning up merged branches ==="
PROTECTED_BRANCHES="main|master|develop|staging|production|HEAD"
MERGED_BRANCHES=$(git branch -r --merged "$REMOTE/main" | grep -v -E "($PROTECTED_BRANCHES)" | sed "s|$REMOTE/||" | grep -v "^/")

if [ -z "$MERGED_BRANCHES" ]; then
    echo "No merged branches to delete"
else
    echo "Found merged branches:"
    echo "$MERGED_BRANCHES"
    echo ""
    
    for branch in $MERGED_BRANCHES; do
        delete_ref "$branch" "merged branch"
    done
fi

# Clean up old unmerged branches
echo ""
echo "=== Cleaning up old unmerged branches ==="
CUTOFF_DATE=$(date -d "$DAYS_BRANCHES days ago" +%s)

OLD_BRANCHES=$(git for-each-ref --format='%(refname:short) %(committerdate:unix)' "refs/remotes/$REMOTE" | \
    grep -v -E "($PROTECTED_BRANCHES)" | \
    awk -v cutoff="$CUTOFF_DATE" '$2 < cutoff {print $1}' | \
    sed "s|$REMOTE/||")

if [ -z "$OLD_BRANCHES" ]; then
    echo "No old branches to delete"
else
    echo "Found old branches (older than $DAYS_BRANCHES days):"
    for branch in $OLD_BRANCHES; do
        BRANCH_DATE=$(git log -1 --format=%cd --date=short "$REMOTE/$branch" 2>/dev/null || echo "unknown")
        echo "  $branch (last commit: $BRANCH_DATE)"
    done
    echo ""
    
    for branch in $OLD_BRANCHES; do
        delete_ref "$branch" "old branch"
    done
fi

# Clean up old tags (by count)
echo ""
echo "=== Cleaning up old tags (keeping newest $KEEP_TAGS) ==="
ALL_TAGS=$(git for-each-ref --sort=-creatordate --format='%(refname:short)' refs/tags)
TOTAL_TAGS=$(echo "$ALL_TAGS" | wc -l)

if [ "$TOTAL_TAGS" -gt "$KEEP_TAGS" ]; then
    TAGS_TO_DELETE=$(echo "$ALL_TAGS" | tail -n +$((KEEP_TAGS + 1)))
    echo "Total tags: $TOTAL_TAGS"
    echo "Keeping: $KEEP_TAGS newest tags"
    echo "Deleting: $(echo "$TAGS_TO_DELETE" | wc -l) old tags"
    echo ""
    
    for tag in $TAGS_TO_DELETE; do
        delete_ref "$tag" "tag"
    done
else
    echo "Total tags ($TOTAL_TAGS) is within limit ($KEEP_TAGS), skipping count-based cleanup"
fi

# Clean up old tags (by date)
echo ""
echo "=== Cleaning up old tags (older than $DAYS_TAGS days) ==="
CUTOFF_DATE_TAGS=$(date -d "$DAYS_TAGS days ago" +%s)

OLD_TAGS=$(git for-each-ref --format='%(refname:short) %(creatordate:unix)' refs/tags | \
    awk -v cutoff="$CUTOFF_DATE_TAGS" '$2 < cutoff {print $1}')

if [ -z "$OLD_TAGS" ]; then
    echo "No old tags to delete by date"
else
    echo "Found old tags (older than $DAYS_TAGS days):"
    for tag in $OLD_TAGS; do
        TAG_DATE=$(git log -1 --format=%cd --date=short "$tag" 2>/dev/null || echo "unknown")
        echo "  $tag (created: $TAG_DATE)"
    done
    echo ""
    
    for tag in $OLD_TAGS; do
        delete_ref "$tag" "old tag"
    done
fi

echo ""
echo "=== Cleaning up old releases ==="

# Check if gh command is available
if ! command -v gh &> /dev/null; then
    echo "GitHub CLI (gh) not found. Skipping release cleanup."
    echo "Install it from: https://cli.github.com/"
else
    # Clean up old releases (by count)
    echo "Keeping newest $KEEP_RELEASES releases..."
    
    ALL_RELEASES=$(gh release list --limit 100 --json tagName,createdAt,isDraft,isPrerelease 2>/dev/null | \
        jq -r '.[] | select(.isDraft == false) | "\(.tagName) \(.createdAt)"' | sort -k2 -r)
    
    if [ -n "$ALL_RELEASES" ]; then
        TOTAL_RELEASES=$(echo "$ALL_RELEASES" | wc -l)
        
        if [ "$TOTAL_RELEASES" -gt "$KEEP_RELEASES" ]; then
            RELEASES_TO_DELETE=$(echo "$ALL_RELEASES" | tail -n +$((KEEP_RELEASES + 1)) | cut -d' ' -f1)
            
            echo "Total releases: $TOTAL_RELEASES"
            echo "Deleting: $(echo "$RELEASES_TO_DELETE" | wc -l) old releases"
            echo ""
            
            for release in $RELEASES_TO_DELETE; do
                if [ "$DRY_RUN" = true ]; then
                    echo "[DRY RUN] Would delete release: $release"
                else
                    echo "Deleting release: $release"
                    gh release delete "$release" --yes || echo "Failed to delete release $release"
                fi
            done
        else
            echo "Total releases ($TOTAL_RELEASES) is within limit ($KEEP_RELEASES), skipping count-based cleanup"
        fi
        
        # Clean up old releases (by date)
        echo ""
        echo "Finding releases older than $DAYS_RELEASES days..."
        CUTOFF_DATE=$(date -d "$DAYS_RELEASES days ago" -u +"%Y-%m-%dT%H:%M:%SZ")
        
        OLD_RELEASES=$(gh release list --limit 100 --json tagName,createdAt,isDraft 2>/dev/null | \
            jq -r --arg cutoff "$CUTOFF_DATE" '.[] | select(.isDraft == false and .createdAt < $cutoff) | .tagName')
        
        if [ -n "$OLD_RELEASES" ]; then
            echo "Found old releases to delete:"
            for release in $OLD_RELEASES; do
                if [ "$DRY_RUN" = true ]; then
                    echo "[DRY RUN] Would delete old release: $release"
                else
                    echo "Deleting old release: $release"
                    gh release delete "$release" --yes || echo "Failed to delete release $release"
                fi
            done
        else
            echo "No releases older than $DAYS_RELEASES days found"
        fi
    else
        echo "No releases found or unable to fetch releases"
    fi
fi

echo ""
echo "Cleanup complete!"

# Show current state
echo ""
echo "=== Current state ==="
BRANCH_COUNT=$(git branch -r | grep -v HEAD | wc -l)
TAG_COUNT=$(git tag | wc -l)
echo "Remaining remote branches: $BRANCH_COUNT"
echo "Remaining tags: $TAG_COUNT"

if command -v gh &> /dev/null; then
    RELEASE_COUNT=$(gh release list --limit 100 2>/dev/null | wc -l)
    echo "Remaining releases: $RELEASE_COUNT"
fi