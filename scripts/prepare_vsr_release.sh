#!/usr/bin/env sh

set -eu

usage() {
  cat <<'EOF'
Usage: ./scripts/prepare_vsr_release.sh <version>

Updates the workspace release version, refreshes Cargo.lock for workspace packages,
runs the same packaging checks used by the publish workflow, creates a release commit,
and creates the matching annotated tag.

Example:
  ./scripts/prepare_vsr_release.sh 0.1.9
EOF
}

die() {
  echo "$*" >&2
  exit 1
}

version="${1:-}"

if [ "$#" -ne 1 ] || [ -z "$version" ]; then
  usage >&2
  exit 1
fi

old_ifs=$IFS
IFS=.
set -- $version
IFS=$old_ifs

if [ "$#" -ne 3 ]; then
  die "release version must use MAJOR.MINOR.PATCH format"
fi

for part in "$@"; do
  case "$part" in
    ''|*[!0-9]*)
      die "release version must use numeric MAJOR.MINOR.PATCH components"
      ;;
  esac
done

if ! git diff --quiet || ! git diff --cached --quiet; then
  die "worktree must be clean before preparing a release"
fi

if [ -n "$(git ls-files --others --exclude-standard)" ]; then
  die "worktree must not contain untracked files before preparing a release"
fi

tag="vsra-v$version"

if git rev-parse -q --verify "refs/tags/$tag" >/dev/null 2>&1; then
  die "tag $tag already exists"
fi

current_version="$(cargo pkgid -p vsra | sed 's/.*#.*@//')"

if [ "$current_version" = "$version" ]; then
  die "vsra is already at version $version"
fi

sed -i \
  -e "/^\\[workspace.package\\]/,/^\\[/ s/^version = \".*\"$/version = \"$version\"/" \
  -e "s/^rest_macro = { path = \"crates\\/rest_macro\", version = \".*\" }$/rest_macro = { path = \"crates\\/rest_macro\", version = \"$version\" }/" \
  -e "s/^rest_macro_core = { path = \"crates\\/rest_macro_core\", version = \".*\" }$/rest_macro_core = { path = \"crates\\/rest_macro_core\", version = \"$version\" }/" \
  Cargo.toml

cargo update --workspace

cargo package -p rest_macro_core --features codegen,turso-local --locked --allow-dirty
cargo check -p vsra --locked

git add Cargo.toml Cargo.lock
git commit -m "Release vsra $version"
git tag -a "$tag" -m "Release vsra $version"

echo "Created release commit and tag:"
echo "  version: $version"
echo "  tag: $tag"
echo "Next:"
echo "  git push origin HEAD"
echo "  git push origin $tag"
