#!/bin/sh

set -e

RELEASE_TYPE=${RELEASE_TYPE:-minor}
cargo set-version --bump ${RELEASE_TYPE}
VERSION=`cargo pkgid | cut -d"#" -f2`
export OPENID_RUST_MAJOR_VERSION=`echo ${VERSION} | cut -d"." -f1,2`
if [ "${RELEASE_TYPE}" != "patch" ]; then
    pushd ../openid-examples
    git checkout main
    git pull
    cargo upgrade -p openid@${OPENID_RUST_MAJOR_VERSION}
    cargo update
    cargo build
    git add .
    git commit -m"openid version ${OPENID_RUST_MAJOR_VERSION}"
    git branch v${OPENID_RUST_MAJOR_VERSION}
    git push
    git push origin v${OPENID_RUST_MAJOR_VERSION}
    popd
fi
handlebars-magic templates .
git add .
git commit -m"Release v${VERSION}"
git tag v${VERSION}
git push && git push --tag