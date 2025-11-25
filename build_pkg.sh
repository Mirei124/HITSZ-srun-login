#!/bin/bash

set -euo pipefail

pkgver=$(cat pyproject.toml | sed -n 's/version = "\(.\+\)"/\1/p')

python -m build --sdist --no-isolation
rm -f pacman/*.tar.gz
cp -f dist/srun_login-"$pkgver".tar.gz pacman/
cd pacman/
sed -i "s/pkgver=.*/pkgver=${pkgver}/" PKGBUILD
updpkgsums
makepkg -sCf
