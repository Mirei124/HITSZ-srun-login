#!/bin/bash

pkgver=$(cat pyproject.toml | sed -n 's/version = "\(.\+\)"/\1/p')

python -m build
rm -f pacman/*.tar.gz
cp -f dist/srun_login-"$pkgver".tar.gz pacman/
cd pacman/
sed -n "s/pkgver=.*/pkgver=${pkgver}/" PKGBUILD
updpkgsums
makepkg -sCf
