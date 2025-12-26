# local development PKGBUILD - not intended for package repositories

options=(!strip debug)

pkgname=picotls
pkgver=1.0
pkgrel=1
pkgdesc='picotls'
url='https://github.com/kaldron-labs/picotls'
license=('MIT')
arch=('x86_64')
depends=('openssl')
makedepends=('cmake' 'git')

prepare() {
    cd "$startdir"
    git submodule update --init --recursive
}

build() {
    cd "$startdir"
    cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/
    cmake --build build
}

package() {
    cd "$startdir"
    DESTDIR="$pkgdir" cmake --install build
}
