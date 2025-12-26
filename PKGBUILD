pkgname=picotls
pkgver=1.0
pkgrel=1
pkgdesc='picotls'
arch=('x86_64')
options=(!strip debug)

build() {
    echo ok
}

package() {
    DESTDIR="$pkgdir" cmake --install build
}
