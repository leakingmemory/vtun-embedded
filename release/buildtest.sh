rm -rf vtun-embedded-$version
tar xzvf $assetpath/vtun-embedded-$version.tar.gz || exit 1
cd vtun-embedded-$version || exit 1
./configure || exit 1
make || exit 1
if [ ! -f vtunemd ]; then
  echo 'Did not build the binary'
  exit 1
fi
cd ..
rm -rf vtun-embedded-$version