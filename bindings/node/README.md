Node.js addon is built like this (requires SWIG >= 3.x):   

```
swig -c++ -javascript -node -I../../nscrypto -o nscrypto_wrap.cc ../nscrypto.i
node-gyp configure build
```
