{
  "targets": [
    {
      "target_name" : "nscrypto",
      "sources" : [
        "nscrypto_wrap.cc",
        "../../nscrypto/nscrypto_ecdh.cc"
      ],
      "include_dirs": [
        "../../nscrypto",
      ],
      "libraries" : [
        "-lcrypto",
      ],
      "cflags": [
        "-std=c++11 -Wno-unused-value -Wno-unused-function -Wno-unknown-pragmas",
      ],
      "defines" : [
        "__NODE_JS__",
      ],
    }
  ]
}
