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
      "conditions": [
        ["OS == 'mac'", {
          "include_dirs": [
            "../../include",
          ],          
          "xcode_settings": {
          	"LIBRARY_SEARCH_PATHS": ["../../lib"],
            "MACOSX_DEPLOYMENT_TARGET": "10.7",
            "OTHER_CFLAGS": [
              "-std=c++11",
              "-stdlib=libc++",
              "-Wno-unused-function",
              "-Wno-deprecated-declarations",
            ],
          },
        }],
      ],
    },
  ],
}
