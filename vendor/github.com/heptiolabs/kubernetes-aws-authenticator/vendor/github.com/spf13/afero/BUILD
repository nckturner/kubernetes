package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
    "go_test",
)

go_test(
    name = "go_default_test",
    srcs = [
        "afero_test.go",
        "basepath_test.go",
        "composite_test.go",
        "copyOnWriteFs_test.go",
        "ioutil_test.go",
        "match_test.go",
        "memmap_test.go",
        "path_test.go",
        "ro_regexp_test.go",
        "util_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "afero.go",
        "basepath.go",
        "cacheOnReadFs.go",
        "const_win_unix.go",
        "copyOnWriteFs.go",
        "httpFs.go",
        "ioutil.go",
        "match.go",
        "memmap.go",
        "os.go",
        "path.go",
        "readonlyfs.go",
        "regexpfs.go",
        "unionFile.go",
        "util.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/github.com/spf13/afero/mem:go_default_library",
        "//vendor/golang.org/x/text/transform:go_default_library",
        "//vendor/golang.org/x/text/unicode/norm:go_default_library",
    ],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [
        ":package-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/spf13/afero/mem:all-srcs",
    ],
    tags = ["automanaged"],
)
