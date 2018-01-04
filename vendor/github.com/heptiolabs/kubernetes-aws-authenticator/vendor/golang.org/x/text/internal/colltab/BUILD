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
        "collelem_test.go",
        "colltab_test.go",
        "contract_test.go",
        "iter_test.go",
        "numeric_test.go",
        "trie_test.go",
        "weighter_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/text/language:go_default_library"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "collelem.go",
        "colltab.go",
        "contract.go",
        "iter.go",
        "numeric.go",
        "table.go",
        "trie.go",
        "weighter.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/golang.org/x/text/language:go_default_library",
        "//vendor/golang.org/x/text/unicode/norm:go_default_library",
    ],
)

go_test(
    name = "go_default_xtest",
    srcs = ["collate_test.go"],
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/text/language:go_default_library"],
)

filegroup(
    name = "package-srcs",
    srcs = glob(["**"]),
    tags = ["automanaged"],
    visibility = ["//visibility:private"],
)

filegroup(
    name = "all-srcs",
    srcs = [":package-srcs"],
    tags = ["automanaged"],
)
