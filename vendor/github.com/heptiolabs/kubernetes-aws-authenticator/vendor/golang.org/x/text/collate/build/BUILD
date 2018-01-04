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
        "builder_test.go",
        "colelem_test.go",
        "contract_test.go",
        "order_test.go",
        "trie_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "builder.go",
        "colelem.go",
        "contract.go",
        "order.go",
        "table.go",
        "trie.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/golang.org/x/text/language:go_default_library",
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
    srcs = [":package-srcs"],
    tags = ["automanaged"],
)
