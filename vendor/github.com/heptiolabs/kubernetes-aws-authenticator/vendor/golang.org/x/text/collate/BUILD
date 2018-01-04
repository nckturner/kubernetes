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
        "collate_test.go",
        "export_test.go",
        "option_test.go",
        "reg_test.go",
        "table_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = [
        "//vendor/golang.org/x/text/language:go_default_library",
        "//vendor/golang.org/x/text/unicode/norm:go_default_library",
    ],
)

go_library(
    name = "go_default_library",
    srcs = [
        "collate.go",
        "index.go",
        "option.go",
        "sort.go",
        "tables.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/golang.org/x/text/language:go_default_library",
        "//vendor/golang.org/x/text/unicode/norm:go_default_library",
    ],
)

go_test(
    name = "go_default_xtest",
    srcs = ["sort_test.go"],
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
    srcs = [
        ":package-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/collate/build:all-srcs",
    ],
    tags = ["automanaged"],
)
