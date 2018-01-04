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
        "core_test.go",
        "ranges_test.go",
        "tables_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/text/unicode/norm:go_default_library"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "bidi.go",
        "bracket.go",
        "core.go",
        "prop.go",
        "tables.go",
        "trieval.go",
    ],
    tags = ["automanaged"],
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
