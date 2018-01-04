package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
    "go_test",
)

go_library(
    name = "go_default_library",
    srcs = [
        "compact.go",
        "print.go",
        "triegen.go",
    ],
    tags = ["automanaged"],
)

go_test(
    name = "go_default_xtest",
    srcs = [
        "data_test.go",
        "example_compact_test.go",
        "example_test.go",
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
