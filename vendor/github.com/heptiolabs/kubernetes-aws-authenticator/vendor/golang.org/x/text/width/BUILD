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
        "common_test.go",
        "runes_test.go",
        "tables_test.go",
        "transform_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/text/transform:go_default_library"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "kind_string.go",
        "tables.go",
        "transform.go",
        "trieval.go",
        "width.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/text/transform:go_default_library"],
)

go_test(
    name = "go_default_xtest",
    srcs = ["example_test.go"],
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/text/width:go_default_library"],
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
