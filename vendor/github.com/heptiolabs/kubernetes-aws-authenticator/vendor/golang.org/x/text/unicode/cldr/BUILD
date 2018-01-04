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
        "cldr_test.go",
        "collate_test.go",
        "data_test.go",
        "resolve_test.go",
        "slice_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "base.go",
        "cldr.go",
        "collate.go",
        "decode.go",
        "resolve.go",
        "slice.go",
        "xml.go",
    ],
    tags = ["automanaged"],
)

go_test(
    name = "go_default_xtest",
    srcs = ["examples_test.go"],
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
