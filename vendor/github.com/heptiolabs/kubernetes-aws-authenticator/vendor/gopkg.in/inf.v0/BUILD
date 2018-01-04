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
        "benchmark_test.go",
        "dec_go1_2_test.go",
        "dec_internal_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "dec.go",
        "rounder.go",
    ],
    tags = ["automanaged"],
)

go_test(
    name = "go_default_xtest",
    srcs = [
        "dec_test.go",
        "example_test.go",
        "rounder_example_test.go",
        "rounder_test.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor/gopkg.in/inf.v0:go_default_library"],
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
