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
        "bench_test.go",
        "example_test.go",
        "purell_test.go",
        "urlnorm_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = ["purell.go"],
    tags = ["automanaged"],
    deps = [
        "//vendor/github.com/PuerkitoBio/urlesc:go_default_library",
        "//vendor/golang.org/x/net/idna:go_default_library",
        "//vendor/golang.org/x/text/unicode/norm:go_default_library",
        "//vendor/golang.org/x/text/width:go_default_library",
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
