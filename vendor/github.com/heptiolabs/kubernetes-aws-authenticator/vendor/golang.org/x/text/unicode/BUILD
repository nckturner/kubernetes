package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
)

go_library(
    name = "go_default_library",
    srcs = ["doc.go"],
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
    srcs = [
        ":package-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/unicode/bidi:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/unicode/cldr:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/unicode/norm:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/unicode/rangetable:all-srcs",
    ],
    tags = ["automanaged"],
)
