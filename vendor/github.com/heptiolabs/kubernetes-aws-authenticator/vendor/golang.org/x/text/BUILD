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
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/collate:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/internal:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/language:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/secure:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/transform:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/unicode:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text/width:all-srcs",
    ],
    tags = ["automanaged"],
)
