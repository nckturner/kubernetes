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
        "header_rules_test.go",
        "v4_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = [
        "//vendor/github.com/aws/aws-sdk-go/aws:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/credentials:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/request:go_default_library",
    ],
)

go_library(
    name = "go_default_library",
    srcs = [
        "header_rules.go",
        "options.go",
        "uri_path.go",
        "v4.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/github.com/aws/aws-sdk-go/aws:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/credentials:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/request:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/private/protocol/rest:go_default_library",
    ],
)

go_test(
    name = "go_default_xtest",
    srcs = [
        "functional_1_5_test.go",
        "functional_test.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/github.com/aws/aws-sdk-go/aws:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/signer/v4:go_default_library",
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
