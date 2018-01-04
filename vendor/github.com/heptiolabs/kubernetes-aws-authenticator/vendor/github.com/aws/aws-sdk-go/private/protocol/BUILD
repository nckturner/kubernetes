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
        "idempotency.go",
        "unmarshal.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor/github.com/aws/aws-sdk-go/aws/request:go_default_library"],
)

go_test(
    name = "go_default_xtest",
    srcs = [
        "idempotency_test.go",
        "protocol_test.go",
        "unmarshal_test.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/github.com/aws/aws-sdk-go/aws/client/metadata:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/aws/request:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/private/protocol:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/private/protocol/ec2query:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/private/protocol/jsonrpc:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/private/protocol/query:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/private/protocol/rest:go_default_library",
        "//vendor/github.com/aws/aws-sdk-go/private/protocol/restxml:go_default_library",
        "//vendor/github.com/stretchr/testify/assert:go_default_library",
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
    srcs = [
        ":package-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/aws/aws-sdk-go/private/protocol/query:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/aws/aws-sdk-go/private/protocol/rest:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/aws/aws-sdk-go/private/protocol/xml/xmlutil:all-srcs",
    ],
    tags = ["automanaged"],
)
