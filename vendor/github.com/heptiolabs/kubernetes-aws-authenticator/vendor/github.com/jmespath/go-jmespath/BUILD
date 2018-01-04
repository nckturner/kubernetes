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
        "api_test.go",
        "compliance_test.go",
        "interpreter_test.go",
        "lexer_test.go",
        "parser_test.go",
        "util_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = ["//vendor/github.com/stretchr/testify/assert:go_default_library"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "api.go",
        "astnodetype_string.go",
        "functions.go",
        "interpreter.go",
        "lexer.go",
        "parser.go",
        "toktype_string.go",
        "util.go",
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
