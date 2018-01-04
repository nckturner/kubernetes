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
        "keysparsing_test.go",
        "lexer_test.go",
        "marshal_test.go",
        "parser_test.go",
        "position_test.go",
        "token_test.go",
        "toml_test.go",
        "tomltree_create_test.go",
        "tomltree_write_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = [
        "//vendor/github.com/davecgh/go-spew/spew:go_default_library",
        "//vendor/gopkg.in/yaml.v2:go_default_library",
    ],
)

go_library(
    name = "go_default_library",
    srcs = [
        "doc.go",
        "keysparsing.go",
        "lexer.go",
        "marshal.go",
        "parser.go",
        "position.go",
        "token.go",
        "toml.go",
        "tomltree_create.go",
        "tomltree_write.go",
    ],
    tags = ["automanaged"],
)

go_test(
    name = "go_default_xtest",
    srcs = ["doc_test.go"],
    tags = ["automanaged"],
    deps = ["//vendor/github.com/pelletier/go-toml:go_default_library"],
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
