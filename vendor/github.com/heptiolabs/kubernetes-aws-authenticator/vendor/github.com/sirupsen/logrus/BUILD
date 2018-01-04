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
        "alt_exit_test.go",
        "entry_test.go",
        "formatter_bench_test.go",
        "hook_test.go",
        "json_formatter_test.go",
        "logger_bench_test.go",
        "logrus_test.go",
        "text_formatter_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = ["//vendor/github.com/stretchr/testify/assert:go_default_library"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "alt_exit.go",
        "doc.go",
        "entry.go",
        "exported.go",
        "formatter.go",
        "hooks.go",
        "json_formatter.go",
        "logger.go",
        "logrus.go",
        "terminal_linux.go",
        "text_formatter.go",
        "writer.go",
    ],
    tags = ["automanaged"],
    deps = [
        "//vendor/golang.org/x/crypto/ssh/terminal:go_default_library",
        "//vendor/golang.org/x/sys/unix:go_default_library",
    ],
)

go_test(
    name = "go_default_xtest",
    srcs = [
        "example_basic_test.go",
        "example_hook_test.go",
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
