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
        "bash_completions_test.go",
        "cobra_test.go",
        "command_test.go",
        "zsh_completions_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = ["//vendor/github.com/spf13/pflag:go_default_library"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "args.go",
        "bash_completions.go",
        "cobra.go",
        "command.go",
        "command_notwin.go",
        "zsh_completions.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor/github.com/spf13/pflag:go_default_library"],
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
