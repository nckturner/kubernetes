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
        "fsnotify_test.go",
        "inotify_poller_test.go",
        "inotify_test.go",
        "integration_test.go",
    ],
    library = ":go_default_library",
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/sys/unix:go_default_library"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "fsnotify.go",
        "inotify.go",
        "inotify_poller.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/sys/unix:go_default_library"],
)

go_test(
    name = "go_default_xtest",
    srcs = ["example_test.go"],
    tags = ["automanaged"],
    deps = ["//vendor/github.com/fsnotify/fsnotify:go_default_library"],
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
