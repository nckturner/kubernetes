package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_library",
    "go_test",
)

go_test(
    name = "go_default_test",
    srcs = ["export_test.go"],
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = [
        "asm_linux_amd64.s",
        "bluetooth_linux.go",
        "constants.go",
        "dev_linux.go",
        "dirent.go",
        "endian_little.go",
        "env_unix.go",
        "env_unset.go",
        "file_unix.go",
        "flock.go",
        "pagesize_unix.go",
        "race0.go",
        "sockcmsg_linux.go",
        "sockcmsg_unix.go",
        "str.go",
        "syscall.go",
        "syscall_linux.go",
        "syscall_linux_amd64.go",
        "syscall_linux_amd64_gc.go",
        "syscall_unix.go",
        "syscall_unix_gc.go",
        "zerrors_linux_amd64.go",
        "zsyscall_linux_amd64.go",
        "zsysnum_linux_amd64.go",
        "ztypes_linux_amd64.go",
    ],
    tags = ["automanaged"],
)

go_test(
    name = "go_default_xtest",
    srcs = [
        "creds_test.go",
        "dev_linux_test.go",
        "mmap_unix_test.go",
        "syscall_linux_test.go",
        "syscall_test.go",
        "syscall_unix_test.go",
    ],
    tags = ["automanaged"],
    deps = ["//vendor/golang.org/x/sys/unix:go_default_library"],
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
