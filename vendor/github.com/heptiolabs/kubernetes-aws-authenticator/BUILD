package(default_visibility = ["//visibility:public"])

licenses(["notice"])

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_binary",
    "go_library",
)

go_binary(
    name = "kubernetes-aws-authenticator",
    library = ":go_default_library",
    tags = ["automanaged"],
)

go_library(
    name = "go_default_library",
    srcs = ["main.go"],
    tags = ["automanaged"],
    deps = ["//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/cmd:go_default_library"],
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
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/cmd:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/pkg/config:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/pkg/server:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/pkg/token:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/PuerkitoBio/purell:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/PuerkitoBio/urlesc:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/aws/aws-sdk-go:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/emicklei/go-restful:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/fsnotify/fsnotify:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/go-ini/ini:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/go-openapi/jsonpointer:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/go-openapi/jsonreference:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/go-openapi/spec:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/go-openapi/swag:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/gogo/protobuf/proto:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/gogo/protobuf/sortkeys:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/golang/glog:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/google/gofuzz:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/hashicorp/hcl:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/inconshreveable/mousetrap:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/jmespath/go-jmespath:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/magiconair/properties:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/mailru/easyjson:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/mitchellh/mapstructure:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/pelletier/go-toml:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/sirupsen/logrus:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/spf13/afero:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/spf13/cast:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/spf13/cobra:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/spf13/jwalterweatherman:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/spf13/pflag:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/github.com/spf13/viper:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/crypto/ssh:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/net/http2:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/net/idna:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/net/lex/httplex:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/sys/unix:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/sys/windows:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/golang.org/x/text:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/gopkg.in/inf.v0:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/gopkg.in/yaml.v2:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/api/authentication/v1:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/api/authentication/v1beta1:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/api/resource:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/apis/meta/v1:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/conversion:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/fields:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/labels:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/runtime:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/selection:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/types:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/util/errors:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/util/intstr:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/util/net:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/util/runtime:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/util/sets:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/util/validation:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/util/wait:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/pkg/watch:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/apimachinery/third_party/forked/golang/reflect:all-srcs",
        "//vendor/github.com/heptiolabs/kubernetes-aws-authenticator/vendor/k8s.io/kube-openapi/pkg/common:all-srcs",
    ],
    tags = ["automanaged"],
)
