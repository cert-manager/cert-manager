# Copyright 2020 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file is automatically updated by hack/update-deps.sh

load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_repositories():
    go_repository(
        name = "co_honnef_go_tools",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "honnef.co/go/tools",
        sum = "h1:UoveltGrhghAA7ePc+e+QYDHXrBps2PqFZiHkGR/xK8=",
        version = "v0.0.1-2020.1.4",
    )

    go_repository(
        name = "com_github_agnivade_levenshtein",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/agnivade/levenshtein",
        sum = "h1:3oJU7J3FGFmyhn8KHjmVaZCN5hxTr7GxgRue+sxIXdQ=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_ahmetb_gen_crd_api_reference_docs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ahmetb/gen-crd-api-reference-docs",
        sum = "h1:+XfOU14S4bGuwyvCijJwhhBIjYN+YXS18jrCY2EzJaY=",
        version = "v0.3.0",
    )

    go_repository(
        name = "com_github_akamai_akamaiopen_edgegrid_golang",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/akamai/AkamaiOPEN-edgegrid-golang",
        sum = "h1:bLzehmpyCwQiqCE1Qe9Ny6fbFqs7hPlmo9vKv2orUxs=",
        version = "v1.1.1",
    )

    go_repository(
        name = "com_github_alecthomas_template",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/alecthomas/template",
        sum = "h1:JYp7IbQjafoB+tBA3gMyHYHrpOtNuDiK/uB5uXxq5wM=",
        version = "v0.0.0-20190718012654-fb15b899a751",
    )

    go_repository(
        name = "com_github_alecthomas_units",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/alecthomas/units",
        sum = "h1:UQZhZ2O0vMHr2cI+DC1Mbh0TJxzA3RcLoMsFw+aXw7E=",
        version = "v0.0.0-20190924025748-f65c72e2690d",
    )
    go_repository(
        name = "com_github_alexflint_go_filemutex",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/alexflint/go-filemutex",
        sum = "h1:AMzIhMUqU3jMrZiTuW0zkYeKlKDAFD+DG20IoO421/Y=",
        version = "v0.0.0-20171022225611-72bdc8eae2ae",
    )

    go_repository(
        name = "com_github_andreyvit_diff",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/andreyvit/diff",
        sum = "h1:bvNMNQO63//z+xNgfBlViaCIJKLlCJ6/fmUseuG0wVQ=",
        version = "v0.0.0-20170406064948-c7f18ee00883",
    )

    go_repository(
        name = "com_github_antihax_optional",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/antihax/optional",
        sum = "h1:xK2lYat7ZLaVVcIuj82J8kIro4V6kDe0AUDFboUCwcg=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_antlr_antlr4_runtime_go_antlr",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/antlr/antlr4/runtime/Go/antlr",
        sum = "h1:GCzyKMDDjSGnlpl3clrdAK7I1AaVoaiKDOYkUzChZzg=",
        version = "v0.0.0-20210826220005-b48c857c3a0e",
    )

    go_repository(
        name = "com_github_armon_circbuf",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/armon/circbuf",
        sum = "h1:QEF07wC0T1rKkctt1RINW/+RMTVmiwxETico2l3gxJA=",
        version = "v0.0.0-20150827004946-bbbad097214e",
    )

    go_repository(
        name = "com_github_armon_consul_api",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/armon/consul-api",
        sum = "h1:G1bPvciwNyF7IUmKXNt9Ak3m6u9DE1rF+RmtIkBpVdA=",
        version = "v0.0.0-20180202201655-eb2c6b5be1b6",
    )

    go_repository(
        name = "com_github_armon_go_metrics",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/armon/go-metrics",
        sum = "h1:FR+drcQStOe+32sYyJYyZ7FIdgoGGBnwLl+flodp8Uo=",
        version = "v0.3.10",
    )

    go_repository(
        name = "com_github_armon_go_radix",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/armon/go-radix",
        sum = "h1:F4z6KzEeeQIMeLFa97iZU6vupzoecKdU5TX24SNppXI=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_asaskevich_govalidator",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/asaskevich/govalidator",
        sum = "h1:4daAzAu0S6Vi7/lbWECcX0j45yZReDZ56BQsrVBOEEY=",
        version = "v0.0.0-20200428143746-21a406dcc535",
    )

    go_repository(
        name = "com_github_aws_aws_sdk_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/aws/aws-sdk-go",
        sum = "h1:QsZ49jnpwPDqh8UoJbr15ItN5oltCyo+sUj/Fl8558w=",
        version = "v1.40.21",
    )

    go_repository(
        name = "com_github_azure_azure_sdk_for_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/azure-sdk-for-go",
        sum = "h1:DmhwMrUIvpeoTDiWRDtNHqelNUd3Og8JCkrLHQK795c=",
        version = "v56.3.0+incompatible",
    )

    go_repository(
        name = "com_github_azure_go_ansiterm",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-ansiterm",
        sum = "h1:UQHMgLO+TxOElx5B5HZ4hJQsoJ/PvUvKRhJHDQXO8P8=",
        version = "v0.0.0-20210617225240-d185dfc1b5a1",
    )

    go_repository(
        name = "com_github_azure_go_autorest",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest",
        sum = "h1:V5VMDjClD3GiElqLWO7mz2MxNAK/vTfRHdAubSIPRgs=",
        version = "v14.2.0+incompatible",
    )

    go_repository(
        name = "com_github_azure_go_autorest_autorest",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest/autorest",
        sum = "h1:s8H1PbCZSqg/DH7JMlOz6YMig6htWLNPsjDdlLqCx3M=",
        version = "v0.11.20",
    )

    go_repository(
        name = "com_github_azure_go_autorest_autorest_adal",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest/autorest/adal",
        sum = "h1:X+p2GF0GWyOiSmqohIaEeuNFNDY4I4EOlVuUQvFdWMk=",
        version = "v0.9.15",
    )

    go_repository(
        name = "com_github_azure_go_autorest_autorest_date",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest/autorest/date",
        sum = "h1:7gUk1U5M/CQbp9WoqinNzJar+8KY+LPI6wiWrP/myHw=",
        version = "v0.3.0",
    )

    go_repository(
        name = "com_github_azure_go_autorest_autorest_mocks",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest/autorest/mocks",
        sum = "h1:K0laFcLE6VLTOwNgSxaGbUcLPuGXlNkbVvq4cW4nIHk=",
        version = "v0.4.1",
    )

    go_repository(
        name = "com_github_azure_go_autorest_autorest_to",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest/autorest/to",
        sum = "h1:oXVqrxakqqV1UZdSazDOPOLvOIz+XA683u8EctwboHk=",
        version = "v0.4.0",
    )

    go_repository(
        name = "com_github_azure_go_autorest_autorest_validation",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest/autorest/validation",
        sum = "h1:AgyqjAd94fwNAoTjl/WQXg4VvFeRFpO+UhNyRXqF1ac=",
        version = "v0.3.1",
    )

    go_repository(
        name = "com_github_azure_go_autorest_logger",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest/logger",
        sum = "h1:IG7i4p/mDa2Ce4TRyAO8IHnVhAVF3RFU+ZtXWSmf4Tg=",
        version = "v0.2.1",
    )

    go_repository(
        name = "com_github_azure_go_autorest_tracing",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Azure/go-autorest/tracing",
        sum = "h1:TYi4+3m5t6K48TGI9AUdb+IzbnSxvnvUMfuitfgcfuo=",
        version = "v0.6.0",
    )

    go_repository(
        name = "com_github_benbjohnson_clock",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/benbjohnson/clock",
        sum = "h1:Q92kusRqC1XV2MjkWETPvjJVqKetz1OzxZB7mHJLju8=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_beorn7_perks",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/beorn7/perks",
        sum = "h1:VlbKKnNfV8bJzeqoa4cOKqO6bYr3WgKZxO8Z16+hsOM=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_bgentry_speakeasy",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bgentry/speakeasy",
        sum = "h1:ByYyxL9InA1OWqxJqqp2A5pYHUrCiAL6K3J+LKSsQkY=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_bitly_go_simplejson",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bitly/go-simplejson",
        sum = "h1:6IH+V8/tVMab511d5bn4M7EwGXZf9Hj6i2xSwkNEM+Y=",
        version = "v0.5.0",
    )
    go_repository(
        name = "com_github_bits_and_blooms_bitset",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bits-and-blooms/bitset",
        sum = "h1:Kn4yilvwNtMACtf1eYDlG8H77R07mZSPbMjLyS07ChA=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_bketelsen_crypt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bketelsen/crypt",
        sum = "h1:w/jqZtC9YD4DS/Vp9GhWfWcCpuAL58oTnLoI8vE9YHU=",
        version = "v0.0.4",
    )

    go_repository(
        name = "com_github_blang_semver",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/blang/semver",
        sum = "h1:cQNTCjp13qL8KC3Nbxr/y2Bqb63oX6wdnnjpJbkM4JQ=",
        version = "v3.5.1+incompatible",
    )

    go_repository(
        name = "com_github_bmizerany_assert",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bmizerany/assert",
        sum = "h1:DDGfHa7BWjL4YnC6+E63dPcxHo2sUxDIu8g3QgEJdRY=",
        version = "v0.0.0-20160611221934-b7ed37b82869",
    )

    go_repository(
        name = "com_github_bshuster_repo_logrus_logstash_hook",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bshuster-repo/logrus-logstash-hook",
        sum = "h1:e+C0SB5R1pu//O4MQ3f9cFuPGoOVeF2fE4Og9otCc70=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_buger_jsonparser",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/buger/jsonparser",
        sum = "h1:y853v6rXx+zefEcjET3JuKAqvhj+FKflQijjeaSv2iA=",
        version = "v0.0.0-20180808090653-f4dd9f5a6b44",
    )

    go_repository(
        name = "com_github_bugsnag_bugsnag_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bugsnag/bugsnag-go",
        sum = "h1:rFt+Y/IK1aEZkEHchZRSq9OQbsSzIT/OrI8YFFmRIng=",
        version = "v0.0.0-20141110184014-b1d153021fcd",
    )

    go_repository(
        name = "com_github_bugsnag_osext",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bugsnag/osext",
        sum = "h1:otBG+dV+YK+Soembjv71DPz3uX/V/6MMlSyD9JBQ6kQ=",
        version = "v0.0.0-20130617224835-0dd3f918b21b",
    )

    go_repository(
        name = "com_github_bugsnag_panicwrap",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/bugsnag/panicwrap",
        sum = "h1:nvj0OLI3YqYXer/kZD8Ri1aaunCxIEsOst1BVJswV0o=",
        version = "v0.0.0-20151223152923-e2c28503fcd0",
    )

    go_repository(
        name = "com_github_burntsushi_toml",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/BurntSushi/toml",
        sum = "h1:GaI7EiDXDRfa8VshkTj7Fym7ha+y8/XxIgD2okUIjLw=",
        version = "v0.4.1",
    )

    go_repository(
        name = "com_github_burntsushi_xgb",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/BurntSushi/xgb",
        sum = "h1:1BDTz0u9nC3//pOCMdNH+CiXJVYJh5UQNCOBG7jbELc=",
        version = "v0.0.0-20160522181843-27f122750802",
    )

    go_repository(
        name = "com_github_cenkalti_backoff_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cenkalti/backoff/v3",
        sum = "h1:ske+9nBpD9qZsTBoF41nW5L+AIuFBKMeze18XQ3eG1c=",
        version = "v3.0.0",
    )
    go_repository(
        name = "com_github_cenkalti_backoff_v4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cenkalti/backoff/v4",
        sum = "h1:G2HAfAmvm/GcKan2oOQpBXOd2tT2G57ZnZGWa1PxPBQ=",
        version = "v4.1.1",
    )

    go_repository(
        name = "com_github_census_instrumentation_opencensus_proto",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/census-instrumentation/opencensus-proto",
        sum = "h1:t/LhUZLVitR1Ow2YOnduCsavhwFUklBMoGVYUCqmCqk=",
        version = "v0.3.0",
    )

    go_repository(
        name = "com_github_certifi_gocertifi",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/certifi/gocertifi",
        sum = "h1:uH66TXeswKn5PW5zdZ39xEwfS9an067BirqA+P4QaLI=",
        version = "v0.0.0-20200922220541-2c3bb06c6054",
    )

    go_repository(
        name = "com_github_cespare_xxhash",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cespare/xxhash",
        sum = "h1:a6HrQnmkObjyL+Gs60czilIUGqrzKutQD6XZog3p+ko=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_cespare_xxhash_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cespare/xxhash/v2",
        sum = "h1:YRXhKfTDauu4ajMg1TPgFO5jnlC2HCbmLXMcTG5cbYE=",
        version = "v2.1.2",
    )

    go_repository(
        name = "com_github_chai2010_gettext_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/chai2010/gettext-go",
        sum = "h1:7aWHqerlJ41y6FOsEUvknqgXnGmJyJSbjhAWq5pO4F8=",
        version = "v0.0.0-20160711120539-c6fed771bfd5",
    )
    go_repository(
        name = "com_github_checkpoint_restore_go_criu_v4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/checkpoint-restore/go-criu/v4",
        sum = "h1:WW2B2uxx9KWF6bGlHqhm8Okiafwwx7Y2kcpn8lCpjgo=",
        version = "v4.1.0",
    )
    go_repository(
        name = "com_github_checkpoint_restore_go_criu_v5",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/checkpoint-restore/go-criu/v5",
        sum = "h1:TW8f/UvntYoVDMN1K2HlT82qH1rb0sOjpGw3m6Ym+i4=",
        version = "v5.0.0",
    )

    go_repository(
        name = "com_github_chzyer_logex",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/chzyer/logex",
        sum = "h1:Swpa1K6QvQznwJRcfTfQJmTE72DqScAa40E+fbHEXEE=",
        version = "v1.1.10",
    )

    go_repository(
        name = "com_github_chzyer_readline",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/chzyer/readline",
        sum = "h1:fY5BOSpyZCqRo5OhCuC+XN+r/bBCmeuuJtjz+bCNIf8=",
        version = "v0.0.0-20180603132655-2972be24d48e",
    )

    go_repository(
        name = "com_github_chzyer_test",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/chzyer/test",
        sum = "h1:q763qf9huN11kDQavWsoZXJNW3xEE4JJyHa5Q25/sd8=",
        version = "v0.0.0-20180213035817-a1ea475d72b1",
    )

    go_repository(
        name = "com_github_cilium_ebpf",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cilium/ebpf",
        sum = "h1:iHsfF/t4aW4heW2YKfeHrVPGdtYTL4C4KocpM8KTSnI=",
        version = "v0.6.2",
    )

    go_repository(
        name = "com_github_circonus_labs_circonus_gometrics",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/circonus-labs/circonus-gometrics",
        sum = "h1:C29Ae4G5GtYyYMm1aztcyj/J5ckgJm2zwdDajFbx1NY=",
        version = "v2.3.1+incompatible",
    )

    go_repository(
        name = "com_github_circonus_labs_circonusllhist",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/circonus-labs/circonusllhist",
        sum = "h1:TJH+oke8D16535+jHExHj4nQvzlZrj7ug5D7I/orNUA=",
        version = "v0.1.3",
    )

    go_repository(
        name = "com_github_client9_misspell",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/client9/misspell",
        sum = "h1:ta993UF76GwbvJcIo3Y68y/M3WxlpEHPWIGDkJYwzJI=",
        version = "v0.3.4",
    )

    go_repository(
        name = "com_github_cloudflare_cloudflare_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cloudflare/cloudflare-go",
        sum = "h1:y2a6KwYHTFxhw+8PLhz0q5hpTGj6Un3W1pbpQLhzFaE=",
        version = "v0.20.0",
    )

    go_repository(
        name = "com_github_cncf_udpa_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cncf/udpa/go",
        sum = "h1:hzAQntlaYRkVSFEfj9OTWlVV1H155FMD8BTKktLv0QI=",
        version = "v0.0.0-20210930031921-04548b0d99d4",
    )

    go_repository(
        name = "com_github_cncf_xds_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cncf/xds/go",
        sum = "h1:KwaoQzs/WeUxxJqiJsZ4euOly1Az/IgZXXSxlD/UBNk=",
        version = "v0.0.0-20211130200136-a8f946100490",
    )

    go_repository(
        name = "com_github_cockroachdb_datadriven",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cockroachdb/datadriven",
        sum = "h1:xD/lrqdvwsc+O2bjSSi3YqY73Ke3LAiSCx49aCesA0E=",
        version = "v0.0.0-20200714090401-bf6692d28da5",
    )

    go_repository(
        name = "com_github_cockroachdb_errors",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cockroachdb/errors",
        sum = "h1:Lap807SXTH5tri2TivECb/4abUkMZC9zRoLarvcKDqs=",
        version = "v1.2.4",
    )

    go_repository(
        name = "com_github_cockroachdb_logtags",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cockroachdb/logtags",
        sum = "h1:o/kfcElHqOiXqcou5a3rIlMc7oJbMQkeLk0VQJ7zgqY=",
        version = "v0.0.0-20190617123548-eb05cc24525f",
    )

    go_repository(
        name = "com_github_containerd_aufs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/aufs",
        sum = "h1:2oeJiwX5HstO7shSrPZjrohJZLzK36wvpdmzDRkL/LY=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_containerd_btrfs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/btrfs",
        sum = "h1:osn1exbzdub9L5SouXO5swW4ea/xVdJZ3wokxN5GrnA=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_containerd_cgroups",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/cgroups",
        sum = "h1:mZBclaSgNDfPWtfhj2xJY28LZ9nYIgzB0pwSURPl6JM=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_containerd_console",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/console",
        sum = "h1:Pi6D+aZXM+oUw1czuKgH5IJ+y0jhYcwBJfx5/Ghn9dE=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_containerd_containerd",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/containerd",
        sum = "h1:3cQ2uRVCkJVcx5VombsE7105Gl9Wrl7ORAO3+4+ogf4=",
        version = "v1.5.10",
    )

    go_repository(
        name = "com_github_containerd_continuity",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/continuity",
        sum = "h1:UFRRY5JemiAhPZrr/uE0n8fMTLcZsUvySPr1+D7pgr8=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_containerd_fifo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/fifo",
        sum = "h1:6PirWBr9/L7GDamKr+XM0IeUFXu5mf3M/BPpH9gaLBU=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_containerd_go_cni",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/go-cni",
        sum = "h1:YbJAhpTevL2v6u8JC1NhCYRwf+3Vzxcc5vGnYoJ7VeE=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_containerd_go_runc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/go-runc",
        sum = "h1:oU+lLv1ULm5taqgV/CJivypVODI4SUz1znWjv3nNYS0=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_containerd_imgcrypt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/imgcrypt",
        sum = "h1:LBwiTfoUsdiEGAR1TpvxE+Gzt7469oVu87iR3mv3Byc=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_containerd_nri",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/nri",
        sum = "h1:6QioHRlThlKh2RkRTR4kIT3PKAcrLo3gIWnjkM4dQmQ=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_containerd_stargz_snapshotter_estargz",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/stargz-snapshotter/estargz",
        sum = "h1:5e7heayhB7CcgdTkqfZqrNaNv15gABwr3Q2jBTbLlt4=",
        version = "v0.4.1",
    )

    go_repository(
        name = "com_github_containerd_ttrpc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/ttrpc",
        sum = "h1:GbtyLRxb0gOLR0TYQWt3O6B0NvT8tMdorEHqIQo/lWI=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_containerd_typeurl",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/typeurl",
        sum = "h1:Chlt8zIieDbzQFzXzAeBEF92KhExuE4p9p92/QmY7aY=",
        version = "v1.0.2",
    )
    go_repository(
        name = "com_github_containerd_zfs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containerd/zfs",
        sum = "h1:cXLJbx+4Jj7rNsTiqVfm6i+RNLx6FFA2fMmDlEf+Wm8=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_containernetworking_cni",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containernetworking/cni",
        sum = "h1:7zpDnQ3T3s4ucOuJ/ZCLrYBxzkg0AELFfII3Epo9TmI=",
        version = "v0.8.1",
    )
    go_repository(
        name = "com_github_containernetworking_plugins",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containernetworking/plugins",
        sum = "h1:FD1tADPls2EEi3flPc2OegIY1M9pUa9r2Quag7HMLV8=",
        version = "v0.9.1",
    )
    go_repository(
        name = "com_github_containers_ocicrypt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/containers/ocicrypt",
        sum = "h1:prL8l9w3ntVqXvNH1CiNn5ENjcCnr38JqpSyvKKB4GI=",
        version = "v1.1.1",
    )

    go_repository(
        name = "com_github_coreos_bbolt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/bbolt",
        sum = "h1:wZwiHHUieZCquLkDL0B8UhzreNWsPHooDAG3q34zk0s=",
        version = "v1.3.2",
    )

    go_repository(
        name = "com_github_coreos_etcd",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/etcd",
        sum = "h1:8F3hqu9fGYLBifCmRCJsicFqDx/D68Rt3q1JMazcgBQ=",
        version = "v3.3.13+incompatible",
    )

    go_repository(
        name = "com_github_coreos_go_etcd",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/go-etcd",
        sum = "h1:bXhRBIXoTm9BYHS3gE0TtQuyNZyeEMux2sDi4oo5YOo=",
        version = "v2.0.0+incompatible",
    )
    go_repository(
        name = "com_github_coreos_go_iptables",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/go-iptables",
        sum = "h1:mw6SAibtHKZcNzAsOxjoHIG0gy5YFHhypWSSNc6EjbQ=",
        version = "v0.5.0",
    )

    go_repository(
        name = "com_github_coreos_go_oidc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/go-oidc",
        sum = "h1:sdJrfw8akMnCuUlaZU3tE/uYXFgfqom8DBE9so9EBsM=",
        version = "v2.1.0+incompatible",
    )

    go_repository(
        name = "com_github_coreos_go_semver",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/go-semver",
        sum = "h1:wkHLiw0WNATZnSG7epLsujiMCgPAc9xhjJ4tgnAxmfM=",
        version = "v0.3.0",
    )

    go_repository(
        name = "com_github_coreos_go_systemd",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/go-systemd",
        sum = "h1:Wf6HqHfScWJN9/ZjdUKyjop4mf3Qdd+1TvvltAvM3m8=",
        version = "v0.0.0-20190321100706-95778dfbb74e",
    )

    go_repository(
        name = "com_github_coreos_go_systemd_v22",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/go-systemd/v22",
        sum = "h1:D9/bQk5vlXQFZ6Kwuu6zaiXJ9oTPe68++AzAJc1DzSI=",
        version = "v22.3.2",
    )

    go_repository(
        name = "com_github_coreos_pkg",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/coreos/pkg",
        sum = "h1:lBNOc5arjvs8E5mO2tbpBpLoyyu8B6e44T7hJy6potg=",
        version = "v0.0.0-20180928190104-399ea9e2e55f",
    )

    go_repository(
        name = "com_github_cpu_goacmedns",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cpu/goacmedns",
        sum = "h1:DM3H2NiN2oam7QljgGY5ygy4yDXhK5Z4JUnqaugs2C4=",
        version = "v0.1.1",
    )

    go_repository(
        name = "com_github_cpuguy83_go_md2man",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cpuguy83/go-md2man",
        sum = "h1:BSKMNlYxDvnunlTymqtgONjNnaRV1sTpcovwwjF22jk=",
        version = "v1.0.10",
    )

    go_repository(
        name = "com_github_cpuguy83_go_md2man_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cpuguy83/go-md2man/v2",
        sum = "h1:r/myEWzV9lfsM1tFLgDyu0atFtJ1fXn261LKYj/3DxU=",
        version = "v2.0.1",
    )

    go_repository(
        name = "com_github_creack_pty",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/creack/pty",
        sum = "h1:07n33Z8lZxZ2qwegKbObQohDhXDQxiMMz1NOUGYlesw=",
        version = "v1.1.11",
    )

    go_repository(
        name = "com_github_cyphar_filepath_securejoin",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/cyphar/filepath-securejoin",
        sum = "h1:YX6ebbZCZP7VkM3scTTokDgBL2TY741X51MTk3ycuNI=",
        version = "v0.2.3",
    )
    go_repository(
        name = "com_github_d2g_dhcp4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/d2g/dhcp4",
        sum = "h1:Xo2rK1pzOm0jO6abTPIQwbAmqBIOj132otexc1mmzFc=",
        version = "v0.0.0-20170904100407-a1d1b6c41b1c",
    )
    go_repository(
        name = "com_github_d2g_dhcp4client",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/d2g/dhcp4client",
        sum = "h1:suYBsYZIkSlUMEz4TAYCczKf62IA2UWC+O8+KtdOhCo=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_d2g_dhcp4server",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/d2g/dhcp4server",
        sum = "h1:+CpLbZIeUn94m02LdEKPcgErLJ347NUwxPKs5u8ieiY=",
        version = "v0.0.0-20181031114812-7d4a0a7f59a5",
    )
    go_repository(
        name = "com_github_d2g_hardwareaddr",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/d2g/hardwareaddr",
        sum = "h1:itqmmf1PFpC4n5JW+j4BU7X4MTfVurhYRTjODoPb2Y8=",
        version = "v0.0.0-20190221164911-e7d9fbe030e4",
    )
    go_repository(
        name = "com_github_danieljoos_wincred",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/danieljoos/wincred",
        sum = "h1:3RNcEpBg4IhIChZdFRSdlQt1QjCp1sMAPIrOnm7Yf8g=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_data_dog_go_sqlmock",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/DATA-DOG/go-sqlmock",
        sum = "h1:Shsta01QNfFxHCfpW6YH2STWB0MudeXXEWMr20OEh60=",
        version = "v1.5.0",
    )

    go_repository(
        name = "com_github_datadog_datadog_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/DataDog/datadog-go",
        sum = "h1:qSG2N4FghB1He/r2mFrWKCaL7dXCilEuNEeAn20fdD4=",
        version = "v3.2.0+incompatible",
    )

    go_repository(
        name = "com_github_davecgh_go_spew",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/davecgh/go-spew",
        sum = "h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=",
        version = "v1.1.1",
    )

    go_repository(
        name = "com_github_daviddengcn_go_colortext",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/daviddengcn/go-colortext",
        sum = "h1:uVsMphB1eRx7xB1njzL3fuMdWRN8HtVzoUOItHMwv5c=",
        version = "v0.0.0-20160507010035-511bcaf42ccd",
    )

    go_repository(
        name = "com_github_denisenkom_go_mssqldb",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/denisenkom/go-mssqldb",
        sum = "h1:RSohk2RsiZqLZ0zCjtfn3S4Gp4exhpBWHyQ7D0yGjAk=",
        version = "v0.9.0",
    )

    go_repository(
        name = "com_github_denverdino_aliyungo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/denverdino/aliyungo",
        sum = "h1:p6poVbjHDkKa+wtC8frBMwQtT3BmqGYBjzMwJ63tuR4=",
        version = "v0.0.0-20190125010748-a747050bb1ba",
    )

    go_repository(
        name = "com_github_dgrijalva_jwt_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/dgrijalva/jwt-go",
        sum = "h1:7qlOGliEKZXTDg6OTjfoBKDXWrumCAMpl/TFQ4/5kLM=",
        version = "v3.2.0+incompatible",
    )

    go_repository(
        name = "com_github_dgryski_go_sip13",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/dgryski/go-sip13",
        sum = "h1:RMLoZVzv4GliuWafOuPuQDKSm1SJph7uCRnnS61JAn4=",
        version = "v0.0.0-20181026042036-e10d5fee7954",
    )

    go_repository(
        name = "com_github_digitalocean_godo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/digitalocean/godo",
        sum = "h1:3SywGJBC18HaYtPQF+T36jYzXBi+a6eIMonSjDll7TA=",
        version = "v1.65.0",
    )
    go_repository(
        name = "com_github_distribution_distribution_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/distribution/distribution/v3",
        sum = "h1:DBZ2sN7CK6dgvHVpQsQj4sRMCbWTmd17l+5SUCjnQSY=",
        version = "v3.0.0-20211118083504-a29a3c99a684",
    )

    go_repository(
        name = "com_github_dnaeon_go_vcr",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/dnaeon/go-vcr",
        sum = "h1:r8L/HqC0Hje5AXMu1ooW8oyQyOFv4GxqpL0nRP7SLLY=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_docker_cli",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/cli",
        sum = "h1:tXU1ezXcruZQRrMP8RN2z9N91h+6egZTS1gsPsKantc=",
        version = "v20.10.11+incompatible",
    )

    go_repository(
        name = "com_github_docker_distribution",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/distribution",
        sum = "h1:Q50tZOPR6T/hjNsyc9g8/syEs6bk8XXApsHjKukMl68=",
        version = "v2.8.1+incompatible",
    )

    go_repository(
        name = "com_github_docker_docker",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/docker",
        sum = "h1:CEeNmFM0QZIsJCZKMkZx0ZcahTiewkrgiwfYD+dfl1U=",
        version = "v20.10.12+incompatible",
    )

    go_repository(
        name = "com_github_docker_docker_credential_helpers",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/docker-credential-helpers",
        sum = "h1:axCks+yV+2MR3/kZhAmy07yC56WZ2Pwu/fKWtKuZB0o=",
        version = "v0.6.4",
    )

    go_repository(
        name = "com_github_docker_go_connections",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/go-connections",
        sum = "h1:El9xVISelRB7BuFusrZozjnkIM5YnzCViNKohAFqRJQ=",
        version = "v0.4.0",
    )
    go_repository(
        name = "com_github_docker_go_events",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/go-events",
        sum = "h1:+pKlWGMw7gf6bQ+oDZB4KHQFypsfjYlq/C4rfL7D3g8=",
        version = "v0.0.0-20190806004212-e31b211e4f1c",
    )

    go_repository(
        name = "com_github_docker_go_metrics",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/go-metrics",
        sum = "h1:AgB/0SvBxihN0X8OR4SjsblXkbMvalQ8cjmtKQ2rQV8=",
        version = "v0.0.1",
    )

    go_repository(
        name = "com_github_docker_go_units",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/go-units",
        sum = "h1:3uh0PgVws3nIA0Q+MwDC8yjEPf9zjRfZZWXZYDct3Tw=",
        version = "v0.4.0",
    )

    go_repository(
        name = "com_github_docker_libtrust",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/libtrust",
        sum = "h1:ZClxb8laGDf5arXfYcAtECDFgAgHklGI8CxgjHnXKJ4=",
        version = "v0.0.0-20150114040149-fa567046d9b1",
    )

    go_repository(
        name = "com_github_docker_spdystream",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docker/spdystream",
        sum = "h1:cenwrSVm+Z7QLSV/BsnenAOcDXdX4cMv4wP0B/5QbPg=",
        version = "v0.0.0-20160310174837-449fdfce4d96",
    )

    go_repository(
        name = "com_github_docopt_docopt_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/docopt/docopt-go",
        sum = "h1:bWDMxwH3px2JBh6AyO7hdCn/PkvCZXii8TGj7sbtEbQ=",
        version = "v0.0.0-20180111231733-ee0de3bc6815",
    )

    go_repository(
        name = "com_github_dustin_go_humanize",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/dustin/go-humanize",
        sum = "h1:VSnTsYCnlFHaM2/igO1h6X3HA71jcobQuxemgkq4zYo=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_elazarl_goproxy",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/elazarl/goproxy",
        sum = "h1:yUdfgN0XgIJw7foRItutHYUIhlcKzcSf5vDpdhQAKTc=",
        version = "v0.0.0-20180725130230-947c36da3153",
    )

    go_repository(
        name = "com_github_emicklei_go_restful",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/emicklei/go-restful",
        sum = "h1:spTtZBk5DYEvbxMVutUuTyh1Ao2r4iyvLdACqsl/Ljk=",
        version = "v2.9.5+incompatible",
    )

    go_repository(
        name = "com_github_envoyproxy_go_control_plane",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/envoyproxy/go-control-plane",
        sum = "h1:cgDRLG7bs59Zd+apAWuzLQL95obVYAymNJek76W3mgw=",
        version = "v0.10.1",
    )

    go_repository(
        name = "com_github_envoyproxy_protoc_gen_validate",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/envoyproxy/protoc-gen-validate",
        sum = "h1:JiO+kJTpmYGjEodY7O1Zk8oZcNz1+f30UtwtXoFUPzE=",
        version = "v0.6.2",
    )

    go_repository(
        name = "com_github_evanphx_json_patch",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/evanphx/json-patch",
        sum = "h1:4onqiflcdA9EOZ4RxV643DvftH5pOlLGNtQ5lPWQu84=",
        version = "v4.12.0+incompatible",
    )

    go_repository(
        name = "com_github_exponent_io_jsonpath",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/exponent-io/jsonpath",
        sum = "h1:105gxyaGwCFad8crR9dcMQWvV9Hvulu6hwUh4tWPJnM=",
        version = "v0.0.0-20151013193312-d6023ce2651d",
    )

    go_repository(
        name = "com_github_fatih_camelcase",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/fatih/camelcase",
        sum = "h1:hxNvNX/xYBp0ovncs8WyWZrOrpBNub/JfaMvbURyft8=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_fatih_color",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/fatih/color",
        sum = "h1:8LOYc1KYPPmyKMuN8QV2DNRWNbLo6LZ0iLs8+mlH53w=",
        version = "v1.13.0",
    )

    go_repository(
        name = "com_github_fatih_structs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/fatih/structs",
        sum = "h1:Q7juDM0QtcnhCpeyLGQKyg4TOIghuNXrkL32pHAUMxo=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_felixge_httpsnoop",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/felixge/httpsnoop",
        sum = "h1:lvB5Jl89CsZtGIWuTcDM1E/vkVs49/Ml7JJe07l8SPQ=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_form3tech_oss_jwt_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/form3tech-oss/jwt-go",
        sum = "h1:7ZaBxOI7TMoYBfyA3cQHErNNyAWIKUMIwqxEtgHOs5c=",
        version = "v3.2.3+incompatible",
    )

    go_repository(
        name = "com_github_frankban_quicktest",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/frankban/quicktest",
        sum = "h1:8sXhOn0uLys67V8EsXLc6eszDs8VXWxL3iRvebPhedY=",
        version = "v1.11.3",
    )

    go_repository(
        name = "com_github_fsnotify_fsnotify",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/fsnotify/fsnotify",
        sum = "h1:mZcQUHVQUQWoPXXtuf9yuEXKudkV2sx1E06UadKWpgI=",
        version = "v1.5.1",
    )
    go_repository(
        name = "com_github_fullsailor_pkcs7",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/fullsailor/pkcs7",
        sum = "h1:RDBNVkRviHZtvDvId8XSGPu3rmpmSe+wKRcEWNgsfWU=",
        version = "v0.0.0-20190404230743-d7302db945fa",
    )

    go_repository(
        name = "com_github_fvbommel_sortorder",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/fvbommel/sortorder",
        sum = "h1:dSnXLt4mJYH25uDDGa3biZNQsozaUWDSWeKJ0qqFfzE=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_garyburd_redigo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/garyburd/redigo",
        sum = "h1:LofdAjjjqCSXMwLGgOgnE+rdPuvX9DxCqaHwKy7i/ko=",
        version = "v0.0.0-20150301180006-535138d7bcd7",
    )
    go_repository(
        name = "com_github_getkin_kin_openapi",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/getkin/kin-openapi",
        sum = "h1:j77zg3Ec+k+r+GA3d8hBoXpAc6KX9TbBPrwQGBIy2sY=",
        version = "v0.76.0",
    )

    go_repository(
        name = "com_github_getsentry_raven_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/getsentry/raven-go",
        sum = "h1:no+xWJRb5ZI7eE8TWgIq1jLulQiIoLG0IfYxv5JYMGs=",
        version = "v0.2.0",
    )

    go_repository(
        name = "com_github_ghodss_yaml",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ghodss/yaml",
        sum = "h1:wQHKEahhL6wmXdzwWG11gIVCkOv05bNOh+Rxn0yngAk=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_globalsign_mgo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/globalsign/mgo",
        sum = "h1:DujepqpGd1hyOd7aW59XpK7Qymp8iy83xq74fLr21is=",
        version = "v0.0.0-20181015135952-eeefdecb41b8",
    )

    go_repository(
        name = "com_github_go_asn1_ber_asn1_ber",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-asn1-ber/asn1-ber",
        sum = "h1:gvPdv/Hr++TRFCl0UbPFHC54P9N9jgsRPnmnr419Uck=",
        version = "v1.3.1",
    )

    go_repository(
        name = "com_github_go_errors_errors",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-errors/errors",
        sum = "h1:LUHzmkK3GUKUrL/1gfBUxAHzcev3apQlezX/+O7ma6w=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_go_gl_glfw",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-gl/glfw",
        sum = "h1:QbL/5oDUmRBzO9/Z7Seo6zf912W/a6Sr4Eu0G/3Jho0=",
        version = "v0.0.0-20190409004039-e6da0acd62b1",
    )

    go_repository(
        name = "com_github_go_gl_glfw_v3_3_glfw",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-gl/glfw/v3.3/glfw",
        sum = "h1:WtGNWLvXpe6ZudgnXrq0barxBImvnnJoMEhXAzcbM0I=",
        version = "v0.0.0-20200222043503-6f7a984d4dc4",
    )

    go_repository(
        name = "com_github_go_ini_ini",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-ini/ini",
        sum = "h1:Mujh4R/dH6YL8bxuISne3xX2+qcQ9p0IxKAP6ExWoUo=",
        version = "v1.25.4",
    )

    go_repository(
        name = "com_github_go_kit_kit",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-kit/kit",
        sum = "h1:wDJmvq38kDhkVxi50ni9ykkdUr1PKgqKOoi01fa0Mdk=",
        version = "v0.9.0",
    )

    go_repository(
        name = "com_github_go_kit_log",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-kit/log",
        sum = "h1:DGJh0Sm43HbOeYDNnVZFl8BvcYVvjD5bqYJvp0REbwQ=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_go_ldap_ldap_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-ldap/ldap/v3",
        sum = "h1:7WsKqasmPThNvdl0Q5GPpbTDD/ZD98CfuawrMIuh7qQ=",
        version = "v3.1.10",
    )

    go_repository(
        name = "com_github_go_logfmt_logfmt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-logfmt/logfmt",
        sum = "h1:TrB8swr/68K7m9CcGut2g3UOihhbcbiMAYiuTXdEih4=",
        version = "v0.5.0",
    )

    go_repository(
        name = "com_github_go_logr_logr",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-logr/logr",
        sum = "h1:QK40JKJyMdUDz+h+xvCsru/bJhvG0UxvePV0ufL/AcE=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_go_logr_zapr",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-logr/zapr",
        sum = "h1:n4JnPI1T3Qq1SFEi/F8rwLrZERp2bso19PJZDB9dayk=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_go_openapi_analysis",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/analysis",
        sum = "h1:8b2ZgKfKIUTVQpTb77MoRDIMEIwvDVw40o3aOXdfYzI=",
        version = "v0.19.5",
    )

    go_repository(
        name = "com_github_go_openapi_errors",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/errors",
        sum = "h1:a2kIyV3w+OS3S97zxUndRVD46+FhGOUBDFY7nmu4CsY=",
        version = "v0.19.2",
    )

    go_repository(
        name = "com_github_go_openapi_jsonpointer",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/jsonpointer",
        sum = "h1:gZr+CIYByUqjcgeLXnQu2gHYQC9o73G2XUeOFYEICuY=",
        version = "v0.19.5",
    )

    go_repository(
        name = "com_github_go_openapi_jsonreference",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/jsonreference",
        sum = "h1:1WJP/wi4OjB4iV8KVbH73rQaoialJrqv8gitZLxGLtM=",
        version = "v0.19.5",
    )

    go_repository(
        name = "com_github_go_openapi_loads",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/loads",
        sum = "h1:5I4CCSqoWzT+82bBkNIvmLc0UOsoKKQ4Fz+3VxOB7SY=",
        version = "v0.19.4",
    )

    go_repository(
        name = "com_github_go_openapi_runtime",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/runtime",
        sum = "h1:csnOgcgAiuGoM/Po7PEpKDoNulCcF3FGbSnbHfxgjMI=",
        version = "v0.19.4",
    )

    go_repository(
        name = "com_github_go_openapi_spec",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/spec",
        sum = "h1:Xm0Ao53uqnk9QE/LlYV5DEU09UAgpliA85QoT9LzqPw=",
        version = "v0.19.5",
    )

    go_repository(
        name = "com_github_go_openapi_strfmt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/strfmt",
        sum = "h1:eRfyY5SkaNJCAwmmMcADjY31ow9+N7MCLW7oRkbsINA=",
        version = "v0.19.3",
    )

    go_repository(
        name = "com_github_go_openapi_swag",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/swag",
        sum = "h1:gm3vOOXfiuw5i9p5N9xJvfjvuofpyvLA9Wr6QfK5Fng=",
        version = "v0.19.14",
    )

    go_repository(
        name = "com_github_go_openapi_validate",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-openapi/validate",
        sum = "h1:QhCBKRYqZR+SKo4gl1lPhPahope8/RLt6EVgY8X80w0=",
        version = "v0.19.5",
    )

    go_repository(
        name = "com_github_go_sql_driver_mysql",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-sql-driver/mysql",
        sum = "h1:ozyZYNQW3x3HtqT1jira07DN2PArx2v7/mN66gGcHOs=",
        version = "v1.5.0",
    )

    go_repository(
        name = "com_github_go_stack_stack",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-stack/stack",
        sum = "h1:5SgMzNM5HxrEjV0ww2lTmX6E2Izsfxas4+YHWRs3Lsk=",
        version = "v1.8.0",
    )

    go_repository(
        name = "com_github_go_task_slim_sprig",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-task/slim-sprig",
        sum = "h1:p104kn46Q8WdvHunIJ9dAyjPVtrBPhSr3KT2yUst43I=",
        version = "v0.0.0-20210107165309-348f09dbbbc0",
    )

    go_repository(
        name = "com_github_go_test_deep",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/go-test/deep",
        sum = "h1:onZX1rnHT3Wv6cqNgYyFOOlgVKJrksuCMCRvJStbMYw=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_gobuffalo_flect",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gobuffalo/flect",
        sum = "h1:f/ZukRnSNA/DUpSNDadko7Qc0PhGvsew35p/2tu+CRY=",
        version = "v0.2.3",
    )

    go_repository(
        name = "com_github_gobuffalo_logger",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gobuffalo/logger",
        sum = "h1:YaXOTHNPCvkqqA7w05A4v0k2tCdpr+sgFlgINbQ6gqc=",
        version = "v1.0.3",
    )

    go_repository(
        name = "com_github_gobuffalo_packd",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gobuffalo/packd",
        sum = "h1:6ERZvJHfe24rfFmA9OaoKBdC7+c9sydrytMg8SdFGBM=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_gobuffalo_packr_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gobuffalo/packr/v2",
        sum = "h1:tkQpju6i3EtMXJ9uoF5GT6kB+LMTimDWD8Xvbz6zDVA=",
        version = "v2.8.1",
    )

    go_repository(
        name = "com_github_gobwas_glob",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gobwas/glob",
        sum = "h1:A4xDbljILXROh+kObIiy5kIaPYD8e96x1tgBhUI5J+Y=",
        version = "v0.2.3",
    )

    go_repository(
        name = "com_github_godbus_dbus",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/godbus/dbus",
        sum = "h1:BWhy2j3IXJhjCbC68FptL43tDKIq8FladmaTs3Xs7Z8=",
        version = "v0.0.0-20190422162347-ade71ed3457e",
    )

    go_repository(
        name = "com_github_godbus_dbus_v5",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/godbus/dbus/v5",
        sum = "h1:9349emZab16e7zQvpmsbtjc18ykshndd8y2PG3sgJbA=",
        version = "v5.0.4",
    )

    go_repository(
        name = "com_github_godror_godror",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/godror/godror",
        sum = "h1:uxGAD7UdnNGjX5gf4NnEIGw0JAPTIFiqAyRBZTPKwXs=",
        version = "v0.24.2",
    )

    go_repository(
        name = "com_github_gofrs_flock",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gofrs/flock",
        sum = "h1:+gYjHKf32LDeiEEFhQaotPbLuUXjY5ZqxKgXy7n59aw=",
        version = "v0.8.1",
    )
    go_repository(
        name = "com_github_gofrs_uuid",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gofrs/uuid",
        sum = "h1:1SD/1F5pU8p29ybwgQSwpQk+mwdRrXCYuPhW6m+TnJw=",
        version = "v4.0.0+incompatible",
    )

    go_repository(
        name = "com_github_gogo_googleapis",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gogo/googleapis",
        sum = "h1:zgVt4UpGxcqVOw97aRGxT4svlcmdK35fynLNctY32zI=",
        version = "v1.4.0",
    )

    go_repository(
        name = "com_github_gogo_protobuf",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gogo/protobuf",
        sum = "h1:Ov1cvc58UF3b5XjBnZv7+opcTcQFZebYjWzi34vdm4Q=",
        version = "v1.3.2",
    )

    go_repository(
        name = "com_github_golang_glog",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/golang/glog",
        sum = "h1:nfP3RFugxnNRyKgeWd4oI1nYvXpxrx8ck8ZrcizshdQ=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_golang_groupcache",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/golang/groupcache",
        sum = "h1:oI5xCqsCo564l8iNU+DwB5epxmsaqB+rhGL0m5jtYqE=",
        version = "v0.0.0-20210331224755-41bb18bfe9da",
    )
    go_repository(
        name = "com_github_golang_jwt_jwt_v4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/golang-jwt/jwt/v4",
        sum = "h1:RAqyYixv1p7uEnocuy8P1nru5wprCh/MH2BIlW5z5/o=",
        version = "v4.0.0",
    )

    go_repository(
        name = "com_github_golang_mock",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/golang/mock",
        sum = "h1:ErTB+efbowRARo13NNdxyJji2egdxLGQhRaY+DUumQc=",
        version = "v1.6.0",
    )

    go_repository(
        name = "com_github_golang_protobuf",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/golang/protobuf",
        sum = "h1:ROPKBNFfQgOUMifHyP+KYbvpjbdoFNs+aK7DXlji0Tw=",
        version = "v1.5.2",
    )

    go_repository(
        name = "com_github_golang_snappy",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/golang/snappy",
        sum = "h1:fHPg5GQYlCeLIPB9BZqMVR5nR9A+IM5zcgeTdjMYmLA=",
        version = "v0.0.3",
    )

    go_repository(
        name = "com_github_golang_sql_civil",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/golang-sql/civil",
        sum = "h1:lXe2qZdvpiX5WZkZR4hgp4KJVfY3nMkvmwbVkpv1rVY=",
        version = "v0.0.0-20190719163853-cb61b32ac6fe",
    )

    go_repository(
        name = "com_github_golangplus_testing",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/golangplus/testing",
        sum = "h1:KhcknUwkWHKZPbFy2P7jH5LKJ3La+0ZeknkkmrSgqb0=",
        version = "v0.0.0-20180327235837-af21d9c3145e",
    )
    go_repository(
        name = "com_github_gomodule_redigo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gomodule/redigo",
        sum = "h1:H5XSIre1MB5NbPYFp+i1NBbb5qN1W8Y8YAQoAYbkm8k=",
        version = "v1.8.2",
    )

    go_repository(
        name = "com_github_google_btree",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/btree",
        sum = "h1:gK4Kx5IaGY9CD5sPJ36FHiBJ6ZXl0kilRiiCj+jdYp4=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_google_cel_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/cel-go",
        sum = "h1:u1hg7lcZ/XWw2d3aV1jFS30ijQQ6q0/h1C2ZBeBD1gY=",
        version = "v0.9.0",
    )
    go_repository(
        name = "com_github_google_cel_spec",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/cel-spec",
        sum = "h1:xuthJSiJGoSzq+lVEBIW1MTpaaZXknMCYC4WzVAWOsE=",
        version = "v0.6.0",
    )

    go_repository(
        name = "com_github_google_go_cmp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/go-cmp",
        sum = "h1:BKbKCqvP6I+rmFHt06ZmyQtvB8xAkWdhFyr0ZUNZcxQ=",
        version = "v0.5.6",
    )
    go_repository(
        name = "com_github_google_go_containerregistry",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/go-containerregistry",
        sum = "h1:/+mFTs4AlwsJ/mJe8NDtKb7BxLtbZFpcn8vDsneEkwQ=",
        version = "v0.5.1",
    )

    go_repository(
        name = "com_github_google_go_querystring",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/go-querystring",
        sum = "h1:Xkwi/a1rcvNg1PPYe5vI8GbeBY/jrVuDX5ASuANWTrk=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_google_gofuzz",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/gofuzz",
        sum = "h1:xRy4A+RhZaiKjJ1bPfwQ8sedCA+YS2YcCHW6ec7JMi0=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_google_martian",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/martian",
        sum = "h1:/CP5g8u/VJHijgedC/Legn3BAbAaWPgecwXBIDzw5no=",
        version = "v2.1.0+incompatible",
    )

    go_repository(
        name = "com_github_google_martian_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/martian/v3",
        sum = "h1:d8MncMlErDFTwQGBK1xhv026j9kqhvw1Qv9IbWT1VLQ=",
        version = "v3.2.1",
    )

    go_repository(
        name = "com_github_google_pprof",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/pprof",
        sum = "h1:K6RDEckDVWvDI9JAJYCmNdQXq6neHJOYx3V6jnqNEec=",
        version = "v0.0.0-20210720184732-4bb14d4b1be1",
    )

    go_repository(
        name = "com_github_google_renameio",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/renameio",
        sum = "h1:GOZbcHa3HfsPKPlmyPyN2KEohoMXOhdMbHrvbpl2QaA=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_google_shlex",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/shlex",
        sum = "h1:El6M4kTTCOh6aBiKaUGG7oYTSPP8MxqL4YI3kZKwcP4=",
        version = "v0.0.0-20191202100458-e7afc7fbc510",
    )

    go_repository(
        name = "com_github_google_uuid",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/google/uuid",
        sum = "h1:t6JiXgmwXMjEs8VusXIJk2BXHsn+wx8BZdTaoZ5fu7I=",
        version = "v1.3.0",
    )

    go_repository(
        name = "com_github_googleapis_gax_go_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/googleapis/gax-go/v2",
        sum = "h1:dp3bWCh+PPO1zjRRiCSczJav13sBvG4UhNyVTa1KqdU=",
        version = "v2.1.1",
    )

    go_repository(
        name = "com_github_googleapis_gnostic",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/googleapis/gnostic",
        sum = "h1:9fHAtK0uDfpveeqqo1hkEZJcFvYXAiCN3UutL8F9xHw=",
        version = "v0.5.5",
    )

    go_repository(
        name = "com_github_gophercloud_gophercloud",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gophercloud/gophercloud",
        sum = "h1:P/nh25+rzXouhytV2pUHBb65fnds26Ghl8/391+sT5o=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_gopherjs_gopherjs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gopherjs/gopherjs",
        sum = "h1:EGx4pi6eqNxGaHF6qqu48+N2wcFQ5qg5FXgOdqsJ5d8=",
        version = "v0.0.0-20181017120253-0766667cb4d1",
    )

    go_repository(
        name = "com_github_gorilla_handlers",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gorilla/handlers",
        sum = "h1:9lRY6j8DEeeBT10CvO9hGW0gmky0BprnvDI5vfhUHH4=",
        version = "v1.5.1",
    )

    go_repository(
        name = "com_github_gorilla_mux",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gorilla/mux",
        sum = "h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=",
        version = "v1.8.0",
    )

    go_repository(
        name = "com_github_gorilla_websocket",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gorilla/websocket",
        sum = "h1:+/TMaTYc4QFitKJxsQ7Yye35DkWvkdLcvGKqM+x0Ufc=",
        version = "v1.4.2",
    )

    go_repository(
        name = "com_github_gosuri_uitable",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gosuri/uitable",
        sum = "h1:IG2xLKRvErL3uhY6e1BylFzG+aJiwQviDDTfOKeKTpY=",
        version = "v0.0.4",
    )

    go_repository(
        name = "com_github_gregjones_httpcache",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/gregjones/httpcache",
        sum = "h1:pdN6V1QBWetyv/0+wjACpqVH+eVULgEjkurDLq3goeM=",
        version = "v0.0.0-20180305231024-9cad4c3443a7",
    )

    go_repository(
        name = "com_github_grpc_ecosystem_go_grpc_middleware",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/grpc-ecosystem/go-grpc-middleware",
        sum = "h1:+9834+KizmvFV7pXQGSXQTsaWhq2GjuNUt0aUU0YBYw=",
        version = "v1.3.0",
    )

    go_repository(
        name = "com_github_grpc_ecosystem_go_grpc_prometheus",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/grpc-ecosystem/go-grpc-prometheus",
        sum = "h1:Ovs26xHkKqVztRpIrF/92BcuyuQ/YW4NSIpoGtfXNho=",
        version = "v1.2.0",
    )

    # This repo does not work when using the default gazelle-generated
    # go_repository definition. The fix below was inspired by the examples
    # in https://github.com/bazelbuild/bazel-gazelle/issues/788
    # and https://github.com/bazelbuild/bazel-gazelle/issues/980
    go_repository(
        name = "com_github_grpc_ecosystem_grpc_gateway",
        build_file_generation = "off",
        build_file_proto_mode = "disable",
        build_naming_convention = "go_default_library",
        importpath = "github.com/grpc-ecosystem/grpc-gateway",
        sum = "h1:gmcG1KaJ57LophUzW0Hy8NmPhnMZb4M0+kPpLofRdBo=",
        version = "v1.16.0",
    )

    go_repository(
        name = "com_github_h2non_parth",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/h2non/parth",
        sum = "h1:2VTzZjLZBgl62/EtslCrtky5vbi9dd7HrQPQIx6wqiw=",
        version = "v0.0.0-20190131123155-b4df798d6542",
    )

    go_repository(
        name = "com_github_hashicorp_consul_api",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/consul/api",
        sum = "h1:Hw/G8TtRvOElqxVIhBzXciiSTbapq8hZ2XKZsXk5ZCE=",
        version = "v1.11.0",
    )

    go_repository(
        name = "com_github_hashicorp_consul_sdk",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/consul/sdk",
        sum = "h1:OJtKBtEjboEZvG6AOUdh4Z1Zbyu0WcxQ0qatRrZHTVU=",
        version = "v0.8.0",
    )

    go_repository(
        name = "com_github_hashicorp_errwrap",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/errwrap",
        sum = "h1:hLrqtEDnRye3+sgx6z4qVLNuviH3MR5aQ0ykNJa/UYA=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_hashicorp_go_cleanhttp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-cleanhttp",
        sum = "h1:035FKYIWjmULyFRBKPs8TBQoi0x6d9G4xc9neXJWAZQ=",
        version = "v0.5.2",
    )

    go_repository(
        name = "com_github_hashicorp_go_hclog",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-hclog",
        sum = "h1:bkKf0BeBXcSYa7f5Fyi9gMuQ8gNsxeiNpZjR6VxNZeo=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_hashicorp_go_immutable_radix",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-immutable-radix",
        sum = "h1:DKHmCUm2hRBK510BaiZlwvpD40f8bJFeZnpfm2KLowc=",
        version = "v1.3.1",
    )

    go_repository(
        name = "com_github_hashicorp_go_kms_wrapping_entropy",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-kms-wrapping/entropy",
        sum = "h1:xuTi5ZwjimfpvpL09jDE71smCBRpnF5xfo871BSX4gs=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_hashicorp_go_msgpack",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-msgpack",
        sum = "h1:zKjpN5BK/P5lMYrLmBHdBULWbJ0XpYR+7NGzqkZzoD4=",
        version = "v0.5.3",
    )

    go_repository(
        name = "com_github_hashicorp_go_multierror",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-multierror",
        sum = "h1:B9UzwGQJehnUY1yNrnwREHc3fGbC2xefo8g4TbElacI=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_hashicorp_go_net",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go.net",
        sum = "h1:sNCoNyDEvN1xa+X0baata4RdcpKwcMS6DH+xwfqPgjw=",
        version = "v0.0.1",
    )

    go_repository(
        name = "com_github_hashicorp_go_plugin",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-plugin",
        sum = "h1:4OtAfUGbnKC6yS48p0CtMX2oFYtzFZVv6rok3cRWgnE=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_hashicorp_go_retryablehttp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-retryablehttp",
        sum = "h1:HJunrbHTDDbBb/ay4kxa1n+dLmttUlnP3V9oNE4hmsM=",
        version = "v0.6.6",
    )

    go_repository(
        name = "com_github_hashicorp_go_rootcerts",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-rootcerts",
        sum = "h1:jzhAVGtqPKbwpyCPELlgNWhE1znq+qwJtW5Oi2viEzc=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_hashicorp_go_sockaddr",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-sockaddr",
        sum = "h1:ztczhD1jLxIRjVejw8gFomI1BQZOe2WoVOu0SyteCQc=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_hashicorp_go_syslog",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-syslog",
        sum = "h1:KaodqZuhUoZereWVIYmpUgZysurB1kBLX2j0MwMrUAE=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_hashicorp_go_uuid",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-uuid",
        sum = "h1:cfejS+Tpcp13yd5nYHWDI6qVCny6wyX2Mt5SGur2IGE=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_hashicorp_go_version",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/go-version",
        sum = "h1:3vNe/fWF5CBgRIguda1meWhsZHy3m8gCJ5wx+dIzX/E=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_hashicorp_golang_lru",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/golang-lru",
        sum = "h1:YDjusn29QI/Das2iO9M0BHnIbxPeyuCHsjMW+lJfyTc=",
        version = "v0.5.4",
    )

    go_repository(
        name = "com_github_hashicorp_hcl",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/hcl",
        sum = "h1:0Anlzjpi4vEasTeNFn2mLJgTSwt0+6sfsiTG8qcWGx4=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_hashicorp_logutils",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/logutils",
        sum = "h1:dLEQVugN8vlakKOUE3ihGLTZJRB4j+M2cdTm/ORI65Y=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_hashicorp_mdns",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/mdns",
        sum = "h1:sY0CMhFmjIPDMlTB+HfymFHCaYLhgifZ0QhjaYKD/UQ=",
        version = "v1.0.4",
    )

    go_repository(
        name = "com_github_hashicorp_memberlist",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/memberlist",
        sum = "h1:8+567mCcFDnS5ADl7lrpxPMWiFCElyUEeW0gtj34fMA=",
        version = "v0.3.0",
    )

    go_repository(
        name = "com_github_hashicorp_serf",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/serf",
        sum = "h1:uuEX1kLR6aoda1TBttmJQKDLZE1Ob7KN0NPdE7EtCDc=",
        version = "v0.9.6",
    )

    go_repository(
        name = "com_github_hashicorp_vault_api",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/vault/api",
        sum = "h1:907ld+Z9cALyvbZK2qUX9cLwvSaEQsMVQB3x2KE8+AI=",
        version = "v1.1.1",
    )

    go_repository(
        name = "com_github_hashicorp_vault_sdk",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/vault/sdk",
        sum = "h1:S4O6Iv/dyKlE9AUTXGa7VOvZmsCvg36toPKgV4f2P4M=",
        version = "v0.2.1",
    )

    go_repository(
        name = "com_github_hashicorp_yamux",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hashicorp/yamux",
        sum = "h1:b5rjCoWHc7eqmAS4/qyk21ZsHyb6Mxv/jykxvNTkU4M=",
        version = "v0.0.0-20180604194846-3520598351bb",
    )

    go_repository(
        name = "com_github_howeyc_gopass",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/howeyc/gopass",
        sum = "h1:kQWxfPIHVLbgLzphqk3QUflDy9QdksZR4ygR807bpy0=",
        version = "v0.0.0-20170109162249-bf9dde6d0d2c",
    )

    go_repository(
        name = "com_github_hpcloud_tail",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/hpcloud/tail",
        sum = "h1:nfCOvKYfkgYP8hkirhJocXT2+zOD8yUNjXaWfTlyFKI=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_huandu_xstrings",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/huandu/xstrings",
        sum = "h1:L18LIDzqlW6xN2rEkpdV8+oL/IXWJ1APd+vsdYy4Wdw=",
        version = "v1.3.2",
    )
    go_repository(
        name = "com_github_iancoleman_strcase",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/iancoleman/strcase",
        sum = "h1:05I4QRnGpI0m37iZQRuskXh+w77mr6Z41lwQzuHLwW0=",
        version = "v0.2.0",
    )

    go_repository(
        name = "com_github_ianlancetaylor_demangle",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ianlancetaylor/demangle",
        sum = "h1:mV02weKRL81bEnm8A0HT1/CAelMQDBuQIfLw8n+d6xI=",
        version = "v0.0.0-20200824232613-28f6c0f3b639",
    )

    go_repository(
        name = "com_github_imdario_mergo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/imdario/mergo",
        sum = "h1:b6R2BslTbIEToALKP7LxUvijTsNI9TAe80pLWN2g/HU=",
        version = "v0.3.12",
    )

    go_repository(
        name = "com_github_inconshreveable_mousetrap",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/inconshreveable/mousetrap",
        sum = "h1:Z8tu5sraLXCXIcARxBp/8cbvlwVa7Z1NHg9XEKhtSvM=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_j_keck_arping",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/j-keck/arping",
        sum = "h1:742eGXur0715JMq73aD95/FU0XpVKXqNuTnEfXsLOYQ=",
        version = "v0.0.0-20160618110441-2cf9dc699c56",
    )

    go_repository(
        name = "com_github_jessevdk_go_flags",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/jessevdk/go-flags",
        sum = "h1:4IU2WS7AumrZ/40jfhf4QVDMsQwqA7VEHozFRrGARJA=",
        version = "v1.4.0",
    )

    go_repository(
        name = "com_github_jmespath_go_jmespath",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/jmespath/go-jmespath",
        sum = "h1:BEgLn5cpjn8UN1mAw4NjwDrS35OdebyEtFe+9YPoQUg=",
        version = "v0.4.0",
    )

    go_repository(
        name = "com_github_jmespath_go_jmespath_internal_testify",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/jmespath/go-jmespath/internal/testify",
        sum = "h1:shLQSRRSCCPj3f2gpwzGwWFoC7ycTf1rcQZHOlsJ6N8=",
        version = "v1.5.1",
    )

    go_repository(
        name = "com_github_jmoiron_sqlx",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/jmoiron/sqlx",
        sum = "h1:wv+0IJZfL5z0uZoUjlpKgHkgaFSYD+r9CfrXjEXsO7w=",
        version = "v1.3.4",
    )
    go_repository(
        name = "com_github_joefitzgerald_rainbow_reporter",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/joefitzgerald/rainbow-reporter",
        sum = "h1:AuMG652zjdzI0YCCnXAqATtRBpGXMcAnrajcaTrSeuo=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_jonboulle_clockwork",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/jonboulle/clockwork",
        sum = "h1:UOGuzwb1PwsrDAObMuhUnj0p5ULPj8V/xJ7Kx9qUBdQ=",
        version = "v0.2.2",
    )

    go_repository(
        name = "com_github_josharian_intern",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/josharian/intern",
        sum = "h1:vlS4z54oSdjm0bgjRigI+G1HpF+tI+9rE5LLzOg8HmY=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_jpillora_backoff",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/jpillora/backoff",
        sum = "h1:uvFg412JmmHBHw7iwprIxkPMI+sGQ4kzOWsMeHnm2EA=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_json_iterator_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/json-iterator/go",
        sum = "h1:PV8peI4a0ysnczrg+LtxykD8LfKY9ML6u2jnxaEnrnM=",
        version = "v1.1.12",
    )

    go_repository(
        name = "com_github_jstemmer_go_junit_report",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/jstemmer/go-junit-report",
        sum = "h1:6QPYqodiu3GuPL+7mfx+NwDdp2eTkp9IfEUpgAwUN0o=",
        version = "v0.9.1",
    )

    go_repository(
        name = "com_github_jtolds_gls",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/jtolds/gls",
        sum = "h1:xdiiI2gbIgH/gLH7ADydsJ1uDOEzR8yvV7C0MuV77Wo=",
        version = "v4.20.0+incompatible",
    )

    go_repository(
        name = "com_github_julienschmidt_httprouter",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/julienschmidt/httprouter",
        sum = "h1:U0609e9tgbseu3rBINet9P48AI/D3oJs4dN7jwJOQ1U=",
        version = "v1.3.0",
    )
    go_repository(
        name = "com_github_karrick_godirwalk",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/karrick/godirwalk",
        sum = "h1:7+rWAZPn9zuRxaIqqT8Ohs2Q2Ac0msBqwRdxNCr2VVs=",
        version = "v1.15.8",
    )

    go_repository(
        name = "com_github_kisielk_errcheck",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/kisielk/errcheck",
        sum = "h1:e8esj/e4R+SAOwFwN+n3zr0nYeCyeweozKfO23MvHzY=",
        version = "v1.5.0",
    )

    go_repository(
        name = "com_github_kisielk_gotool",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/kisielk/gotool",
        sum = "h1:AV2c/EiW3KqPNT9ZKl07ehoAGi4C5/01Cfbblndcapg=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_klauspost_compress",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/klauspost/compress",
        sum = "h1:hLQYb23E8/fO+1u53d02A97a8UnsddcvYzq4ERRU4ds=",
        version = "v1.14.1",
    )

    go_repository(
        name = "com_github_konsorten_go_windows_terminal_sequences",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/konsorten/go-windows-terminal-sequences",
        sum = "h1:CE8S1cTafDpPvMhIxNJKvHsGVBgn1xWYf1NbHQhywc8=",
        version = "v1.0.3",
    )
    go_repository(
        name = "com_github_kortschak_utter",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/kortschak/utter",
        sum = "h1:AJVccwLrdrikvkH0aI5JKlzZIORLpfMeGBQ5tHfIXis=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_kr_fs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/kr/fs",
        sum = "h1:Jskdu9ieNAYnjxsi0LbQp1ulIKZV1LAFgK1tWhpZgl8=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_kr_logfmt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/kr/logfmt",
        sum = "h1:T+h1c/A9Gawja4Y9mFVWj2vyii2bbUNDw3kt9VxK2EY=",
        version = "v0.0.0-20140226030751-b84e30acd515",
    )

    go_repository(
        name = "com_github_kr_pretty",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/kr/pretty",
        sum = "h1:WgNl7dwNpEZ6jJ9k1snq4pZsg7DOEN8hP9Xw0Tsjwk0=",
        version = "v0.3.0",
    )

    go_repository(
        name = "com_github_kr_pty",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/kr/pty",
        sum = "h1:hyz3dwM5QLc1Rfoz4FuWJQG5BN7tc6K1MndAUnGpQr4=",
        version = "v1.1.5",
    )

    go_repository(
        name = "com_github_kr_text",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/kr/text",
        sum = "h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=",
        version = "v0.2.0",
    )

    go_repository(
        name = "com_github_lann_builder",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/lann/builder",
        sum = "h1:SOEGU9fKiNWd/HOJuq6+3iTQz8KNCLtVX6idSoTLdUw=",
        version = "v0.0.0-20180802200727-47ae307949d0",
    )

    go_repository(
        name = "com_github_lann_ps",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/lann/ps",
        sum = "h1:P6pPBnrTSX3DEVR4fDembhRWSsG5rVo6hYhAB/ADZrk=",
        version = "v0.0.0-20150810152359-62de8c46ede0",
    )

    go_repository(
        name = "com_github_lib_pq",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/lib/pq",
        sum = "h1:SO9z7FRPzA03QhHKJrH5BXA6HU1rS4V2nIVrrNC1iYk=",
        version = "v1.10.4",
    )

    go_repository(
        name = "com_github_liggitt_tabwriter",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/liggitt/tabwriter",
        sum = "h1:9TO3cAIGXtEhnIaL+V+BEER86oLrvS+kWobKpbJuye0=",
        version = "v0.0.0-20181228230101-89fcab3d43de",
    )
    go_repository(
        name = "com_github_linuxkit_virtsock",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/linuxkit/virtsock",
        sum = "h1:jUp75lepDg0phMUJBCmvaeFDldD2N3S1lBuPwUTszio=",
        version = "v0.0.0-20201010232012-f8cee7dfc7a3",
    )

    go_repository(
        name = "com_github_lithammer_dedent",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/lithammer/dedent",
        sum = "h1:VNzHMVCBNG1j0fh3OrsFRkVUwStdDArbgBWoPAffktY=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_lyft_protoc_gen_star",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/lyft/protoc-gen-star",
        sum = "h1:zSGLzsUew8RT+ZKPHc3jnf8XLaVyHzTcAFBzHtCNR20=",
        version = "v0.5.3",
    )

    go_repository(
        name = "com_github_magiconair_properties",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/magiconair/properties",
        sum = "h1:b6kJs+EmPFMYGkow9GiUyCyOvIwYetYJ3fSaWak/Gls=",
        version = "v1.8.5",
    )

    go_repository(
        name = "com_github_mailru_easyjson",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mailru/easyjson",
        sum = "h1:8yTIVnZgCoiM1TgqoeTl+LfU5Jg6/xL3QhGQnimLYnA=",
        version = "v0.7.6",
    )

    go_repository(
        name = "com_github_makenowjust_heredoc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/MakeNowJust/heredoc",
        sum = "h1:sjQovDkwrZp8u+gxLtPgKGjk5hCxuy2hrRejBTA9xFU=",
        version = "v0.0.0-20170808103936-bb23615498cd",
    )
    go_repository(
        name = "com_github_markbates_errx",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/markbates/errx",
        sum = "h1:QDFeR+UP95dO12JgW+tgi2UVfo0V8YBHiUIOaeBPiEI=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_markbates_oncer",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/markbates/oncer",
        sum = "h1:E83IaVAHygyndzPimgUYJjbshhDTALZyXxvk9FOlQRY=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_markbates_safe",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/markbates/safe",
        sum = "h1:yjZkbvRM6IzKj9tlu/zMJLS0n/V351OZWRnF3QfaUxI=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_marstr_guid",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/marstr/guid",
        sum = "h1:/M4H/1G4avsieL6BbUwCOBzulmoeKVP5ux/3mQNnbyI=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_masterminds_goutils",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Masterminds/goutils",
        sum = "h1:5nUrii3FMTL5diU80unEVvNevw1nH4+ZV4DSLVJLSYI=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_masterminds_semver",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Masterminds/semver",
        sum = "h1:H65muMkzWKEuNDnfl9d70GUjFniHKHRbFPGBuZ3QEww=",
        version = "v1.5.0",
    )

    go_repository(
        name = "com_github_masterminds_semver_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Masterminds/semver/v3",
        sum = "h1:hLg3sBzpNErnxhQtUy/mmLR2I9foDujNK030IGemrRc=",
        version = "v3.1.1",
    )
    go_repository(
        name = "com_github_masterminds_sprig",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Masterminds/sprig",
        sum = "h1:z4yfnGrZ7netVz+0EDJ0Wi+5VZCSYp4Z0m2dk6cEM60=",
        version = "v2.22.0+incompatible",
    )

    go_repository(
        name = "com_github_masterminds_sprig_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Masterminds/sprig/v3",
        sum = "h1:17jRggJu518dr3QaafizSXOjKYp94wKfABxUmyxvxX8=",
        version = "v3.2.2",
    )

    go_repository(
        name = "com_github_masterminds_squirrel",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Masterminds/squirrel",
        sum = "h1:UiOEi2ZX4RCSkpiNDQN5kro/XIBpSRk9iTqdIRPzUXE=",
        version = "v1.5.2",
    )

    go_repository(
        name = "com_github_masterminds_vcs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Masterminds/vcs",
        sum = "h1:NL3G1X7/7xduQtA2sJLpVpfHTNBALVNSjob6KEjPXNQ=",
        version = "v1.13.1",
    )

    go_repository(
        name = "com_github_mattn_go_colorable",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mattn/go-colorable",
        sum = "h1:jF+Du6AlPIjs2BiUiQlKOX0rt3SujHxPnksPKZbaA40=",
        version = "v0.1.12",
    )

    go_repository(
        name = "com_github_mattn_go_isatty",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mattn/go-isatty",
        sum = "h1:yVuAays6BHfxijgZPzw+3Zlu5yQgKGP2/hcQbHb7S9Y=",
        version = "v0.0.14",
    )

    go_repository(
        name = "com_github_mattn_go_oci8",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mattn/go-oci8",
        sum = "h1:aEUDxNAyDG0tv8CA3TArnDQNyc4EhnWlsfxRgDHABHM=",
        version = "v0.1.1",
    )

    go_repository(
        name = "com_github_mattn_go_runewidth",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mattn/go-runewidth",
        sum = "h1:Lm995f3rfxdpd6TSmuVCHVb/QhupuXlYr8sCI/QdE+0=",
        version = "v0.0.9",
    )

    go_repository(
        name = "com_github_mattn_go_shellwords",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mattn/go-shellwords",
        sum = "h1:M2zGm7EW6UQJvDeQxo4T51eKPurbeFbe8WtebGE2xrk=",
        version = "v1.0.12",
    )

    go_repository(
        name = "com_github_mattn_go_sqlite3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mattn/go-sqlite3",
        sum = "h1:dNPt6NO46WmLVt2DLNpwczCmdV5boIZ6g/tlDrlRUbg=",
        version = "v1.14.6",
    )

    go_repository(
        name = "com_github_matttproud_golang_protobuf_extensions",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/matttproud/golang_protobuf_extensions",
        sum = "h1:I0XW9+e1XWDxdcEniV4rQAIOPUGDq67JSCiRCgGCZLI=",
        version = "v1.0.2-0.20181231171920-c182affec369",
    )
    go_repository(
        name = "com_github_maxbrunsfeld_counterfeiter_v6",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/maxbrunsfeld/counterfeiter/v6",
        sum = "h1:g+4J5sZg6osfvEfkRZxJ1em0VT95/UOZgi/l7zi1/oE=",
        version = "v6.2.2",
    )

    go_repository(
        name = "com_github_microsoft_go_winio",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Microsoft/go-winio",
        sum = "h1:aPJp2QD7OOrhO5tQXqQoGSJc+DjDtWTGLOmNyAm6FgY=",
        version = "v0.5.1",
    )

    go_repository(
        name = "com_github_microsoft_hcsshim",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Microsoft/hcsshim",
        sum = "h1:wB06W5aYFfUB3IvootYAY2WnOmIdgPGfqSI6tufQNnY=",
        version = "v0.9.2",
    )
    go_repository(
        name = "com_github_microsoft_hcsshim_test",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Microsoft/hcsshim/test",
        sum = "h1:4FA+QBaydEHlwxg0lMN3rhwoDaQy6LKhVWR4qvq4BuA=",
        version = "v0.0.0-20210227013316-43a75bb4edd3",
    )

    go_repository(
        name = "com_github_miekg_dns",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/miekg/dns",
        sum = "h1:WMszZWJG0XmzbK9FEmzH2TVcqYzFesusSIB41b8KHxY=",
        version = "v1.1.41",
    )
    go_repository(
        name = "com_github_miekg_pkcs11",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/miekg/pkcs11",
        sum = "h1:iMwmD7I5225wv84WxIG/bmxz9AXjWvTWIbM/TYHvWtw=",
        version = "v1.0.3",
    )
    go_repository(
        name = "com_github_mistifyio_go_zfs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mistifyio/go-zfs",
        sum = "h1:aKW/4cBs+yK6gpqU3K/oIwk9Q/XICqd3zOX/UFuvqmk=",
        version = "v2.1.2-0.20190413222219-f784269be439+incompatible",
    )

    go_repository(
        name = "com_github_mitchellh_cli",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/cli",
        sum = "h1:PvH+lL2B7IQ101xQL63Of8yFS2y+aDlsFcsqNc+u/Kw=",
        version = "v1.1.2",
    )

    go_repository(
        name = "com_github_mitchellh_copystructure",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/copystructure",
        sum = "h1:vpKXTN4ewci03Vljg/q9QvCGUDttBOGBIa15WveJJGw=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_mitchellh_go_homedir",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/go-homedir",
        sum = "h1:lukF9ziXFxDFPkA1vsr5zpc1XuPDn/wFntq5mG+4E0Y=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_mitchellh_go_testing_interface",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/go-testing-interface",
        sum = "h1:fzU/JVNcaqHQEcVFAKeR41fkiLdIPrefOvVG1VZ96U0=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_mitchellh_go_wordwrap",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/go-wordwrap",
        sum = "h1:6GlHJ/LTGMrIJbwgdqdl2eEH8o+Exx/0m8ir9Gns0u4=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_mitchellh_gox",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/gox",
        sum = "h1:lfGJxY7ToLJQjHHwi0EX6uYBdK78egf954SQl13PQJc=",
        version = "v0.4.0",
    )

    go_repository(
        name = "com_github_mitchellh_iochan",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/iochan",
        sum = "h1:C+X3KsSTLFVBr/tK1eYN/vs4rJcvsiLU338UhYPJWeY=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_mitchellh_mapstructure",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/mapstructure",
        sum = "h1:OVowDSCllw/YjdLkam3/sm7wEtOy59d8ndGgCcyj8cs=",
        version = "v1.4.3",
    )

    go_repository(
        name = "com_github_mitchellh_osext",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/osext",
        sum = "h1:2+myh5ml7lgEU/51gbeLHfKGNfgEQQIWrlbdaOsidbQ=",
        version = "v0.0.0-20151018003038-5e2d6d41470f",
    )

    go_repository(
        name = "com_github_mitchellh_reflectwalk",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mitchellh/reflectwalk",
        sum = "h1:G2LzWKi524PWgd3mLHV8Y5k7s6XUvT0Gef6zxSIeXaQ=",
        version = "v1.0.2",
    )
    go_repository(
        name = "com_github_moby_locker",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/moby/locker",
        sum = "h1:fOXqR41zeveg4fFODix+1Ch4mj/gT0NE1XJbp/epuBg=",
        version = "v1.0.1",
    )

    go_repository(
        name = "com_github_moby_spdystream",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/moby/spdystream",
        sum = "h1:cjW1zVyyoiM0T7b6UoySUFqzXMoqRckQtXwGPiBhOM8=",
        version = "v0.2.0",
    )
    go_repository(
        name = "com_github_moby_sys_mountinfo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/moby/sys/mountinfo",
        sum = "h1:2Ks8/r6lopsxWi9m58nlwjaeSzUX9iiL1vj5qB/9ObI=",
        version = "v0.5.0",
    )
    go_repository(
        name = "com_github_moby_sys_symlink",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/moby/sys/symlink",
        sum = "h1:MTFZ74KtNI6qQQpuBxU+uKCim4WtOMokr03hCfJcazE=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_moby_term",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/moby/term",
        sum = "h1:yH0SvLzcbZxcJXho2yh7CqdENGMQe73Cw3woZBpPli0=",
        version = "v0.0.0-20210610120745-9d4ed1856297",
    )

    go_repository(
        name = "com_github_modern_go_concurrent",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/modern-go/concurrent",
        sum = "h1:TRLaZ9cD/w8PVh93nsPXa1VrQ6jlwL5oN8l14QlcNfg=",
        version = "v0.0.0-20180306012644-bacd9c7ef1dd",
    )

    go_repository(
        name = "com_github_modern_go_reflect2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/modern-go/reflect2",
        sum = "h1:xBagoLtFs94CBntxluKeaWgTMpvLxC4ur3nMaC9Gz0M=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_monochromegane_go_gitignore",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/monochromegane/go-gitignore",
        sum = "h1:n6/2gBQ3RWajuToeY6ZtZTIKv2v7ThUy5KKusIT0yc0=",
        version = "v0.0.0-20200626010858-205db1a8cc00",
    )

    go_repository(
        name = "com_github_morikuni_aec",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/morikuni/aec",
        sum = "h1:nP9CBfwrvYnBRgY6qfDQkygYDmYwOilePFkwzv4dU8A=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_mrunalp_fileutils",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mrunalp/fileutils",
        sum = "h1:NKzVxiH7eSk+OQ4M+ZYW1K6h27RUV3MI6NUTsHhU6Z4=",
        version = "v0.5.0",
    )

    go_repository(
        name = "com_github_munnerz_crd_schema_fuzz",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/munnerz/crd-schema-fuzz",
        sum = "h1:8erI9yzEnOGw9K5O+a8zZdoo8N/OwrFi7c7SjBtkHAs=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_munnerz_goautoneg",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/munnerz/goautoneg",
        sum = "h1:C3w9PqII01/Oq1c1nUAm88MOHcQC9l5mIlSMApZMrHA=",
        version = "v0.0.0-20191010083416-a7dc8b61c822",
    )

    go_repository(
        name = "com_github_mwitkow_go_conntrack",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mwitkow/go-conntrack",
        sum = "h1:KUppIJq7/+SVif2QVs3tOP0zanoHgBEVAwHxUSIzRqU=",
        version = "v0.0.0-20190716064945-2f068394615f",
    )

    go_repository(
        name = "com_github_mxk_go_flowrate",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/mxk/go-flowrate",
        sum = "h1:y5//uYreIhSUg3J1GEMiLbxo1LJaP8RfCpH6pymGZus=",
        version = "v0.0.0-20140419014527-cca7078d478f",
    )

    go_repository(
        name = "com_github_nbio_st",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/nbio/st",
        sum = "h1:W6apQkHrMkS0Muv8G/TipAy/FJl/rCYT0+EuS8+Z0z4=",
        version = "v0.0.0-20140626010706-e9e8d9816f32",
    )

    go_repository(
        name = "com_github_ncw_swift",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ncw/swift",
        sum = "h1:4DQRPj35Y41WogBxyhOXlrI37nzGlyEcsforeudyYPQ=",
        version = "v1.0.47",
    )

    go_repository(
        name = "com_github_niemeyer_pretty",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/niemeyer/pretty",
        sum = "h1:fD57ERR4JtEqsWbfPhv4DMiApHyliiK5xCTNVSPiaAs=",
        version = "v0.0.0-20200227124842-a10e7caefd8e",
    )

    go_repository(
        name = "com_github_nxadm_tail",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/nxadm/tail",
        sum = "h1:nPr65rt6Y5JFSKQO7qToXr7pePgD6Gwiw05lkbyAQTE=",
        version = "v1.4.8",
    )

    go_repository(
        name = "com_github_nytimes_gziphandler",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/NYTimes/gziphandler",
        sum = "h1:ZUDjpQae29j0ryrS0u/B8HZfJBtBQHjqw2rQ2cqUQ3I=",
        version = "v1.1.1",
    )

    go_repository(
        name = "com_github_oklog_run",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/oklog/run",
        sum = "h1:Ru7dDtJNOyC66gQ5dQmaCa0qIsAUFY3sFpK1Xk8igrw=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_oklog_ulid",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/oklog/ulid",
        sum = "h1:EGfNDEx6MqHz8B3uNV6QAib1UR2Lm97sHi3ocA6ESJ4=",
        version = "v1.3.1",
    )

    go_repository(
        name = "com_github_olekukonko_tablewriter",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/olekukonko/tablewriter",
        sum = "h1:P2Ga83D34wi1o9J6Wh1mRuqd4mF/x/lgBS7N7AbDhec=",
        version = "v0.0.5",
    )

    go_repository(
        name = "com_github_oneofone_xxhash",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/OneOfOne/xxhash",
        sum = "h1:KMrpdQIwFcEqXDklaen+P1axHaj9BSKzvpUUfnHldSE=",
        version = "v1.2.2",
    )

    go_repository(
        name = "com_github_onsi_ginkgo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/onsi/ginkgo",
        sum = "h1:8xi0RTUf59SOSfEtZMvwTvXYMzG4gV23XVHOZiXNtnE=",
        version = "v1.16.5",
    )

    go_repository(
        name = "com_github_onsi_gomega",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/onsi/gomega",
        sum = "h1:9Luw4uT5HTjHTN8+aNcSThgH1vdXnmdJ8xIfZ4wyTRE=",
        version = "v1.17.0",
    )

    go_repository(
        name = "com_github_opencontainers_go_digest",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/opencontainers/go-digest",
        sum = "h1:apOUWs51W5PlhuyGyz9FCeeBIOUDA/6nW8Oi/yOhh5U=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_opencontainers_image_spec",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/opencontainers/image-spec",
        sum = "h1:9yCKha/T5XdGtO0q9Q9a6T5NUCsTn/DrBg0D7ufOcFM=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_opencontainers_runc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/opencontainers/runc",
        sum = "h1:opHZMaswlyxz1OuGpBE53Dwe4/xF7EZTY0A2L/FpCOg=",
        version = "v1.0.2",
    )

    go_repository(
        name = "com_github_opencontainers_runtime_spec",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/opencontainers/runtime-spec",
        sum = "h1:3snG66yBm59tKhhSPQrQ/0bCrv1LQbKt40LnUPiUxdc=",
        version = "v1.0.3-0.20210326190908-1c3f411f0417",
    )
    go_repository(
        name = "com_github_opencontainers_runtime_tools",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/opencontainers/runtime-tools",
        sum = "h1:H7DMc6FAjgwZZi8BRqjrAAHWoqEr5e5L6pS4V0ezet4=",
        version = "v0.0.0-20181011054405-1d69bd0f9c39",
    )
    go_repository(
        name = "com_github_opencontainers_selinux",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/opencontainers/selinux",
        sum = "h1:c4ca10UMgRcvZ6h0K4HtS15UaVSBEaE+iln2LVpAuGc=",
        version = "v1.8.2",
    )

    go_repository(
        name = "com_github_opentracing_opentracing_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/opentracing/opentracing-go",
        sum = "h1:pWlfV3Bxv7k65HYwkikxat0+s3pV4bsqf19k25Ur8rU=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_pascaldekloe_goe",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pascaldekloe/goe",
        sum = "h1:cBOtyMzM9HTpWjXfbbunk26uA6nG3a8n06Wieeh0MwY=",
        version = "v0.1.0",
    )

    go_repository(
        name = "com_github_patrickmn_go_cache",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/patrickmn/go-cache",
        sum = "h1:HRMgzkcYKYpi3C8ajMPV8OFXaaRUnok+kx1WdO15EQc=",
        version = "v2.1.0+incompatible",
    )

    go_repository(
        name = "com_github_pavel_v_chernykh_keystore_go_v4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pavel-v-chernykh/keystore-go/v4",
        sum = "h1:SeA1Gyj3Uxl0vuNFYxN5RaIZ2AMPfCvW4HB2Ki0bYT8=",
        version = "v4.2.0",
    )

    go_repository(
        name = "com_github_pborman_uuid",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pborman/uuid",
        sum = "h1:J7Q5mO4ysT1dv8hyrUGHb9+ooztCXu1D8MY8DZYsu3g=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_pelletier_go_toml",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pelletier/go-toml",
        sum = "h1:tjENF6MfZAg8e4ZmZTeWaWiT2vXtsoO6+iuOjFhECwM=",
        version = "v1.9.4",
    )

    go_repository(
        name = "com_github_peterbourgon_diskv",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/peterbourgon/diskv",
        sum = "h1:UBdAOUP5p4RWqPBg048CAvpKN+vxiaj6gdUUzhl4XmI=",
        version = "v2.0.1+incompatible",
    )

    go_repository(
        name = "com_github_phayes_freeport",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/phayes/freeport",
        sum = "h1:JhzVVoYvbOACxoUmOs6V/G4D5nPVUW73rKvXxP4XUJc=",
        version = "v0.0.0-20180830031419-95f893ade6f2",
    )

    go_repository(
        name = "com_github_pierrec_lz4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pierrec/lz4",
        sum = "h1:WCjObylUIOlKy/+7Abdn34TLIkXiA4UWUMhxq9m9ZXI=",
        version = "v2.5.2+incompatible",
    )

    go_repository(
        name = "com_github_pkg_errors",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pkg/errors",
        sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        version = "v0.9.1",
    )

    go_repository(
        name = "com_github_pkg_sftp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pkg/sftp",
        sum = "h1:VasscCm72135zRysgrJDKsntdmPN+OuU3+nnHYA9wyc=",
        version = "v1.10.1",
    )

    go_repository(
        name = "com_github_pmezard_go_difflib",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pmezard/go-difflib",
        sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_posener_complete",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/posener/complete",
        sum = "h1:NP0eAhjcjImqslEwo/1hq7gpajME0fTLTezBKDqfXqo=",
        version = "v1.2.3",
    )

    go_repository(
        name = "com_github_pquerna_cachecontrol",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/pquerna/cachecontrol",
        sum = "h1:0XM1XL/OFFJjXsYXlG30spTkV/E9+gmd5GD1w2HE8xM=",
        version = "v0.0.0-20171018203845-0dec1b30a021",
    )

    go_repository(
        name = "com_github_prometheus_client_golang",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/prometheus/client_golang",
        sum = "h1:HNkLOAEQMIDv/K+04rukrLx6ch7msSRwf3/SASFAGtQ=",
        version = "v1.11.0",
    )

    go_repository(
        name = "com_github_prometheus_client_model",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/prometheus/client_model",
        sum = "h1:uq5h0d+GuxiXLJLNABMgp2qUWDPiLvgCzz2dUR+/W/M=",
        version = "v0.2.0",
    )

    go_repository(
        name = "com_github_prometheus_common",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/prometheus/common",
        sum = "h1:vGVfV9KrDTvWt5boZO0I19g2E3CsWfpPPKZM9dt3mEw=",
        version = "v0.28.0",
    )

    go_repository(
        name = "com_github_prometheus_procfs",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/prometheus/procfs",
        sum = "h1:mxy4L2jP6qMonqmq+aTtOx1ifVWUgG/TAmntgbh3xv4=",
        version = "v0.6.0",
    )

    go_repository(
        name = "com_github_prometheus_tsdb",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/prometheus/tsdb",
        sum = "h1:YZcsG11NqnK4czYLrWd9mpEuAJIHVQLwdrleYfszMAA=",
        version = "v0.7.1",
    )

    go_repository(
        name = "com_github_puerkitobio_purell",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/PuerkitoBio/purell",
        sum = "h1:WEQqlqaGbrPkxLJWfBwQmfEAE1Z7ONdDLqrN38tNFfI=",
        version = "v1.1.1",
    )

    go_repository(
        name = "com_github_puerkitobio_urlesc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/PuerkitoBio/urlesc",
        sum = "h1:d+Bc7a5rLufV/sSk/8dngufqelfh6jnri85riMAaF/M=",
        version = "v0.0.0-20170810143723-de5bf2ad4578",
    )

    go_repository(
        name = "com_github_rogpeppe_fastuuid",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/rogpeppe/fastuuid",
        sum = "h1:Ppwyp6VYCF1nvBTXL3trRso7mXMlRrw9ooo375wvi2s=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_rogpeppe_go_internal",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/rogpeppe/go-internal",
        sum = "h1:/FiVV8dS/e+YqF2JvO3yXRFbBLTIuSDkuC7aBOAvL+k=",
        version = "v1.6.1",
    )

    go_repository(
        name = "com_github_rubenv_sql_migrate",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/rubenv/sql-migrate",
        sum = "h1:BD7uZqkN8CpjJtN/tScAKiccBikU4dlqe/gNrkRaPY4=",
        version = "v0.0.0-20210614095031-55d5740dbbcc",
    )

    go_repository(
        name = "com_github_russross_blackfriday",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/russross/blackfriday",
        sum = "h1:HyvC0ARfnZBqnXwABFeSZHpKvJHJJfPz81GNueLj0oo=",
        version = "v1.5.2",
    )

    go_repository(
        name = "com_github_russross_blackfriday_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/russross/blackfriday/v2",
        sum = "h1:JIOH55/0cWyOuilr9/qlrm0BSXldqnqwMsf35Ld67mk=",
        version = "v2.1.0",
    )

    go_repository(
        name = "com_github_ryanuber_columnize",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ryanuber/columnize",
        sum = "h1:j1Wcmh8OrK4Q7GXY+V7SVSY8nUWQxHW5TkBe7YUl+2s=",
        version = "v2.1.0+incompatible",
    )

    go_repository(
        name = "com_github_ryanuber_go_glob",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ryanuber/go-glob",
        sum = "h1:iQh3xXAumdQ+4Ufa5b25cRpC5TYKlno6hsv6Cb3pkBk=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_safchain_ethtool",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/safchain/ethtool",
        sum = "h1:2c1EFnZHIPCW8qKWgHMH/fX2PkSabFc5mrVzfUNdg5U=",
        version = "v0.0.0-20190326074333-42ed695e3de8",
    )
    go_repository(
        name = "com_github_sagikazarmark_crypt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/sagikazarmark/crypt",
        sum = "h1:TV5DVog+pihN4Rr0rN1IClv4ePpkzdg9sPrw7WDofZ8=",
        version = "v0.3.0",
    )

    go_repository(
        name = "com_github_satori_go_uuid",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/satori/go.uuid",
        sum = "h1:0uYX9dsZ2yD7q2RtLRtPSdGDWzjeM3TbMJP9utgA0ww=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_sclevine_spec",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/sclevine/spec",
        sum = "h1:1Jwdf9jSfDl9NVmt8ndHqbTZ7XCCPbh1jI3hkDBHVYA=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_sean_seed",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/sean-/seed",
        sum = "h1:nn5Wsu0esKSJiIVhscUtVbo7ada43DJhG55ua/hjS5I=",
        version = "v0.0.0-20170313163322-e2103e2c3529",
    )
    go_repository(
        name = "com_github_seccomp_libseccomp_golang",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/seccomp/libseccomp-golang",
        sum = "h1:NJjM5DNFOs0s3kYE1WUOr6G8V97sdt46rlXTMfXGWBo=",
        version = "v0.9.1",
    )

    go_repository(
        name = "com_github_sergi_go_diff",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/sergi/go-diff",
        sum = "h1:XU+rvMAioB0UC3q1MFrIQy4Vo5/4VsRDQQXHsEya6xQ=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_shopify_logrus_bugsnag",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Shopify/logrus-bugsnag",
        sum = "h1:UrqY+r/OJnIp5u0s1SbQ8dVfLCZJsnvazdBP5hS4iRs=",
        version = "v0.0.0-20171204204709-577dee27f20d",
    )

    go_repository(
        name = "com_github_shopspring_decimal",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/shopspring/decimal",
        sum = "h1:abSATXmQEYyShuxI4/vyW3tV1MrKAJzCZ/0zLUXYbsQ=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_shurcool_sanitized_anchor_name",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/shurcooL/sanitized_anchor_name",
        sum = "h1:PdmoCO6wvbs+7yrJyMORt4/BmY5IYyJwS/kOiWx8mHo=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_sirupsen_logrus",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/sirupsen/logrus",
        sum = "h1:dJKuHgqk1NNQlqoA6BTlM1Wf9DOH3NBjQyu0h9+AZZE=",
        version = "v1.8.1",
    )

    go_repository(
        name = "com_github_smartystreets_assertions",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/smartystreets/assertions",
        sum = "h1:zE9ykElWQ6/NYmHa3jpm/yHnI4xSofP+UP6SpjHcSeM=",
        version = "v0.0.0-20180927180507-b2de0cb4f26d",
    )

    go_repository(
        name = "com_github_smartystreets_goconvey",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/smartystreets/goconvey",
        sum = "h1:fv0U8FUIMPNf1L9lnHLvLhgicrIVChEkdzIKYqbNC9s=",
        version = "v1.6.4",
    )

    go_repository(
        name = "com_github_soheilhy_cmux",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/soheilhy/cmux",
        sum = "h1:jjzc5WVemNEDTLwv9tlmemhC73tI08BNOIGwBOo10Js=",
        version = "v0.1.5",
    )

    go_repository(
        name = "com_github_spaolacci_murmur3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/spaolacci/murmur3",
        sum = "h1:qLC7fQah7D6K1B0ujays3HV9gkFtllcxhzImRR7ArPQ=",
        version = "v0.0.0-20180118202830-f09979ecbc72",
    )

    go_repository(
        name = "com_github_spf13_afero",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/spf13/afero",
        sum = "h1:xoax2sJ2DT8S8xA2paPFjDCScCNeWsg75VG0DLRreiY=",
        version = "v1.6.0",
    )

    go_repository(
        name = "com_github_spf13_cast",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/spf13/cast",
        sum = "h1:s0hze+J0196ZfEMTs80N7UlFt0BDuQ7Q+JDnHiMWKdA=",
        version = "v1.4.1",
    )

    go_repository(
        name = "com_github_spf13_cobra",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/spf13/cobra",
        sum = "h1:R7cSvGu+Vv+qX0gW5R/85dx2kmmJT5z5NM8ifdYjdn0=",
        version = "v1.3.0",
    )

    go_repository(
        name = "com_github_spf13_jwalterweatherman",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/spf13/jwalterweatherman",
        sum = "h1:ue6voC5bR5F8YxI5S67j9i582FU4Qvo2bmqnqMYADFk=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_spf13_pflag",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/spf13/pflag",
        sum = "h1:iy+VFUOCP1a+8yFto/drg2CJ5u0yRoB7fZw3DKv/JXA=",
        version = "v1.0.5",
    )

    go_repository(
        name = "com_github_spf13_viper",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/spf13/viper",
        sum = "h1:mXH0UwHS4D2HwWZa75im4xIQynLfblmWV7qcWpfv0yk=",
        version = "v1.10.0",
    )
    go_repository(
        name = "com_github_stefanberger_go_pkcs11uri",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/stefanberger/go-pkcs11uri",
        sum = "h1:lIOOHPEbXzO3vnmx2gok1Tfs31Q8GQqKLc8vVqyQq/I=",
        version = "v0.0.0-20201008174630-78d3cae3a980",
    )

    go_repository(
        name = "com_github_stoewer_go_strcase",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/stoewer/go-strcase",
        sum = "h1:Z2iHWqGXH00XYgqDmNgQbIBxf3wrNq0F3feEy0ainaU=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_stretchr_objx",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/stretchr/objx",
        sum = "h1:Hbg2NidpLE8veEBkEZTL3CvlkUIVzuU9jDplZO54c48=",
        version = "v0.2.0",
    )

    go_repository(
        name = "com_github_stretchr_testify",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/stretchr/testify",
        sum = "h1:nwc3DEeHmmLAfoZucVR881uASk0Mfjw8xYJ99tb5CcY=",
        version = "v1.7.0",
    )

    go_repository(
        name = "com_github_subosito_gotenv",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/subosito/gotenv",
        sum = "h1:Slr1R9HxAlEKefgq5jn9U+DnETlIUa6HfgEzj0g5d7s=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_syndtr_gocapability",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/syndtr/gocapability",
        sum = "h1:kdXcSzyDtseVEc4yCz2qF8ZrQvIDBJLl4S1c3GCXmoI=",
        version = "v0.0.0-20200815063812-42c35b437635",
    )
    go_repository(
        name = "com_github_tchap_go_patricia",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/tchap/go-patricia",
        sum = "h1:JvoDL7JSoIP2HDE8AbDH3zC8QBPxmzYe32HHy5yQ+Ck=",
        version = "v2.2.6+incompatible",
    )

    go_repository(
        name = "com_github_tidwall_pretty",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/tidwall/pretty",
        sum = "h1:HsD+QiTn7sK6flMKIvNmpqz1qrpP3Ps6jOKIKMooyg4=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_tmc_grpc_websocket_proxy",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/tmc/grpc-websocket-proxy",
        sum = "h1:uruHq4dN7GR16kFc5fp3d1RIYzJW5onx8Ybykw2YQFA=",
        version = "v0.0.0-20201229170055-e5319fda7802",
    )

    go_repository(
        name = "com_github_tv42_httpunix",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/tv42/httpunix",
        sum = "h1:G3dpKMzFDjgEh2q1Z7zUUtKa8ViPtH+ocF0bE0g00O8=",
        version = "v0.0.0-20150427012821-b75d8614f926",
    )

    go_repository(
        name = "com_github_ugorji_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ugorji/go",
        sum = "h1:j4s+tAvLfL3bZyefP2SEWmhBzmuIlH/eqNuPdFPgngw=",
        version = "v1.1.4",
    )

    go_repository(
        name = "com_github_ugorji_go_codec",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ugorji/go/codec",
        sum = "h1:3SVOIvH7Ae1KRYyQWRjXWJEA9sS/c/pjvH++55Gr648=",
        version = "v0.0.0-20181204163529-d75b2dcb6bc8",
    )

    go_repository(
        name = "com_github_urfave_cli",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/urfave/cli",
        sum = "h1:gsqYFH8bb9ekPA12kRo0hfjngWQjkJPlN9R0N78BoUo=",
        version = "v1.22.2",
    )

    go_repository(
        name = "com_github_urfave_cli_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/urfave/cli/v2",
        sum = "h1:qph92Y649prgesehzOrQjdWyxFOp/QVM+6imKHad91M=",
        version = "v2.3.0",
    )

    go_repository(
        name = "com_github_vektah_gqlparser",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/vektah/gqlparser",
        sum = "h1:ZsyLGn7/7jDNI+y4SEhI4yAxRChlv15pUHMjijT+e68=",
        version = "v1.1.2",
    )

    go_repository(
        name = "com_github_venafi_vcert_v4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/Venafi/vcert/v4",
        sum = "h1:tlyhgQKTzMXn9B44hx8CDI4oiaisWEWSGH66KKUh088=",
        version = "v4.14.3",
    )
    go_repository(
        name = "com_github_vishvananda_netlink",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/vishvananda/netlink",
        sum = "h1:cPXZWzzG0NllBLdjWoD1nDfaqu98YMv+OneaKc8sPOA=",
        version = "v1.1.1-0.20201029203352-d40f9887b852",
    )
    go_repository(
        name = "com_github_vishvananda_netns",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/vishvananda/netns",
        sum = "h1:4hwBBUfQCFe3Cym0ZtKyq7L16eZUtYKs+BaHDN6mAns=",
        version = "v0.0.0-20200728191858-db3c7e526aae",
    )

    go_repository(
        name = "com_github_willf_bitset",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/willf/bitset",
        sum = "h1:N7Z7E9UvjW+sGsEl7k/SJrvY2reP1A07MrGuCjIOjRE=",
        version = "v1.1.11",
    )

    go_repository(
        name = "com_github_xeipuuv_gojsonpointer",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/xeipuuv/gojsonpointer",
        sum = "h1:J9EGpcZtP0E/raorCMxlFGSTBrsSlaDGf3jU/qvAE2c=",
        version = "v0.0.0-20180127040702-4e3ac2762d5f",
    )

    go_repository(
        name = "com_github_xeipuuv_gojsonreference",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/xeipuuv/gojsonreference",
        sum = "h1:EzJWgHovont7NscjpAxXsDA8S8BMYve8Y5+7cuRE7R0=",
        version = "v0.0.0-20180127040603-bd5ef7bd5415",
    )

    go_repository(
        name = "com_github_xeipuuv_gojsonschema",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/xeipuuv/gojsonschema",
        sum = "h1:LhYJRs+L4fBtjZUfuSZIKGeVu0QRy8e5Xi7D17UxZ74=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_xiang90_probing",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/xiang90/probing",
        sum = "h1:eY9dn8+vbi4tKz5Qo6v2eYzo7kUS51QINcR5jNpbZS8=",
        version = "v0.0.0-20190116061207-43a291ad63a2",
    )

    go_repository(
        name = "com_github_xlab_treeprint",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/xlab/treeprint",
        sum = "h1:1CFlNzQhALwjS9mBAUkycX616GzgsuYUOCHA5+HSlXI=",
        version = "v0.0.0-20181112141820-a009c3971eca",
    )

    go_repository(
        name = "com_github_xordataexchange_crypt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/xordataexchange/crypt",
        sum = "h1:ESFSdwYZvkeru3RtdrYueztKhOBCSAAzS4Gf+k0tEow=",
        version = "v0.0.3-0.20170626215501-b2862e3d0a77",
    )

    go_repository(
        name = "com_github_yuin_goldmark",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/yuin/goldmark",
        sum = "h1:OtISOGfH6sOWa1/qXqqAiOIAO6Z5J3AEAE18WAq6BiQ=",
        version = "v1.4.0",
    )

    go_repository(
        name = "com_github_yvasiyarov_go_metrics",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/yvasiyarov/go-metrics",
        sum = "h1:+lm10QQTNSBd8DVTNGHx7o/IKu9HYDvLMffDhbyLccI=",
        version = "v0.0.0-20140926110328-57bccd1ccd43",
    )

    go_repository(
        name = "com_github_yvasiyarov_gorelic",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/yvasiyarov/gorelic",
        sum = "h1:hlE8//ciYMztlGpl/VA+Zm1AcTPHYkHJPbHqE6WJUXE=",
        version = "v0.0.0-20141212073537-a9bba5b9ab50",
    )

    go_repository(
        name = "com_github_yvasiyarov_newrelic_platform_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/yvasiyarov/newrelic_platform_go",
        sum = "h1:ERexzlUfuTvpE74urLSbIQW0Z/6hF9t8U4NsJLaioAY=",
        version = "v0.0.0-20140908184405-b21fdbd4370f",
    )

    go_repository(
        name = "com_github_ziutek_mymysql",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "github.com/ziutek/mymysql",
        sum = "h1:GB0qdRGsTwQSBVYuVShFBKaXSnSnYYC2d9knnE1LHFs=",
        version = "v1.5.4",
    )

    go_repository(
        name = "com_google_cloud_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "cloud.google.com/go",
        sum = "h1:y/cM2iqGgGi5D5DQZl6D9STN/3dR/Vx5Mp8s752oJTY=",
        version = "v0.99.0",
    )

    go_repository(
        name = "com_google_cloud_go_bigquery",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "cloud.google.com/go/bigquery",
        sum = "h1:PQcPefKFdaIzjQFbiyOgAqyx8q5djaE7x9Sqe712DPA=",
        version = "v1.8.0",
    )

    go_repository(
        name = "com_google_cloud_go_datastore",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "cloud.google.com/go/datastore",
        sum = "h1:/May9ojXjRkPBNVrq+oWLqmWCkr4OU5uRY29bu0mRyQ=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_google_cloud_go_firestore",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "cloud.google.com/go/firestore",
        sum = "h1:8rBq3zRjnHx8UtBvaOWqBB1xq9jH6/wltfQLlTMh2Fw=",
        version = "v1.6.1",
    )

    go_repository(
        name = "com_google_cloud_go_pubsub",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "cloud.google.com/go/pubsub",
        sum = "h1:ukjixP1wl0LpnZ6LWtZJ0mX5tBmjp1f8Sqer8Z2OMUU=",
        version = "v1.3.1",
    )

    go_repository(
        name = "com_google_cloud_go_storage",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "cloud.google.com/go/storage",
        sum = "h1:STgFzyU5/8miMl0//zKh2aQeTyeaUH3WN9bSUiJ09bA=",
        version = "v1.10.0",
    )

    go_repository(
        name = "com_shuralyov_dmitri_gpu_mtl",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "dmitri.shuralyov.com/gpu/mtl",
        sum = "h1:VpgP7xuJadIUuKccphEpTJnWhS2jkQyMt6Y7pJCD7fY=",
        version = "v0.0.0-20190408044501-666a987793e9",
    )

    go_repository(
        name = "com_sslmate_software_src_go_pkcs12",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "software.sslmate.com/src/go-pkcs12",
        sum = "h1:SqYE5+A2qvRhErbsXFfUEUmpWEKxxRSMgGLkvRAFOV4=",
        version = "v0.0.0-20210415151418-c5206de65a78",
    )

    go_repository(
        name = "in_gopkg_airbrake_gobrake_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/airbrake/gobrake.v2",
        sum = "h1:7z2uVWwn7oVeeugY1DtlPAy5H+KYgB1KeKTnqjNatLo=",
        version = "v2.0.9",
    )

    go_repository(
        name = "in_gopkg_alecthomas_kingpin_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/alecthomas/kingpin.v2",
        sum = "h1:jMFz6MfLP0/4fUyZle81rXUoxOBFi19VUFKVDOQfozc=",
        version = "v2.2.6",
    )

    go_repository(
        name = "in_gopkg_check_v1",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/check.v1",
        sum = "h1:Hei/4ADfdWqJk1ZMxUNpqntNwaWcugrBjAiHlqqRiVk=",
        version = "v1.0.0-20201130134442-10cb98267c6c",
    )

    go_repository(
        name = "in_gopkg_cheggaaa_pb_v1",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/cheggaaa/pb.v1",
        sum = "h1:Ev7yu1/f6+d+b3pi5vPdRPc6nNtP1umSfcWiEfRqv6I=",
        version = "v1.0.25",
    )

    go_repository(
        name = "in_gopkg_errgo_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/errgo.v2",
        sum = "h1:0vLT13EuvQ0hNvakwLuFZ/jYrLp5F3kcWHXdRggjCE8=",
        version = "v2.1.0",
    )

    go_repository(
        name = "in_gopkg_fsnotify_v1",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/fsnotify.v1",
        sum = "h1:xOHLXZwVvI9hhs+cLKq5+I5onOuwQLhQwiu63xxlHs4=",
        version = "v1.4.7",
    )

    go_repository(
        name = "in_gopkg_gemnasium_logrus_airbrake_hook_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/gemnasium/logrus-airbrake-hook.v2",
        sum = "h1:OAj3g0cR6Dx/R07QgQe8wkA9RNjB2u4i700xBkIT4e0=",
        version = "v2.1.2",
    )

    go_repository(
        name = "in_gopkg_gorp_v1",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/gorp.v1",
        sum = "h1:j3DWlAyGVv8whO7AcIWznQ2Yj7yJkn34B8s63GViAAw=",
        version = "v1.7.2",
    )

    go_repository(
        name = "in_gopkg_h2non_gock_v1",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/h2non/gock.v1",
        sum = "h1:SzLqcIlb/fDfg7UvukMpNcWsu7sI5tWwL+KCATZqks0=",
        version = "v1.0.15",
    )

    go_repository(
        name = "in_gopkg_inf_v0",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/inf.v0",
        sum = "h1:73M5CoZyi3ZLMOyDlQh031Cx6N9NDJ2Vvfl76EDAgDc=",
        version = "v0.9.1",
    )

    go_repository(
        name = "in_gopkg_ini_v1",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/ini.v1",
        sum = "h1:XfR1dOYubytKy4Shzc2LHrrGhU0lDCfDGG1yLPmpgsI=",
        version = "v1.66.2",
    )

    go_repository(
        name = "in_gopkg_natefinch_lumberjack_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/natefinch/lumberjack.v2",
        sum = "h1:1Lc07Kr7qY4U2YPouBjpCLxpiyxIVoxqXgkXLknAOE8=",
        version = "v2.0.0",
    )

    go_repository(
        name = "in_gopkg_resty_v1",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/resty.v1",
        sum = "h1:CuXP0Pjfw9rOuY6EP+UvtNvt5DSqHpIxILZKT/quCZI=",
        version = "v1.12.0",
    )

    go_repository(
        name = "in_gopkg_square_go_jose_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/square/go-jose.v2",
        sum = "h1:7odma5RETjNHWJnR32wx8t+Io4djHE1PqxCFx3iiZ2w=",
        version = "v2.5.1",
    )

    go_repository(
        name = "in_gopkg_tomb_v1",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/tomb.v1",
        sum = "h1:uRGJdciOHaEIrze2W8Q3AKkepLTh2hOroT7a+7czfdQ=",
        version = "v1.0.0-20141024135613-dd632973f1e7",
    )

    go_repository(
        name = "in_gopkg_yaml_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/yaml.v2",
        sum = "h1:D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=",
        version = "v2.4.0",
    )

    go_repository(
        name = "in_gopkg_yaml_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gopkg.in/yaml.v3",
        sum = "h1:h8qDotaEPuJATrMmW04NCwg7v22aHH28wwpauUhK9Oo=",
        version = "v3.0.0-20210107192922-496545a6307b",
    )

    go_repository(
        name = "io_etcd_go_bbolt",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/bbolt",
        sum = "h1:/ecaJf0sk1l4l6V4awd65v2C3ILy7MSj+s/x1ADCIMU=",
        version = "v1.3.6",
    )

    go_repository(
        name = "io_etcd_go_etcd",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/etcd",
        sum = "h1:1JFLBqwIgdyHN1ZtgjTBwO+blA6gVOmZurpiMEsETKo=",
        version = "v0.5.0-alpha.5.0.20200910180754-dd1b699fc489",
    )

    go_repository(
        name = "io_etcd_go_etcd_api_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/etcd/api/v3",
        sum = "h1:v28cktvBq+7vGyJXF8G+rWJmj+1XUmMtqcLnH8hDocM=",
        version = "v3.5.1",
    )

    go_repository(
        name = "io_etcd_go_etcd_client_pkg_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/etcd/client/pkg/v3",
        sum = "h1:XIQcHCFSG53bJETYeRJtIxdLv2EWRGxcfzR8lSnTH4E=",
        version = "v3.5.1",
    )

    go_repository(
        name = "io_etcd_go_etcd_client_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/etcd/client/v2",
        sum = "h1:vtxYCKWA9x31w0WJj7DdqsHFNjhkigdAnziDtkZb/l4=",
        version = "v2.305.1",
    )

    go_repository(
        name = "io_etcd_go_etcd_client_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/etcd/client/v3",
        sum = "h1:62Eh0XOro+rDwkrypAGDfgmNh5Joq+z+W9HZdlXMzek=",
        version = "v3.5.0",
    )

    go_repository(
        name = "io_etcd_go_etcd_pkg_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/etcd/pkg/v3",
        sum = "h1:ntrg6vvKRW26JRmHTE0iNlDgYK6JX3hg/4cD62X0ixk=",
        version = "v3.5.0",
    )

    go_repository(
        name = "io_etcd_go_etcd_raft_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/etcd/raft/v3",
        sum = "h1:kw2TmO3yFTgE+F0mdKkG7xMxkit2duBDa2Hu6D/HMlw=",
        version = "v3.5.0",
    )

    go_repository(
        name = "io_etcd_go_etcd_server_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.etcd.io/etcd/server/v3",
        sum = "h1:jk8D/lwGEDlQU9kZXUFMSANkE22Sg5+mW27ip8xcF9E=",
        version = "v3.5.0",
    )

    go_repository(
        name = "io_k8s_api",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/api",
        sum = "h1:85gnfXQOWbJa1SiWGpE9EEtHs0UVvDyIsSMpEtl2D4E=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_apiextensions_apiserver",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/apiextensions-apiserver",
        sum = "h1:AFDUEu/yEf0YnuZhqhIFhPLPhhcQQVuR1u3WCh0rveU=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_apimachinery",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/apimachinery",
        sum = "h1:fhnuMd/xUL3Cjfl64j5ULKZ1/J9n8NuQEgNL+WXWfdM=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_apiserver",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/apiserver",
        sum = "h1:zNvQlG+C/ERjuUz4p7eY/0IWHaMixRSBoxgmyIdwo9Y=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_cli_runtime",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/cli-runtime",
        sum = "h1:C3AFQmo4TK4dlVPLOI62gtHEHu0OfA2Cp4UVRZ1JXns=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_client_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/client-go",
        sum = "h1:YVWvPeerA2gpUudLelvsolzH7c2sFoXXR5wM/sWqNFU=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_code_generator",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/code-generator",
        sum = "h1:MmDMH74oo8YD4r+KdUzd/VVmXUeXf5u0owLI9wZWP5Y=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_component_base",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/component-base",
        sum = "h1:SziYh48+QKxK+ykJ3Ejqd98XdZIseVBG7sBaNLPqy6M=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_component_helpers",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/component-helpers",
        sum = "h1:zCLeBuo3Qs0BqtJu767RXJgs5S9ruFJZcbM1aD+cMmc=",
        version = "v0.23.4",
    )
    go_repository(
        name = "io_k8s_cri_api",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/cri-api",
        sum = "h1:iXX0K2pRrbR8yXbZtDK/bSnmg/uSqIFiVJK1x4LUOMc=",
        version = "v0.20.6",
    )

    go_repository(
        name = "io_k8s_gengo",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/gengo",
        replace = "k8s.io/gengo",
        sum = "h1:LTfmarWsAxo+qlLq6d4FunAM9ZQSq8i6QI+/btzVk+U=",
        version = "v0.0.0-20211115164449-b448ea381d54",
    )

    go_repository(
        name = "io_k8s_klog",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/klog",
        sum = "h1:Pt+yjF5aB1xDSVbau4VsWe+dQNzA0qv1LlXdC2dF6Q8=",
        version = "v1.0.0",
    )

    go_repository(
        name = "io_k8s_klog_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/klog/v2",
        sum = "h1:bUO6drIvCIsvZ/XFgfxoGFQU/a4Qkh0iAlvUR7vlHJw=",
        version = "v2.30.0",
    )

    go_repository(
        name = "io_k8s_kube_aggregator",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/kube-aggregator",
        sum = "h1:gLk78rGLVfUXCdD14NrKg/JFBmNNCZ8FEs3tYt+W6Zk=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_kube_openapi",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/kube-openapi",
        sum = "h1:E3J9oCLlaobFUqsjG9DfKbP2BmgwBL2p7pn0A3dG9W4=",
        version = "v0.0.0-20211115234752-e816edb12b65",
    )

    go_repository(
        name = "io_k8s_kubectl",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/kubectl",
        sum = "h1:mAa+zEOlyZieecEy+xSrhjkpMcukYyHWzcNdX28dzMY=",
        version = "v0.23.4",
    )
    go_repository(
        name = "io_k8s_kubernetes",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/kubernetes",
        sum = "h1:qTfB+u5M92k2fCCCVP2iuhgwwSOv1EkAkvQY1tQODD8=",
        version = "v1.13.0",
    )

    go_repository(
        name = "io_k8s_metrics",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/metrics",
        sum = "h1:99+9V/J1PuCqwvYFiuiuZcDImTx4SfFFiwsIB0ZTqUQ=",
        version = "v0.23.4",
    )

    go_repository(
        name = "io_k8s_sigs_apiserver_network_proxy_konnectivity_client",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/apiserver-network-proxy/konnectivity-client",
        sum = "h1:KQOkVzXrLNb0EP6W0FD6u3CCPAwgXFYwZitbj7K0P0Y=",
        version = "v0.0.27",
    )

    go_repository(
        name = "io_k8s_sigs_controller_runtime",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/controller-runtime",
        sum = "h1:7YIHT2QnHJArj/dk9aUkYhfqfK5cIxPOX5gPECfdZLU=",
        version = "v0.11.1",
    )

    go_repository(
        name = "io_k8s_sigs_controller_tools",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/controller-tools",
        sum = "h1:iZIz1vEcavyEfxjcTLs1WH/MPf4vhPCtTKhoHqV8/G0=",
        version = "v0.7.0",
    )

    go_repository(
        name = "io_k8s_sigs_gateway_api",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/gateway-api",
        sum = "h1:Tof9/PNSZXyfDuTTe1XFvaTlvBRE6bKq1kmV6jj6rQE=",
        version = "v0.4.1",
    )
    go_repository(
        name = "io_k8s_sigs_json",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/json",
        sum = "h1:fD1pz4yfdADVNfFmcP2aBEtudwUQ1AlLnRBALr33v3s=",
        version = "v0.0.0-20211020170558-c049b76a60c6",
    )

    go_repository(
        name = "io_k8s_sigs_kustomize_api",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/kustomize/api",
        sum = "h1:KgU7hfYoscuqag84kxtzKdEC3mKMb99DPI3a0eaV1d0=",
        version = "v0.10.1",
    )

    go_repository(
        name = "io_k8s_sigs_kustomize_cmd_config",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/kustomize/cmd/config",
        sum = "h1:2GD3+knDaqZo6rSibkc4kKGp8auNBJrGPZQCTWN4Rtc=",
        version = "v0.10.2",
    )

    go_repository(
        name = "io_k8s_sigs_kustomize_kustomize_v4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/kustomize/kustomize/v4",
        sum = "h1:6hgMEo3Gt0XmhDt4vo0FJ0LRDMc4i8JC6SUW24D4hQM=",
        version = "v4.4.1",
    )

    go_repository(
        name = "io_k8s_sigs_kustomize_kyaml",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/kustomize/kyaml",
        sum = "h1:9c+ETyNfSrVhxvphs+K2dzT3dh5oVPPEqPOE/cUpScY=",
        version = "v0.13.0",
    )

    go_repository(
        name = "io_k8s_sigs_structured_merge_diff_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/structured-merge-diff/v3",
        sum = "h1:dOmIZBMfhcHS09XZkMyUgkq5trg3/jRyJYFZUiaOp8E=",
        version = "v3.0.0",
    )

    go_repository(
        name = "io_k8s_sigs_structured_merge_diff_v4",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/structured-merge-diff/v4",
        sum = "h1:bKCqE9GvQ5tiVHn5rfn1r+yao3aLQEaLzkkmAkf+A6Y=",
        version = "v4.2.1",
    )

    go_repository(
        name = "io_k8s_sigs_yaml",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "sigs.k8s.io/yaml",
        sum = "h1:a2VclLzOGrwOHDiV8EfBGhvjHvP46CtW5j6POvhYGGo=",
        version = "v1.3.0",
    )

    go_repository(
        name = "io_k8s_utils",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "k8s.io/utils",
        sum = "h1:ck1fRPWPJWsMd8ZRFsWc6mh/zHp5fZ/shhbrgPUxDAE=",
        version = "v0.0.0-20211116205334-6203023598ed",
    )

    go_repository(
        name = "io_opencensus_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opencensus.io",
        sum = "h1:gqCw0LfLxScz8irSi8exQc7fyQ0fKQU/qnC/X8+V/1M=",
        version = "v0.23.0",
    )

    go_repository(
        name = "io_opentelemetry_go_contrib",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/contrib",
        sum = "h1:ubFQUn0VCZ0gPwIoJfBJVpeBlyRMxu8Mm/huKWYd9p0=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_contrib_instrumentation_google_golang_org_grpc_otelgrpc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc",
        sum = "h1:sO4WKdPAudZGKPcpZT4MJn6JaDmpyLrMPDGGyA1SttE=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_contrib_instrumentation_net_http_otelhttp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp",
        sum = "h1:Q3C9yzW6I9jqEc8sawxzxZmY48fs9u220KXq6d5s3XU=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_otel",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/otel",
        sum = "h1:eaP0Fqu7SXHwvjiqDq83zImeehOHX8doTvU9AwXON8g=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_otel_exporters_otlp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/otel/exporters/otlp",
        sum = "h1:PTNgq9MRmQqqJY0REVbZFvwkYOA85vbdQU/nVfxDyqg=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_otel_metric",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/otel/metric",
        sum = "h1:4kzhXFP+btKm4jwxpjIqjs41A7MakRFUS86bqLHTIw8=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_otel_oteltest",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/otel/oteltest",
        sum = "h1:HiITxCawalo5vQzdHfKeZurV8x7ljcqAgiWzF6Vaeaw=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_otel_sdk",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/otel/sdk",
        sum = "h1:JsxtGXd06J8jrnya7fdI/U/MR6yXA5DtbZy+qoHQlr8=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_otel_sdk_export_metric",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/otel/sdk/export/metric",
        sum = "h1:c5VRjxCXdQlx1HjzwGdQHzZaVI82b5EbBgOu2ljD92g=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_otel_sdk_metric",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/otel/sdk/metric",
        sum = "h1:7ao1wpzHRVKf0OQ7GIxiQJA6X7DLX9o14gmVon7mMK8=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_otel_trace",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/otel/trace",
        sum = "h1:1DL6EXUdcg95gukhuRRvLDO/4X5THh/5dIV52lqtnbw=",
        version = "v0.20.0",
    )

    go_repository(
        name = "io_opentelemetry_go_proto_otlp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.opentelemetry.io/proto/otlp",
        sum = "h1:rwOQPCuKAKmwGKq2aVNnYIibI6wnV7EvzgfTCzcdGg8=",
        version = "v0.7.0",
    )

    go_repository(
        name = "io_rsc_binaryregexp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "rsc.io/binaryregexp",
        sum = "h1:HfqmD5MEmC0zvwBuF187nq9mdnXjXsSivRiXN7SmRkE=",
        version = "v0.2.0",
    )

    go_repository(
        name = "io_rsc_quote_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "rsc.io/quote/v3",
        sum = "h1:9JKUTTIUgS6kzR9mK1YuGKv6Nl+DijDNIc0ghT58FaY=",
        version = "v3.1.0",
    )

    go_repository(
        name = "io_rsc_sampler",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "rsc.io/sampler",
        sum = "h1:7uVkIFmeBqHfdjD+gZwtXXI+RODJ2Wc4O7MPEh/QiW4=",
        version = "v1.3.0",
    )
    go_repository(
        name = "land_oras_oras_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "oras.land/oras-go",
        sum = "h1:tfWM1RT7PzUwWphqHU6ptPU3ZhwVnSw/9nEGf519rYg=",
        version = "v1.1.0",
    )

    go_repository(
        name = "net_starlark_go",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.starlark.net",
        sum = "h1:+FNtrFTmVw0YZGpBGX56XDee331t6JAXeK2bcyhLOOc=",
        version = "v0.0.0-20200306205701-8dd3e2ee1dd5",
    )

    go_repository(
        name = "org_bazil_fuse",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "bazil.org/fuse",
        sum = "h1:SC+c6A1qTFstO9qmB86mPV2IpYme/2ZoEQ0hrP+wo+Q=",
        version = "v0.0.0-20160811212531-371fbbdaa898",
    )

    go_repository(
        name = "org_golang_google_api",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "google.golang.org/api",
        sum = "h1:PhGymJMXfGBzc4lBRmrx9+1w4w2wEzURHNGF/sD/xGc=",
        version = "v0.62.0",
    )

    go_repository(
        name = "org_golang_google_appengine",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "google.golang.org/appengine",
        sum = "h1:FZR1q0exgwxzPzp/aF+VccGrSfxfPpkBqjIIEq3ru6c=",
        version = "v1.6.7",
    )

    go_repository(
        name = "org_golang_google_cloud",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "google.golang.org/cloud",
        sum = "h1:Cpp2P6TPjujNoC5M2KHY6g7wfyLYfIWRZaSdIKfDasA=",
        version = "v0.0.0-20151119220103-975617b05ea8",
    )

    go_repository(
        name = "org_golang_google_genproto",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "google.golang.org/genproto",
        sum = "h1:zzNejm+EgrbLfDZ6lu9Uud2IVvHySPl8vQzf04laR5Q=",
        version = "v0.0.0-20220118154757-00ab72f36ad5",
    )

    go_repository(
        name = "org_golang_google_grpc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "google.golang.org/grpc",
        sum = "h1:Eeu7bZtDZ2DpRCsLhUlcrLnvYaMK1Gz86a+hMVvELmM=",
        version = "v1.43.0",
    )

    go_repository(
        name = "org_golang_google_grpc_cmd_protoc_gen_go_grpc",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "google.golang.org/grpc/cmd/protoc-gen-go-grpc",
        sum = "h1:M1YKkFIboKNieVO5DLUEVzQfGwJD30Nv2jfUgzb5UcE=",
        version = "v1.1.0",
    )

    go_repository(
        name = "org_golang_google_protobuf",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "google.golang.org/protobuf",
        sum = "h1:SnqbnDw1V7RiZcXPx5MEeqPv2s79L9i7BJUlG/+RurQ=",
        version = "v1.27.1",
    )

    go_repository(
        name = "org_golang_x_crypto",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/crypto",
        sum = "h1:/pEO3GD/ABYAjuakUS6xSEmmlyVS4kxBNkeA9tLJiTI=",
        version = "v0.0.0-20211117183948-ae814b36b871",
    )

    go_repository(
        name = "org_golang_x_exp",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/exp",
        sum = "h1:QE6XYQK6naiK1EPAe1g/ILLxN5RBoH5xkJk3CqlMI/Y=",
        version = "v0.0.0-20200224162631-6cc2880d07d6",
    )

    go_repository(
        name = "org_golang_x_image",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/image",
        sum = "h1:+qEpEAPhDZ1o0x3tHzZTQDArnOixOzGD9HUJfcg0mb4=",
        version = "v0.0.0-20190802002840-cff245a6509b",
    )

    go_repository(
        name = "org_golang_x_lint",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/lint",
        sum = "h1:VLliZ0d+/avPrXXH+OakdXhpJuEoBZuwh1m2j7U6Iug=",
        version = "v0.0.0-20210508222113-6edffad5e616",
    )

    go_repository(
        name = "org_golang_x_mobile",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/mobile",
        sum = "h1:4+4C/Iv2U4fMZBiMCc98MG1In4gJY5YRhtpDNeDeHWs=",
        version = "v0.0.0-20190719004257-d2bd2a29d028",
    )

    go_repository(
        name = "org_golang_x_mod",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/mod",
        sum = "h1:UG21uOlmZabA4fW5i7ZX6bjw1xELEGg/ZLgZq9auk/Q=",
        version = "v0.5.0",
    )

    go_repository(
        name = "org_golang_x_net",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/net",
        replace = "golang.org/x/net",
        sum = "h1:OgUuv8lsRpBibGNbSizVwKWlysjaNzmC9gYMhPVfqFM=",
        version = "v0.0.0-20210224082022-3d97a244fca7",
    )

    go_repository(
        name = "org_golang_x_oauth2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/oauth2",
        sum = "h1:RerP+noqYHUQ8CMRcPlC2nvTa4dcBIjegkuWdcUDuqg=",
        version = "v0.0.0-20211104180415-d3ed0bb246c8",
    )

    go_repository(
        name = "org_golang_x_sync",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/sync",
        sum = "h1:5KslGYwFpkhGh+Q16bwMP3cOontH8FOep7tGV86Y7SQ=",
        version = "v0.0.0-20210220032951-036812b2e83c",
    )

    go_repository(
        name = "org_golang_x_sys",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/sys",
        sum = "h1:fLOSk5Q00efkSvAm+4xcoXD+RRmLmmulPn5I3Y9F2EM=",
        version = "v0.0.0-20211216021012-1d35b9e2eb4e",
    )

    go_repository(
        name = "org_golang_x_term",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/term",
        sum = "h1:JGgROgKl9N8DuW20oFS5gxc+lE67/N3FcwmBPMe7ArY=",
        version = "v0.0.0-20210927222741-03fcf44c2211",
    )

    go_repository(
        name = "org_golang_x_text",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/text",
        sum = "h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=",
        version = "v0.3.7",
    )

    go_repository(
        name = "org_golang_x_time",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/time",
        sum = "h1:7zkz7BUtwNFFqcowJ+RIgu2MaV/MapERkDIy+mwPyjs=",
        version = "v0.0.0-20210723032227-1f47c861a9ac",
    )

    go_repository(
        name = "org_golang_x_tools",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/tools",
        sum = "h1:VX/uD7MK0AHXGiScH3fsieUQUcpmRERPDYtqZdJnA+Q=",
        version = "v0.1.6-0.20210820212750-d4cc65f0b2ff",
    )

    go_repository(
        name = "org_golang_x_xerrors",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/xerrors",
        sum = "h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
        version = "v0.0.0-20200804184101-5ec99f83aff1",
    )

    go_repository(
        name = "org_mongodb_go_mongo_driver",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.mongodb.org/mongo-driver",
        sum = "h1:jxcFYjlkl8xaERsgLo+RNquI0epW6zuy/ZRQs6jnrFA=",
        version = "v1.1.2",
    )
    go_repository(
        name = "org_mozilla_go_pkcs7",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.mozilla.org/pkcs7",
        sum = "h1:A/5uWzF44DlIgdm/PQFwfMkW0JX+cIcQi/SwLAmZP5M=",
        version = "v0.0.0-20200128120323-432b2356ecb1",
    )

    go_repository(
        name = "org_uber_go_atomic",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.uber.org/atomic",
        sum = "h1:ADUqmZGgLDDfbSL9ZmPxKTybcoEYHgpYfELNoN+7hsw=",
        version = "v1.7.0",
    )

    go_repository(
        name = "org_uber_go_goleak",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.uber.org/goleak",
        sum = "h1:gZAh5/EyT/HQwlpkCy6wTpqfH9H8Lz8zbm3dZh+OyzA=",
        version = "v1.1.12",
    )

    go_repository(
        name = "org_uber_go_multierr",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.uber.org/multierr",
        sum = "h1:y6IPFStTAIT5Ytl7/XYmHvzXQ7S3g/IeZW9hyZ5thw4=",
        version = "v1.6.0",
    )

    go_repository(
        name = "org_uber_go_zap",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "go.uber.org/zap",
        sum = "h1:ue41HOKd1vGURxrmeKIgELGb3jPW9DMUDGtsinblHwI=",
        version = "v1.19.1",
    )

    go_repository(
        name = "sh_helm_helm_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "helm.sh/helm/v3",
        sum = "h1:J1EzhvtvKJRdx9skjUVe5xPN7KK2VA1mVxiQ9Ic5+oU=",
        version = "v3.8.1",
    )

    go_repository(
        name = "tools_gotest",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gotest.tools",
        sum = "h1:VsBPFP1AI068pPrMxtb/S8Zkgf9xEmTLJjfM+P5UIEo=",
        version = "v2.2.0+incompatible",
    )

    go_repository(
        name = "tools_gotest_v3",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gotest.tools/v3",
        sum = "h1:4AuOwCGf4lLR9u3YOe2awrHygurzhO/HeQ6laiA6Sx0=",
        version = "v3.0.3",
    )

    go_repository(
        name = "xyz_gomodules_jsonpatch_v2",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "gomodules.xyz/jsonpatch/v2",
        sum = "h1:4pT439QV83L+G9FkcCriY6EkpcK6r6bK+A5FBUMI7qY=",
        version = "v2.2.0",
    )
