# Synapse — 常用开发入口。纯标准库，无需 pip 安装任何东西。
.PHONY: help test check dist clean run version smoke

PY ?= python3
VERSION := $(shell awk '/^Version:/{print $$2}' packaging-src/DEBIAN/control)

help:                    ## 列出所有目标
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

test:                    ## 跑回归测试(不联网, 含资源泄漏检查)
	$(PY) -W error::ResourceWarning -m unittest discover -s tests -v

check:                   ## 语法 + 编译 + 测试, 提交前跑这个
	$(PY) -m compileall -q synapse.py synapse_classify.py synapse_probe.py tests >/dev/null
	$(PY) -W error::ResourceWarning -m unittest discover -s tests

smoke:                   ## 用临时数据目录跑一遍真实 CLI(不碰你的配置)
	@tmp=$$(mktemp -d); \
	printf '{"targets":{"demo":{"base_url":"https://example.invalid","api_key":"sk-demo","models":["m1"]}}}' > $$tmp/config.json; \
	SYNAPSE_HOME=$$tmp $(PY) synapse.py --version; \
	SYNAPSE_HOME=$$tmp $(PY) synapse.py check --json --target demo 2>/dev/null | $(PY) -c 'import json,sys; print("JSON OK", json.load(sys.stdin)["summary"])'; \
	rm -rf $$tmp

dist: check              ## 打 deb(先跑测试, 测试不过不许出包)
	bash build-deb.sh

version:                 ## 显示当前版本
	@echo "synapse $(VERSION)"

run:                     ## 直接跑源码版
	$(PY) synapse.py status

clean:                   ## 清理生成物
	rm -rf packaging/ dist/ __pycache__ tests/__pycache__ ./*.pyc
