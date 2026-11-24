# XDP firewall lab — chạy trong Linux/WSL2 với quyền root (hoặc sudo).
# Xem specs/001-xdp-firewall/quickstart.md

COMPOSE := docker compose -f lab/docker-compose.yml
FW      := docker exec xdplab-fw-node-1
BUILDER := xdplab/builder:latest

.PHONY: help prereq build builder up down ps logs shell-fw test-unit test-bpf test bench plot clean

help:
	@echo "make up | down | ps | shell-fw | test-unit | test-bpf | test | bench [QUICK=1] | plot | clean"
	@echo "demo: bash lab/demo.sh   (xem docs/demo-script.md)"

## Nạp các module kernel mà lab và benchmark cần (container không tự modprobe được).
prereq:
	@for m in ip_tables iptable_raw iptable_filter nf_tables br_netfilter; do \
		modprobe $$m || { echo "modprobe $$m failed"; exit 1; }; done
	@echo "prereq: kernel modules ok"

build:
	$(COMPOSE) build

## Sau khi Docker tạo mạng: tắt br_netfilter cho iptables. Nếu để =1, iptables của
## host xử lý cả frame đi qua bridge, và rule DOCKER-INTERNAL của mạng internal sẽ
## drop gói client->server (đích khác subnet). Docker bật lại =1 mỗi khi tạo mạng
## nên phải đặt SAU `compose up` (research.md R6).
up: prereq build
	$(COMPOSE) up -d
	sysctl -qw net.bridge.bridge-nf-call-iptables=0 net.bridge.bridge-nf-call-ip6tables=0 net.bridge.bridge-nf-call-arptables=0
	@$(COMPOSE) ps
	@bash lab/wait-ready.sh

## Gỡ XDP trước (bỏ qua lỗi nếu chưa nạp) rồi xóa container + mạng.
down:
	-@$(FW) xdpfw unload 2>/dev/null
	$(COMPOSE) down -v --remove-orphans

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs --tail=50

shell-fw:
	$(FW) bash

## Unit test thuần Go (không cần quyền).
test-unit: builder
	docker run --rm -v "$(CURDIR)":/src -w /src $(BUILDER) sh -c 'go generate ./... && go test ./internal/parse/...'

## Test chương trình XDP bằng BPF_PROG_TEST_RUN (cần privileged), không cần lab.
test-bpf: builder
	docker run --rm --privileged -v "$(CURDIR)":/src -w /src $(BUILDER) \
		sh -c 'go generate ./... && go test -tags bpftest -count=1 -v ./internal/...'

## Functional test trên lab đang chạy (US1/US2 acceptance scenarios).
test:
	bash tests/functional.sh

bench:
	bash bench/run_bench.sh $(if $(QUICK),--quick,)

plot:
	python3 bench/plot.py

builder:
	docker build -q --target builder -t $(BUILDER) -f lab/fw-node/Dockerfile . >/dev/null

clean:
	rm -f internal/bpfobj/*_bpfel.go internal/bpfobj/*_bpfel.o
