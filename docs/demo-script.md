# Kịch bản demo (≤ 10 phút)

Theo PROJECT_OVERVIEW.md mục 7. Mọi lệnh chạy trong **terminal Ubuntu (WSL)** với quyền root, ở thư mục
gốc repo. Docker chỉ có trong WSL: lệnh `docker`/`make` gõ trong PowerShell sẽ không chạy.

## Chuẩn bị (trước khi bấm quay, không tính giờ)

```bash
sudo -i                                   # root
cd "/mnt/d/Học Ths/Mạng thế hệ mới"       # thư mục repo (sửa nếu khác)
make up                                   # build + dựng 6 container, chờ tới khi "lab ready"
alias fw='docker exec xdplab-fw-node-1 xdpfw'
IF=$(docker exec xdplab-fw-node-1 cat /run/xdp_iface)   # interface ngoài của fw-node
lab/demo.sh clear                         # bắt đầu không có bộ lọc nào
```

- Mở trình duyệt `http://localhost:3000`: dashboard **XDP Firewall** mở sẵn (không cần đăng nhập).
  Chọn khoảng thời gian "Last 5 minutes".
- Mở sẵn 3 ảnh `results/20261124-200114/*.png` cho bước 6.
- Cắm sạc, tắt ứng dụng nặng: số liệu trên WSL nhạy với tải nền.

`lab/demo.sh watch N` in mỗi giây: số gói **tới fw-node**, số gói **bị drop**, và **CPU toàn hệ thống**
(`%sys+%irq+%soft` cộng cả 8 CPU, thang 0–800). Đây là cùng cách đo với benchmark (research R7: trên
veth, phần xử lý nhận chạy trên CPU của bên gửi, nên phải đo CPU toàn máy chứ không đo riêng fw-node).

---

## Bước 0 — Topology (1')

```bash
make ps
```

Kỳ vọng: 6 service `running` (fw-node, client, attacker, server, prometheus, grafana).
Nói về sơ đồ trong `lab/docker-compose.yml`: client 10.10.1.10 và attacker 10.10.1.66 ở `net_ext`,
server 10.10.2.20 ở `net_int`, fw-node định tuyến giữa hai mạng và gắn XDP lên interface phía `net_ext`.
Grafana: ô trạng thái báo **NOT LOADED**, các đồ thị trống.

## Bước 1 — Traffic hợp lệ (1')

```bash
docker exec xdplab-client-1 curl -s http://10.10.2.20/
docker exec xdplab-client-1 ping -c 3 -q 10.10.2.20
```

Kỳ vọng: `<h1>XDP lab server</h1>`; ping 0% loss, RTT khoảng 0,1 ms.

## Bước 2 — Tấn công flood (1,5')

```bash
lab/demo.sh flood            # attacker bắn UDP 64 B, 200 000 gói/s tới server udp/9999
lab/demo.sh watch 5
```

Kỳ vọng: cột "tới fw" khoảng 200k pps, "drop" = 0 (không có bộ lọc, fw-node chuyển hết gói tới server),
CPU khoảng **85–100**/800.

> Trung thực: ở mức 200k pps trên máy lab, ping của client **gần như không đổi** (Đo 3 trong
> benchmark: RTT p99 < 0,4 ms ở mọi cấu hình). Điểm cần cho người xem thấy là CPU bị tiêu tốn để
> xử lý gói rác, không phải client mất kết nối.

## Bước 3 — Nạp XDP và chặn attacker (2')

```bash
fw load --iface $IF --mode native
fw status                    # mode: native, prog_id
fw block-ip 10.10.1.66/32
lab/demo.sh flood            # khởi động lại flood để trafgen giữ đúng 200k pps (xem ghi chú)
lab/demo.sh watch 5
docker exec xdplab-client-1 curl -s http://10.10.2.20/
```

Kỳ vọng:
- `watch`: "drop" ≈ "tới fw" ≈ 200k pps, CPU giảm còn khoảng **30–40**/800.
- Grafana (refresh 1 s): ô trạng thái **LOADED · native**, đường **drop_ip** vọt lên khoảng 200k pps,
  bảng top rule hiện `10.10.1.66/32`.
- client vẫn tải được trang web.

Ghi chú: trafgen không giữ đúng tốc độ khi chi phí phía nhận thay đổi giữa chừng, nên sau khi đổi bộ lọc
cần chạy lại `lab/demo.sh flood`. 1–2 giây đầu của `watch` có thể cao hơn 200k (trafgen bù gói).

## Bước 4 — Đổi rule lúc đang chạy (1')

```bash
fw block-port tcp 8080
fw list                      # 2 rule, cột PACKETS của 10.10.1.66/32 đang tăng
fw stats                     # pass / drop_ip / drop_port / parse_err
docker exec xdplab-client-1 curl -s http://10.10.2.20/   # vẫn qua: rule chỉ chặn tcp/8080
fw unblock-port tcp 8080
```

Kỳ vọng: rule thêm/xóa có hiệu lực ngay, không phải nạp lại chương trình, flood vẫn bị drop liên tục
(Grafana không có khoảng trống).

## Bước 5 — So sánh với iptables (2')

```bash
lab/demo.sh use ipt-legacy-filter        # gỡ XDP, cài 1 rule DROP trong iptables filter FORWARD
lab/demo.sh watch 5                      # CPU khoảng 45–50/800, cao hơn XDP

lab/demo.sh use ipt-legacy-filter 10000  # 10 000 rule, rule khớp attacker đặt cuối
lab/demo.sh watch 5                      # chỉ còn khoảng 16k pps, CPU bão hòa ~100/800

lab/demo.sh use xdp-native 10000         # cùng 10 000 rule trên XDP (LPM trie)
lab/demo.sh watch 5                      # trở lại ~200k pps, CPU khoảng 40–45/800
```

`use` tự khởi động lại flood. Kỳ vọng: iptables duyệt rule tuần tự nên sụp ở 10 000 rule; XDP tra
LPM trie nên gần như không đổi. Nói thêm: với 1 rule, iptables bảng **raw** tốn CPU ngang XDP trên
veth (Đo 1), lý do ở bước 6.

```bash
lab/demo.sh stop
lab/demo.sh clear
```

## Bước 6 — Kết quả benchmark và hạn chế (1,5')

Trình bày 3 ảnh trong `results/20261124-200114/`:

- `drop_cost.png` — Đo 1: chi phí drop với 1 rule.
- `rule_scaling.png` — Đo 2: mở rộng theo số rule.
- `legit_impact.png` — Đo 3: ảnh hưởng tới traffic hợp lệ.

Các hạn chế cần nêu (PROJECT_OVERVIEW.md mục 12 và README mục Hạn chế): veth trên WSL2 khiến lợi thế
"drop trước khi cấp phát skb" của XDP không xuất hiện; XDP native trên veth làm mất GRO/TSO (throughput
TCP hợp lệ khoảng 3,5 Gbit/s so với khoảng 30 Gbit/s); số liệu chỉ có giá trị so sánh tương đối.

---

| Bước | Thời lượng | Tổng |
|---|---|---|
| 0 Topology | 1' | 1' |
| 1 Traffic hợp lệ | 1' | 2' |
| 2 Flood | 1,5' | 3,5' |
| 3 XDP chặn | 2' | 5,5' |
| 4 Đổi rule | 1' | 6,5' |
| 5 So sánh iptables | 2' | 8,5' |
| 6 Biểu đồ, hạn chế | 1,5' | **10'** |
