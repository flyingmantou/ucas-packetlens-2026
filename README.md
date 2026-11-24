# PacketLens · 实验 1A

PacketLens 是一个带图形界面的网络嗅探器。它可以从本机网络接口实时抓包（NPS），也可以打开已有的 PCAP 文件，分析协议、筛选报文和追踪 TCP 流（NPA）。

## 从 GitHub 下载到另一台电脑

在新电脑的浏览器登录有权访问此私有仓库的 GitHub 账号，打开[项目首页](https://github.com/flyingmantou/ucas-packetlens-2026)，点击绿色 **Code → Download ZIP**，或直接[下载 main 分支的源码 ZIP](https://github.com/flyingmantou/ucas-packetlens-2026/archive/refs/heads/main.zip)。使用 Git 的同学也可以执行 `git clone https://github.com/flyingmantou/ucas-packetlens-2026.git`，按提示用已获授权的账号登录。

完整解压 ZIP，打开同时包含本说明和 `run.py` 的文件夹。程序、课程样例和实抓样本都在包里。新电脑需要有桌面环境，并安装带 Tkinter 的 Python 3.12。若使用本地便携源码包，解压后的启动步骤相同。

## Windows 快速启动

在解压后的文件夹地址栏输入 `powershell` 并回车，然后运行：

```powershell
py -3.12 run.py --open samples/course-demo.pcap
```

窗口打开后应能看到课程样例中的报文。离线演示只需要 Python 和 Tkinter，未安装 Npcap 也可以进行。如果系统找不到 `py`，而 `python --version` 显示 3.12，可将命令开头的 `py -3.12` 换成 `python`。运行 `py -3.12 -m tkinter` 可以单独检查图形环境。[Python 的 Tkinter 说明](https://docs.python.org/3.12/library/tkinter.html)

**演示协议分析（NPA）。** 从「文件 → 打开 Linux 实测 PCAP」载入随包附带的真实抓包记录。在「显示过滤」输入 `http` 并点击「应用」，选中一条 HTTP 报文，再点「追踪 TCP 流」。窗口中可以读到请求 `GET /live-proof HTTP/1.1` 和响应 `HTTP/1.1 200 OK`。

要演示 TLS 握手，可点「文件 → 打开课程示例」，在「显示过滤」输入 `tls.sni == "www.ucas.ac.cn"`，点击「应用」并选中报文，在 TLS 详情中查看域名、ALPN 和 JA3 指纹。

**演示实时抓包（NPS）。** 先在这台 Windows 电脑上安装 Npcap，再重新打开 PacketLens。选择正在使用的 Wi-Fi 或以太网卡，点「开始抓包」，用浏览器访问一个网页，观察报文列表，再点「停止」。如果安装 Npcap 时选择了仅管理员可用，抓包时需要管理员授权。[Npcap 官方安装说明](https://npcap.com/guide/npcap-users-guide.html)

**需要显示本机进程时**，在同一文件夹运行以下命令，再用虚拟环境中的 Python 启动程序。安装的 `psutil` 用于将实时 TCP 连接匹配到进程。普通 PCAP 文件里没有历史进程号。

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run.py
```

## macOS 或 Linux

在有桌面环境的电脑上，进入源码目录后执行：

```sh
python3.12 run.py --open samples/course-demo.pcap
```

如果 Python 3.12 的命令是 `python3`，可用 `python3` 替换。实时抓包还需要系统提供 libpcap，并允许当前用户访问选定的网络接口。

## 已验证的范围

| 版本和环境 | 实际结果 |
| --- | --- |
| 11 月 24 日，Windows 11，源码 [`7e56399`](https://github.com/flyingmantou/ucas-packetlens-2026/commit/7e56399da2198eb7e6d30675b5524c08093f3019) | Python 3.12.3、Npcap 1.60。[66 项自动化测试](evidence/windows-2026-11-24/test-results.json)全部通过，跳过 0 项。图形界面载入课程样例后显示 31 个报文，应用 `http` 过滤后显示 2 个。 |
| 11 月 24 日源码，macOS | 本机 62 项自动化测试全部通过。 |
| 11 月 19 日版本，Windows | 56 项中 55 项通过。测试机未安装 Npcap，跳过了 1 项依赖它的原生过滤器测试。 |
| 11 月 19 日版本，Linux | 在回环接口实际抓到 12 个报文。该记录保存在 `evidence/live-loopback.pcap`，可在其他系统离线打开。 |

Windows 回环接口捕获了 13 个自生成的报文。回放时可在同一条 TCP 流中看到 `GET /live-proof HTTP/1.1` 请求和 `HTTP/1.1 200 OK` 响应。UDP 往返、进程归属和正常停止检查均通过，内核和程序队列丢包数均为 0。[实抓记录](evidence/windows-2026-11-24/live-results.json) · [原始 PCAP](evidence/windows-2026-11-24/live-loopback.pcap)

要在目标机复核自动化用例，可运行 `py -3.12 scripts/run_tests.py`（macOS 或 Linux 使用 `python3.12`）。[跨平台测试记录](https://github.com/flyingmantou/ucas-packetlens-2026/actions/runs/44474335061)
