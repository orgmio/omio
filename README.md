# OMIO

一个简易的跨平台、强伪装、高性能代理协议实现

该项目已被放弃并更名OMIO 新项目地址:<https://github.com/orgmio/mio>

This project was given up , To get the latest version, please visit <https://github.com/orgmio/mio>

# 🚀 项目特点

- 抗审查
- 速度快
- 多平台通用
- 部署简单

## 📚 项目文档

### ⚙️ 如何使用

安装（mio是通用的，具体请查看示例配置文件）

```bash
cd /usr/bin
wget -O mio https://github.com/orgmio/omio/releases/latest/download/mio-⚠️OS-⚠️archoptimize-⚠️LibC(option)
chmod +x ./mio
cd /etc/
mkdir -p /etc/mio
touch /etc/mio/config.toml
chmod 755 /etc/mio/*
```

启动服务端：

```bash
./mio -c example-server.toml
```

启动客户端：

```bash
./mio -c example-client.toml
```

如果配置文件叫做`config.toml`那么可以直接执行二进制文件

### ⚙ 作为systemd服务运行

```bash
cat <<'EOF'> /usr/lib/systemd/system/mio.service
[Unit]
Description=mio service
Documentation=https://867678.xyz/projects/omio
After=network.target nss-lookup.target network-online.target
[Service]
Type=simple
WorkingDirectory=/etc/mio
ExecStart=/usr/bin/mio server -c /etc/mio/config.toml
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl start mio
systemctl status mio # 显示running即为成功
systemctl enable mio # 可选 开机自启动
```

### ⬆️ 更新

```bash
cd /usr/bin
rm ./mio
wget -O mio https://github.com/orgmio/omio/releases/latest/download/mio-⚠️OS-⚠️archoptimize-⚠️LibC(Option)
chmod +x ./mio
systemctl restart mio
```

## ⚠️ 安全性警告

为了配置的方便mio使用一个名为HMAC的TLSClientHello字段进行握手验证

这个字段一般是随机的所以很好藏密钥，不过需要稍微长一点才有安全性

下列是一个推荐的示例用openssl生成符合要求的密码

```bash
openssl rand -hex 32
```

这里以HMAC`（RFC2104）`的规范为例
| 长度 单位：字节 | 安全性 |
| ---- | ---- |
| 16 | 刚达到不那么容易破解的临界点 |
| 32 | 现代暴力破解工具一般没辙 |
| 64 | 刚好卡在HMAC的临界点 超过就会被SHA256压缩成32字节 |

`sni`字段必须是一个支持TLS1.3的HTTPS URL，因为需要偷他的证书(没错这是类Reality)，端口可以任意。

## 🏃 协议行为

协议行为旨在模拟`caddy-real/`下存在的wireshark抓包文件

这个文件夹下是由wireshark抓包的真实brave访问真实caddy的行为

客户端行为旨在模拟ArchLinux源`extra`中带的`Brave`浏览器的无痕模式

只要在公网传输的数据包与wireshark抓到的真实行为无异此项目就算成功

- **way-mio.pcapng**:我前前后后用他访问了些正常的网站用于测试伪装程度
- **way-brave-caddy-baidu.pcapng**:brave访问一个反代了百度的caddy的行为 配置文件在Caddyfile

需注意local.867678.xyz没有真正的权威指向 这是我用来测试的

> How it works:

首先客户端会发送魔改的TLS握手字段，把修改过的HMAC值藏在TLSClientHello中

服务端接收到这个ClientHello之后，会根据服务端的配置文件进行比较，如果认证成功，后面会走一个魔改的TLS加密隧道

如果认证不成功，连接将被无脑转发给`sni`字段，有效防止主动探测

然后通信双方开始进行HTTP/1.1通信，为了让服务端看起来就是伪装域名的服务器，他修改了utls模块，伪装自己是caddy

与Reality自己通过私有Key和ShortID生成假证书进行连接不同，mio则是直接将伪装域名的证书返回，服务端不需要看证书，服务端直接对比HMAC字段

客户端的行为也在尝试伪装自己是Brave，虽然肯定不能像navie那样做到100%伪装，但是我们也实现了一样的JA3指纹

为了提供高性能，协议会在HTTP/1.1连接成功建立后一段时间尝试升级到HTTP/3

如果成功，后续都将走HTTP/3协议进行连接，QUIC提供了强抗丢包和强伪装性

如果不成功或HTTP/3一段时间后被阻断，后续将持续尝试升级成HTTP/3协议

流量控制方面，我希望实现一个用户态的BBR，但ChatGPT表示这额度不够（悲）但还是生成了cubic流控（笑）

### 🤝 参考指纹和握手动作

这是真实抓包真正的客户端访问真正的服务端的抓包文件

为了做到1:1指纹这是必不可少的

brave访问caddy反代的百度:`https://r2.867678.xyz/pcap/way-brave-caddy-baidu.pcapng`

mio:`https://r2.867678.xyz/pcap/way-mio.pcapng`

## 🔩 开发

开发使用的配置文件可以在项目根目录新建一个叫做`config.toml`的配置文件，caddy可以直接放在`caddy-real/`目录 Git已忽略他们

初始化环境（假设你用archlinux）

```bash
sudo pacman -Syyuu --needed wget git
git clone git@github.com:orgmio/mio.git
wget -O config.toml https://raw.githubusercontent.com/orgmio/mio/refs/heads/main/example-client.toml
cd caddy-real
wget https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz
tar -xzvf caddy_2.11.4_linux_amd64.tar.gz
rm ./caddy_2.11.4_linux_amd64.tar.gz ./LICENSE ./README.md
chmod +x ./caddy
cd ..
```

测试真brave访问真caddy（需要开好几个窗口）

需要确保你在项目根目录下且执行完毕初始化环境

```bash
sudo pacman -Syyuu --needed brave-bin wireshark-qt
echo "local.867678.xyz 127.0.0.1" >> /etc/hosts
# 启动caddy
cd caddy-real
sudo ./caddy run
# 如果是第一次跑，请打开一个新窗口下列命令
sudo ./caddy trust
# 启动brave
mkdir -p /tmp/brave-guest
brave --user-data-dir=/tmp/brave-guest
# 启动wireshark抓包
sudo wireshark
# 过滤目标
tls.handshake.extensions_server_name == "local.867678.xyz"
# 访问 local.867678.xyz即可
```

测试mio协议

在客户端 mio项目根目录上：

```bash
go run .
```

在服务端：

```bash
touch config.toml
wget -O mio https://github.com/orgmio/mio/releases/latest/download/mio-⚠️OS-⚠️archoptimize-⚠️LibC(Option)
chmod +x ./mio
./mio
```

抓包和过滤目标的方法与brave中的示例相同

# ⚖️ 条款与授权

该项目以GNU AFFERO GENERAL PUBLIC LICENSE v3授权 详细参见LICENSE

如果您希望二次开发或集成到其他代理工具如xray中，也可以指定一个AGPL或GPL v3.0或更高版本

另外 本项目魔改了quic-go和utls库 在此项目的./utls-mio和./quic-mio目录下

前者是MIT所以可以变成AGPL-v3;后者需要附上一封版权声明，我们将他附到了LICENSE的下面
