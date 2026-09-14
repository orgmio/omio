# The MIO proxy protocol

一个快速、隐私、跨平台、开源的代理协议概念验证。

## 🚀 特性

- Chrome TLS：[utls](https://github.com/refraction-networking/utls) `HelloChrome_Auto`
- 证书：像 Reality 一样借用 `dest` 站点，不用自签
- 认证：密码派生 X25519，握手失败就转发给 dest
- 速度：支持自动升降级HTTP/3，大幅度提升高丢包环境下的速度。在HTTP/3不可用时自动退回2或1.1。

## ⚙️ 构建

```bash
go build
```

## ⚖️ 条款与授权

此项目基于[Mo Public License](https://867678.xyz/docs/mopl)授权

引用的其他项目使用他们的许可条款