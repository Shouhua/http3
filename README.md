## 关于
本工程是兴趣使然，试验HTTP3协议各种特性，依赖quictls, ngtcp2, nghttp3, 目前实现了HTTP3客户端，目前忙于找工作，暂时没有时间整服务端，服务端可以使用各种支持HTTP3协议的web站点或者自己编译[最新的nginx](https://juejin.cn/post/7348299792122118181)。后面可能集成到[mujs](https://github.com/Shouhua/mujs)的运行时环境。目前已实现的特性包括：
1. 支持 `SSLKEYLOGFILE` 环境变量输出密钥文件用于比如`wireshark`调试, 设置后生成 `keylog.txt` 文件
2. 使用`\k` 命令手动 **`Key Update`**
3. 使用 `\c` 命令模拟 **`Connection Migration`**
4. 支持 **Early Data**, 会生成本地`quic_transport_paramter.pem`文件和`quic_session.pem`文件，前者保存`QUIC`协议相关参数，后者保存`QUIC session`相关参数。使用 `--disable-early-data` 禁止。
5. HTTP3 request and response(Of Course).
6. 支持证书校验，打印证书链

## 编译运行
1. 编译依赖库 `quictls`, `ngtcp2`, `nghttp3`

可以参考curl库的编译页面 https://curl.se/docs/http3.html  
一些问题可以参考我整理的博客 https://juejin.cn/column/7367753873892737043  

2. 编译&&运行client

直接运行`make http3`就行, 详情见Makefile, 注意里面依赖库编译参数
