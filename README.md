# Knowledge Base 慢雾安全团队知识库

`慢雾科技`：https://www.slowmist.com
`慢雾区`：https://www.slowmist.io

`我们在努力成为区块链世界的“安全基础设施”。未知的才是有趣的，已知的如果不分享将会变得索然无味。`

## 目录
- [Knowledge Base 慢雾安全团队知识库](#knowledge-base-慢雾安全团队知识库)
  - [目录](#目录)
  - [基础研究](#基础研究)
    - [EOS Security of SlowMist](#eos-security-of-slowmist)
      - [EOS 攻击手法分析](#eos-攻击手法分析)
  - [翻译资料](#翻译资料)
  - [开放报告](#开放报告)
  - [思维导图](#思维导图)
  - [技术分析](#技术分析)
    - [DeFi 攻击手法分析](#defi-攻击手法分析)
    - [链上追踪技术分析](#链上追踪技术分析)
    - [其他区块链技术分析](#其他区块链技术分析)
    - [:fire: 针对数字货币交易平台充值入账的攻击手法](#fire-针对数字货币交易平台充值入账的攻击手法)
  - [其他资料](#其他资料)

## 基础研究
Basic research of blockchain security, include: `Bitcoin`, `Monero`, `Ethereum`, `EOS` and other top blockchains.

* [Paper of SlowMist](https://github.com/slowmist/papers)
* [Threat Intelligence of SlowMist](https://slowmist.io/disclosure/)
* [Public topic of SlowMist HackingTime](https://github.com/slowmist/HackingTime_Public)
* [Ontology Triones Service Node security checklist](https://github.com/slowmist/Ontology-Triones-Service-Node-security-checklist)
* [vechain core nodes security checklist](https://github.com/slowmist/vechain-core-nodes-security-checklist)
* [:fire: cryptocurrency security](https://github.com/slowmist/cryptocurrency-security)
* [:fire: Blockchain-dark-forest-selfguard-handbook](https://github.com/slowmist/Blockchain-dark-forest-selfguard-handbook)
* [Open of SlowMist](https://github.com/slowmist/)

### EOS Security of SlowMist

* [EOS 超级节点安全执行指南](https://github.com/slowmist/eos-bp-nodes-security-checklist)
* [EOS 超级节点安全审计方案](https://github.com/slowmist/eos-bp-nodes-security-checklist/blob/master/audit.md)
* [EOS 智能合约最佳安全开发指南](https://github.com/slowmist/eos-smart-contract-security-best-practices)
* [EOS 天眼(EOS MonKit)](https://eos.slowmist.io/)
* [FireWall.X — 强大的 EOS 智能合约防火墙](https://firewallx.io/) & [FireWall.X GitHub](https://github.com/firewall-x)

#### EOS 攻击手法分析
慢雾安全团队对 EOSIO 生态的各类新型攻击手法进行分析，如下是分析文章。
* :pushpin: [EOS 回滚攻击手法分析之黑名单篇](https://mp.weixin.qq.com/s/WyZ4j3O68qfN5IOvjx3MOg)
* [EOS 回滚攻击手法之重放篇](https://mp.weixin.qq.com/s/gqzkBTxKf7kwL5OgCtMgvQ)
* [EOS 新型攻击手法之 hard_fail 状态攻击](https://mp.weixin.qq.com/s/qsqqPB24fEjBgnq3Xr3xjQ)
* [EOS 假充值\(hard_fail 状态攻击\)红色预警细节披露与修复方案](https://mp.weixin.qq.com/s/fKINfZLW65LYaD4qO-21nA)
* [随机数之殇 — EOS 新型随机数攻击手法技术分析](https://mp.weixin.qq.com/s/6qb6nYLIUeUJViaFgHVX_A)
* :pushpin: [EOS DApp 现新型交易排挤攻击及通用防御建议](https://mp.weixin.qq.com/s/1-SvoY-kNhH2YllNZdKyOA)

## 翻译资料

Some translated blockchain security documents.

* [DASP Top10 中文版](./translations/DASP-top10-chinese.pdf)
* [Solidity 安全：已知攻击方法和常见防御模式综合列表](./translations/solidity-security-comprehensive-list-of-known-attack-vectors-and-common-anti-patterns_zh-cn.md)
* [全面解析公共区块链系统攻击面](./translations/Exploring-the-Attack-Surface-of-Blockchain-A-Systematic-Overview/Exploring-the-Attack-Surface-of-Blockchain-A-Systematic-Overview_zh-cn.md)

## 开放报告

Some open security audit reports of SlowMist.
- [Open Security Audit Report](./open-report-V2/README.md)
  * [Blockchain Security Audit Report](./open-report-V2/blockchain/)
  * [Blockchain Application Security Audit Report](./open-report-V2/blockchain-application/)
  * [Smart Contract Security Audit Report](./open-report-V2/smart-contract/)

## 思维导图

Some mind maps of blockchain security.

* [DApp Attack & Defense](./mindmaps/dapp_attack_defense.png)
* [Exchange or Wallet Attack & Defense](./mindmaps/exchange_wallet_attack_defense.png)
* [Evil Blockchain & how to be evil](./mindmaps/evil_blockchain.png)

## 技术分析
### DeFi 攻击手法分析
慢雾安全团队对各类 DeFi 被黑事件保持紧密跟进，并及时对其攻击手法进行分析，如下是慢雾安全团队对攻击事件的手法的剖析文章。
* :pushpin: [慢雾：详解 DeFi 协议 bZx 二次被黑](https://mp.weixin.qq.com/s/XTMdy826NTRarKY3wVIdog)
* :pushpin: [慢雾：IOTA 重大被盗币事件的分析与安全建议](https://mp.weixin.qq.com/s/z7LWitwQAm707xQ7FIJrRw)
* :pushpin: [慢雾：DeFi平台Lendf.Me被黑细节分析及防御建议](https://mp.weixin.qq.com/s/tps3EvxyWWTLHYzxsa9ffw)
* :pushpin: [慢雾协助：Lendf.Me 黑客攻击事件真相还原](https://mp.weixin.qq.com/s/ZH8_sKq-_E-sYDC21p2juA)
* :pushpin: [慢雾：详解 Uniswap 的 ERC777 重入风险](https://mp.weixin.qq.com/s/2ElVUSrk-heV9mpFIwnDhg)
* :pushpin: [慢雾：VETH 合约被黑分析](https://mp.weixin.qq.com/s/uOPrpIt8DDIIPzN-RBODGg)
* :pushpin: [慢雾：Balancer 第一次被黑详细分析](https://mp.weixin.qq.com/s/sESfNRLN66w2OnFjs_PMuA)
* [慢雾：Opyn 合约被黑详细分析](https://mp.weixin.qq.com/s/t5RSYdvNc1rtJzSdlCYK2w)
* :pushpin: [DeFi YAM，一行代码如何蒸发数亿美元？](https://mp.weixin.qq.com/s/21lGo_f7HaVSNm98KRO0gg)
* [慢雾：YFValue，一行代码如何锁定上亿资产](https://mp.weixin.qq.com/s/AHlUwg140Z-WQJufkNTEzg)
* [慢雾：DeFi Saver 用户的 31 万枚 DAI 是如何被盗的？](https://mp.weixin.qq.com/s/bkjMFdI_bbfZZj6m6G6yBQ)
* [慢雾：Harvest.Finance 被黑事件简析](https://mp.weixin.qq.com/s/Qhh4c70Nmi6rs_JnNJXKiQ)
* [无中生有？DeFi 协议 Akropolis 重入攻击简析](https://mp.weixin.qq.com/s/WhRJ9Xt3mJCBwe2i4fOXZw)
* [Value DeFi 协议闪电贷攻击简要分析](https://mp.weixin.qq.com/s/ozmtoMQUQpM2rG42SlReHA)
* [闪电贷+重入攻击，OUSD 损失 700 万美金技术简析](https://mp.weixin.qq.com/s/rLJPpZ3BIiD0qW5M-UgNmA)
* [假钱换真钱，揭秘 Pickle Finance 被黑过程](https://mp.weixin.qq.com/s/H5DbJvCxnNNmcflJBfvbUg)
* :pushpin: [以小博大，简析 Sushi Swap 攻击事件始末](https://mp.weixin.qq.com/s/-Vp9bPSqxE0yw2hk_yogFw)
* [采用延时喂价还被黑？Warp Finance 被黑详解](https://mp.weixin.qq.com/s/ues5U9Bl971hSqGO1a4SYA)
* [Cover 协议被黑简要分析](https://mp.weixin.qq.com/s/zdW9fM3Sbz3PLbux4aGmFg)
* :pushpin: [简析 SushiSwap 第二次被攻击始末](https://mp.weixin.qq.com/s/CUholEeD8AWL15psz1-9tQ)
* :pushpin: [yearn finance 被黑简析](https://mp.weixin.qq.com/s/_0Q3-rXBRGxViZbxH6Wsbg)
* [简析 Alpha Finance & Cream被黑](https://mp.weixin.qq.com/s/amTcgpTNh4cAS5LKGMN0gA)
* [可避天灾，难免人祸 —— Furucombo 被黑分析](https://mp.weixin.qq.com/s/74Zv0TBJ3hLIZPUWDkiT4Q)
* [铸币疑云 —— Paid Network 被盗细节分析](https://mp.weixin.qq.com/s/iw4GdF1KbPmlQOm8Z3qrFA)
* :pushpin: [狸猫换太子 —— DODO 被黑分析](https://mp.weixin.qq.com/s/1OrH7Ucqyt9sl7lkBBmb_g)
* [开心做聚合，无奈被攻击 —— Rari 被黑事故分析](https://mp.weixin.qq.com/s/0Lwjf14hW5ahz3Om6jXRug)
* [代币闪崩，差点归零 - PancakeBunny 被黑简析](https://mp.weixin.qq.com/s/O2j5OyUh2qJZSRhnMD5KTg)
* [我竟骗了我自己？—— BurgerSwap 被黑分析](https://mp.weixin.qq.com/s/p16-rCxvqQaxj3SWvw0hXw)
* [走过最长的路，竟是自己的套路 —— Alchemix 事件分析](https://mp.weixin.qq.com/s/Stb5dwoTx75k43Vmmn5ZIQ)
* [“不可思议” 的被黑之旅 —— Impossible Finance 被黑分析](https://mp.weixin.qq.com/s/CXqGxmXEJ4DeSYb8qv8vVw)
* [强扭的瓜不甜 —— SafeDollar 被黑分析](https://mp.weixin.qq.com/s/3_qOkt6rlp1seRlu6L1Hfg)
* [梅开二度 —— PancakeBunny 被黑分析](https://mp.weixin.qq.com/s/f2kD_l9Cs1mHQXBQYemwvQ)
* [又一经典的闪电贷套利 —— Wault.Finance 被黑事件分析](https://mp.weixin.qq.com/s/aFSnSDPk4RYlcKz6Qr_CmQ)
* [空手套白狼 —— Popsicle 被黑分析](https://mp.weixin.qq.com/s/O6gJeXVgYqodTXyh8h9FFg)
* :pushpin: [被黑 6.1 亿美金的 Poly Network 事件分析与疑难问答](https://mp.weixin.qq.com/s/5ogP1v7fJsJnlLuUs6lzlg)
* [权利的游戏 —— DAO Maker 被黑分析](https://mp.weixin.qq.com/s/N-afjgJD3R3JhlcrFxx12A)
* :pushpin: [慢雾：Cream Finance 被黑简要分析](https://mp.weixin.qq.com/s/a9s61_u30f4X8310A952_Q)
* [Zabu Finance 被黑分析](https://mp.weixin.qq.com/s/fR5dVzpaoggwgGMyUih-ug)
* :pushpin: [天价手续费分析：我不是真土豪](https://mp.weixin.qq.com/s/PN7UwkRA4jaxkK-93xPlHw)
* :pushpin: [DeFi 平台 Cream Finance 再遭攻击，1.3 亿美金被盗](https://mp.weixin.qq.com/s/ykz63ZtfbObwRs3UTE3toQ)
* [（更新）老调重弹 —— “通缩型代币” 兼容性问题](https://mp.weixin.qq.com/s/rdh3DyKG5peJvPBgriA8bg)
* :pushpin: [千万美元被盗 —— DeFi 平台 MonoX Finance 被黑分析](https://mp.weixin.qq.com/s/s0tO1aqOKGlRcXjyZFU_3Q)
* [环环相扣 —— Gnosis Safe Multisig 用户被黑分析](https://mp.weixin.qq.com/s/3KHnPNap7hMBbhkENUOAMg)
* :pushpin: [8000 万美元不翼而飞 —— QBridge 被黑简析](https://mp.weixin.qq.com/s/PLbuI9JFxyFRlDlj9rPvmQ)
* [重建世界：The Sandbox 任意燃烧漏洞回顾](https://mp.weixin.qq.com/s/UECwAt_p8rXn-3kZ4kC2VQ)
* [“零元购” —— TreasureDAO NFT 交易市场漏洞分析](https://mp.weixin.qq.com/s/SEbXWmugJBz0C00vyzYcCw)
* [大意失荆州 —— Paraluni 被黑分析](https://mp.weixin.qq.com/s/a5fFI5sFNAyuDxGqTFmC2A)
* [故技重施 —— Hundred Finance 被黑分析](https://mp.weixin.qq.com/s/tlXn3IDSbeoxXQfNe_dH3A)
* [慢雾：OneRing Finance 被黑分析](https://mp.weixin.qq.com/s/MyR_O8wuZJUT1S6eIMH9TA)
* [Jet Protocol 任意提款漏洞](https://mp.weixin.qq.com/s/Hxvaz8u21p94ChxCshIftA)
* [损失超 6.1 亿美元 —— Ronin Network 被黑分析](https://mp.weixin.qq.com/s/0U58Chw970X2GWcj2fvLPg)
* [Revest Finance 被黑分析](https://mp.weixin.qq.com/s/OnHZITW-VTl7qNJkLHaVgA)
* [智能合约安全审计入门篇 —— 重入漏洞](https://mp.weixin.qq.com/s/4j5_CirSySE1GLd3BP9CZQ)
* [智能合约安全审计入门篇 —— 溢出漏洞](https://mp.weixin.qq.com/s/7lqM7MlKqvQBKBRCX-Nxgg)
* [智能合约安全审计入门篇 —— 自毁函数](https://mp.weixin.qq.com/s/exO9RCeUvysFQkBdMo3RgA)
* [智能合约安全审计入门篇 —— 访问私有数据](https://mp.weixin.qq.com/s/_DV6UaRdA_6pUFXt-EnTtA)

### 链上追踪技术分析
慢雾安全团队对 DeFi 被黑事件保持跟进，协助被黑的项目方进行链上追踪，并深入研究各类混币平台，寻找突破混币进行追踪的可能。
* [慢雾：复盘 Liquid 交易平台被盗 9000 多万美元事件](https://mp.weixin.qq.com/s/GIDGDsMo3nkkmS8yuhDOhg)
* [链上追踪：洗币手法科普之 Peel Chain](https://mp.weixin.qq.com/s/MVrkfoNDSIlN-VYW0CMisQ)
* [链上追踪：洗币手法科普之 Tornado.Cash](https://mp.weixin.qq.com/s/LDdCb-7p4ojrzVd3tLk28w)
* [慢雾 AML：“揭开” Tornado.Cash 的匿名面纱](https://mp.weihttps://mp.weixin.qq.com/s/LDdCb-7p4ojrzVd3tLk28wxin.qq.com/s/ht5g10nIEyWc_3HSvh0auw)
* [THORChain 连遭三击，黑客会是同一个吗？](https://mp.weixin.qq.com/s/6DBtGGXtUs9Gcy4v0IxU1A)
* :pushpin: [被黑 6.1 亿美金的 Poly Network 事件分析与疑难问答](https://mp.weixin.qq.com/s/5ogP1v7fJsJnlLuUs6lzlg)


### 其他区块链技术分析
慢雾安全团队不断深入主流公链的生态，专注研究公链生态的安全。
* :pushpin: [以太坊黑色情人节](https://4294967296.io/eth214/)
* :pushpin: [以太坊生态缺陷导致的一起亿级代币盗窃大案](https://mp.weixin.qq.com/s/Kk2lsoQ1679Gda56Ec-zJg)
* :pushpin: [Billions of Tokens Theft Case cause by ETH Ecological Defects](https://mp.weixin.qq.com/s/ia9nBhmqVEXiiQdFrjzmyg)
* :pushpin: [Bitpay 旗下 Copay 被定向供应链攻击事件分析](https://mp.weixin.qq.com/s/oW54NLEYRnwRj4JUOtQS1g)
* :pushpin: [⼀个通杀绝⼤多数交易平台的 XSS 0day 漏洞](https://mp.weixin.qq.com/s/yfbKf_5Nk2NXFl2-xlFqKg)
* [假币的换脸戏法 —— 技术拆解 THORChain 跨链系统“假充值”漏洞](https://mp.weixin.qq.com/s/n--FSXOKJV0fa5Dc_VG_4Q)
* :pushpin: [引介｜一种安全的 LP 价格的获取方法](https://mp.weixin.qq.com/s/HmDFoUY-D7b8xUMnTgM_Tg)
* [技术干货 | 聊聊区块链安全攻防实践](https://mp.weixin.qq.com/s/umkkkWvlsZo-t58JcCbm5g)
* [技术干货 | 比特币点对点网络中的日蚀攻击](https://mp.weixin.qq.com/s/9U0gLQ2cpuprc3vbh0rLZw)
* :pushpin: [慢雾安全团队关于 ETC 51% 算力攻击的分析](https://mp.weixin.qq.com/s/JmpOxXcmXpDbzYeMNcGugg)
* [关于 Cosmos & IRISnet Validator 安全部署的一些思考](https://mp.weixin.qq.com/s/_eCQ4xronNptzQc-d8xPZQ)
* :pushpin: [冲突的公链！来自 P2P 协议的异形攻击漏洞](https://mp.weixin.qq.com/s/UmricgYGUakAlZTb0ihqdw)
* [BCH 升级攻击事件安全分析](https://mp.weixin.qq.com/s/Bp_lNKvnddDogYBcT4Hekw)
* [关于 Edgeware 锁仓合约的拒绝服务漏洞](https://mp.weixin.qq.com/s/qpjAuWqKh9BgcanFiHZiqg)
* [慢雾分析：门罗币钱包之“狸猫换太子”](https://mp.weixin.qq.com/s/PeIgmHDEgy0k8OU9R0q02A)
* [遗忘的亚特兰蒂斯：以太坊短地址攻击详解](https://mp.weixin.qq.com/s/LLCpIC54MksMmYjIDKPmPQ)
* [以太坊智能合约重放攻击细节剖析](https://mp.weixin.qq.com/s/kEGbx-I17kzm7bTgu-Nh2g)
* [以太坊 Solidity 未初始化存储指针安全风险浅析](https://mp.weixin.qq.com/s/ebLq4NkgbjZwBBuH37XPpA)
* :pushpin: [慢雾：假钱包 App 已致上万人被盗，损失高达十三亿美元](https://mp.weixin.qq.com/s/6e5GEiocogN3CO8IWxIXLA)
* [慢雾：伪 Electrum 鱼叉钓鱼攻击分析](https://mp.weixin.qq.com/s/7MMXj8Lll4YkssOXoxdm4A)
* [价值两百万的以太坊钱包陷阱](https://mp.weixin.qq.com/s/YPS7ZY6KGDYWZypjQrMpAw)
* [区块链诈骗手法之假币骗局揭秘](https://mp.weixin.qq.com/s/W4On3uKDLAi8xGctZGYTXA)

### :fire: 针对数字货币交易平台充值入账的攻击手法
慢雾安全团队依靠多年的区块链安全行业经验，首发了各类假充值的攻击手法，为交易平台提供安全检查服务，保障交易平台的充值入账安全。
* [USDT 假充值手法](https://mp.weixin.qq.com/s/CtAKLNe0MOKDyUFaod4_hw)
* [EOS 假充值手法](https://mp.weixin.qq.com/s/fKINfZLW65LYaD4qO-21nA)
* [XRP 假充值手法](https://developers.ripple.com/partial-payments.html)
* [以太坊代币假充值手法](https://mp.weixin.qq.com/s/3cMbE6p_4qCdVLa4FNA5-A)
* [比特币RBF假充值手法](https://mp.weixin.qq.com/s/OYi2JDbAoLEdg8VDouqbIg)
* [XMR锁定转账手法](https://mp.weixin.qq.com/s/Kt-G_bYbuUMIbSGSnyYXLA)
* [以太坊假充值手法](https://t.zsxq.com/YNbMFIa)
* [IOST 假充值手法-未公开](https://www.slowmist.com/?lang=zh#products)
* [FileCoin 假充值手法-未公开](https://www.slowmist.com/?lang=zh#products)
* [NEM 假充值手法-未公开](https://www.slowmist.com/?lang=zh#products)
* [Solana 假充值手法-未公开](https://www.slowmist.com/?lang=zh#products)
* [波场代币 假充值手法-未公开](https://www.slowmist.com/?lang=zh#products)
* [terra 假充值手法-未公开](https://www.slowmist.com/?lang=zh#products)
* [BTC/dogcoin/LTC 假充值手法-未公开](https://www.slowmist.com/?lang=zh#products)

## 其他资料

Other awesome collections.

* [Hacked](https://hacked.slowmist.io)
* [Awesome Blockchain Bug Bounty](https://github.com/slowmist/awesome-blockchain-bug-bounty)
* [慢雾科普：区块链安全入门笔记](./blockchain_security_study_notes/README.md)