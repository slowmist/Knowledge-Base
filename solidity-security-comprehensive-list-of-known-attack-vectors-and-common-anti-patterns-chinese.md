# Solidity 安全：已知攻击方法和常见防御模式综合列表

原文链接：[https://blog.sigmaprime.io/solidity-security.html](https://blog.sigmaprime.io/solidity-security.html)

译者：爱上平顶山@慢雾安全团队

校对：keywolf@慢雾安全团队

虽然处于起步阶段，但是 Solidity 已被广泛采用，并被用于编译我们今天看到的许多以太坊智能合约中的字节码。相应地，开发者和用户也获得许多严酷的教训，例如发现语言和EVM的细微差别。这篇文章旨在作为一个相对深入和最新的介绍性文章，详述 Solidity 开发人员曾经踩过的坑，避免后续开发者重蹈覆辙。

## 目录

* [重入漏洞](#重入漏洞)
  * [漏洞](#漏洞)
  * [预防技术](#预防技术)
  * [真实世界的例子：DAO](#真实世界的例子dao)

* [算法上下溢出](#算法上下溢出)
  * [漏洞](#漏洞-1)
  * [预防技术](#预防技术-1)
  * [实际示例：PoWHC和批量传输溢出（CVE-2018-10299）](#实际示例powhc和批量传输溢出cve-2018-10299)

* [不期而至的Ether](#不期而至的ether)
  * [漏洞](#漏洞-2)
  * [预防技术](#预防技术-2)
  * [真实世界的例子：未知](#真实世界的例子未知)

* [Delegatecall](#delegatecall)
  * [漏洞](#漏洞-3)
  * [预防技术](#预防技术-3)
  * [真实世界的例子：Parity Multisig Wallet（Second Hack）](#真实世界示例parity-multisig-walletsecond-hack)

* [默认可见性（Visibility）](#默认可见性Visibility)
  * [漏洞](#漏洞-4)
  * [预防技术](#预防技术-4)
  * [真实世界示例：Parity MultiSig Wallet（First Hack）](#真实世界示例parity-multisig-wallet-first-hack)

* [随机数误区](#随机数误区)
  * [漏洞](#漏洞-5)
  * [预防技术](#预防技术-5)
  * [真实案例：PRNG合约](#真实案例prng合约)

* [外部合约引用](#外部合约引用)
  * [漏洞](#漏洞-6)
  * [预防技术](#预防技术-6)
  * [真实的例子：再入蜜罐](#真实的例子再入蜜罐)

* [短地址/参数攻击](#短地址参数攻击)
  * [漏洞](#漏洞-7)
  * [预防技术](#预防技术-7)
  * [真实世界的例子：未知](#真实世界的例子未知-1)

* [未检查的CALL返回值](#未检查的call返回值)
  * [漏洞](#漏洞-8)
  * [预防技术](#预防技术-8)
  * [真实的例子：Etherpot和以太之王](#真实的例子etherpot和以太之王)

* [条件竞争/抢先提交](#条件竞争/抢先提交)
  * [漏洞](#漏洞-9)
  * [预防技术](#预防技术-9)
  * [真实世界的例子：ERC20和Bancor](#真实世界的例子erc20和bancor)

* [拒绝服务（DOS）](#拒绝服务dos)
  * [漏洞](#漏洞-10)
  * [预防技术](#预防技术-10)
  * [真实的例子：GovernMental](#真实的例子governmental)

* [锁定时间戳操作](#锁定时间戳操作)
  * [漏洞](#漏洞-11)
  * [预防技术](#预防技术-11)
  * [真实的例子：GovernMental](#真实的例子governmental)

* [谨慎构建函数](#谨慎构建函数)
  * [漏洞](#漏洞-12)
  * [预防技术](#预防技术-12)
  * [真实世界的例子：Rubixi](#真实世界的例子rubixi)

* [虚拟化存储指针](#虚拟化存储指针)
  * [漏洞](#漏洞-13)
  * [预防技术](#预防技术-13)
  * [真实世界的例子：蜂蜜罐：OpenAddressLottery和CryptoRoulette](#真实世界的例子蜜罐openaddresslottery和cryptoroulette)

* [浮点和数值精度](#浮点和数值精度)
  * [漏洞](#漏洞-14)
  * [预防技术](#预防技术-14)
  * [真实世界的例子：Ethstick](#真实世界的例子ethstick)

* [tx.origin身份验证](#txorigin身份验证)
  * [漏洞](#漏洞-15)
  * [预防技术](#预防技术-15)
  * [真实世界的例子：未知](#真实世界的例子未知-2)

* [以太坊怪异模式](#以太坊怪异模式)
  * [无键ether](#无键ether)
  * [一次性地址](#一次性地址)

* [有趣的加密相关的hacks/bugs列表](#有趣的加密相关的hacksbugs列表)

* [参考文献/更多阅读列表](#参考文献更多阅读列表)

  - [Ethereum Wiki - Safety](https://github.com/ethereum/wiki/wiki/Safety)
  - [Solidity Docs - Security Considerations](solidity.readthedocs.io/en/latest/security-considerations.html)
  - [Consensus - Ethereum Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices)
  - [History of Ethereum Security Vulnerabilities, Hacks and Their Fixes](https://applicature.com/blog/history-of-ethereum-security-vulnerabilities-hacks-and-their-fixes)
  - [Decentralized Application Security Project (DASP) Top 10 of 2018](http://www.dasp.co/)
  - [A Survey of attacks on Ethereum Smart Contracts](https://eprint.iacr.org/2016/1007.pdf)
  - [Ethereum Smart Contract Security](https://medium.com/cryptronics/ethereum-smart-contract-security-73b0ede73fa8)
  - [Lessons Learnt from the Underhanded Solidity Contest](https://medium.com/@chriseth/lessons-learnt-from-the-underhanded-solidity-contest-8388960e09b1)


## 重入漏洞

以太坊智能合约的特点之一是能够调用和利用其他外部合约的代码。合约通常也处理 Ether，因此通常会将 Ether 发送给各种外部用户地址。调用外部合约或将以太网发送到地址的操作需要合约提交外部调用。这些外部调用可能被攻击者劫持，迫使合约执行进一步的代码（即通过回退函数），包括回调自身。因此代码执行“重新进入”合约。这种攻击被用于臭名昭著的 DAO 攻击。

有关重入攻击的进一步阅读，请参阅[对智能合约的重入式攻击](https://medium.com/@gus_tavo_guim/reentrancy-attack-on-smart-contracts-how-to-identify-the-exploitable-and-an-example-of-an-attack-4470a2d8dfe4)和 [Consensus - 以太坊智能合约最佳实践](https://consensys.github.io/smart-contract-best-practices/known_attacks/#dos-with-unexpected-revert)。

### 漏洞

当合约将 Ether 发送到未知地址时，可能会发生此攻击。攻击者可以在 [Fallback 函数](https://solidity.readthedocs.io/en/latest/contracts.html?highlight=fallback#fallback-function)中的外部地址处构建一个包含恶意代码的合约。因此，当合约向此地址发送 Ether 时，它将调用恶意代码。通常，恶意代码会在易受攻击的合约上执行一个函数、该函数会运行一项开发人员不希望的操作。“重入”这个名称来源于外部恶意合约回复了易受攻击合约的功能，并在易受攻击的合约的任意位置“重新输入”了代码执行。

为了澄清这一点，请考虑简单易受伤害的合约，该合约充当以太坊保险库，允许存款人每周只提取 1 个 Ether。

EtherStore.sol：

```solidity
contract EtherStore {

    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;
    
    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdrawFunds (uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] -= _weiToWithdraw;
        lastWithdrawTime[msg.sender] = now;
    }
 }
```

该合约有两个公共职能。 ` depositFunds() ` 和 ` withdrawFunds() ` 。该 ` depositFunds() ` 功能只是增加发件人余额。该 ` withdrawFunds() ` 功能允许发件人指定要撤回的 wei 的数量。如果所要求的退出金额小于 1Ether 并且在上周没有发生撤回，它才会成功。额，真会是这样吗？... 

该漏洞出现在 [17] 行，我们向用户发送他们所要求的以太数量。考虑一个恶意攻击者创建下列合约，

Attack.sol：

```solidity
import "EtherStore.sol";

contract Attack {
  EtherStore public etherStore;

  // intialise the etherStore variable with the contract address
  constructor(address _etherStoreAddress) {
      etherStore = EtherStore(_etherStoreAddress);
  }
  
  function pwnEtherStore() public payable {
      // attack to the nearest ether
      require(msg.value >= 1 ether);
      // send eth to the depositFunds() function
      etherStore.depositFunds.value(1 ether)();
      // start the magic
      etherStore.withdrawFunds(1 ether);
  }
  
  function collectEther() public {
      msg.sender.transfer(this.balance);
  }
    
  // fallback function - where the magic happens
  function () payable {
      if (etherStore.balance > 1 ether) {
          etherStore.withdrawFunds(1 ether);
      }
  }
}
```

让我们看看这个恶意合约是如何利用我们的 ` EtherStore ` 合约的。攻击者可以（假定恶意合约地址为 ` 0x0...123 ` ）使用 ` EtherStore ` 合约地址作为构造函数参数来创建上述合约。这将初始化并将公共变量 ` etherStore ` 指向我们想要攻击的合约。

然后攻击者会调用这个 ` pwnEtherStore() ` 函数，并存入一些 Ehter（大于或等于1），比方说 1Ehter，在这个例子中。在这个例子中，我们假设一些其他用户已经将若干 Ehter 存入这份合约中，比方说它的当前余额就是 ` 10 ether ` 。然后会发生以下情况：

1. Attack.sol -Line [15] -EtherStore合约的 ` despoitFunds ` 函数将会被调用，并伴随 1Ether 的 mag.value（和大量的 Gas）。sender(msg.sender) 将是我们的恶意合约 ` （0x0...123） ` 。因此， ` balances[0x0..123] = 1 ether ` 。
2. Attack.sol - Line [17] - 恶意合约将使用一个参数来调用合约的 ` withdrawFunds() ` 功能。这将通过所有要求（合约的行 [12] - [16] ），因为我们以前没有提款。
3. EtherStore.sol - 行 [17] - 合约将发送 1Ether 回恶意合约。
4. Attack.sol - Line [25] - 发送给恶意合约的 Ether 将执行 fallback 函数。
5. Attack.sol - Line [26] - EtherStore 合约的总余额是 10Ether，现在是 9Ether，如果声明通过。
6. Attack.sol - Line [27] - 回退函数然后再次动用 EtherStore 中的 ` withdrawFunds() ` 函数并“重入” EtherStore合约。
7. EtherStore.sol - 行 [11] - 在第二次调用 ` withdrawFunds() ` 时，我们的余额仍然是 1Ether，因为 行[18] 尚未执行。因此，我们仍然有 ` balances[0x0..123] = 1 ether `。` lastWithdrawTime ` 变量也是这种情况。我们再次通过所有要求。
8. EtherStore.sol - 行[17] - 我们撤回另外的 1Ether。
9. 步骤4-8将重复 - 直到 ` EtherStore.balance >= 1 `，这是由 Attack.sol - Line [26] 所指定的。
10. Attack.sol - Line [26] - 一旦在 EtherStore 合约中留下少于 1（或更少）的 Ether，此 if 语句将失败。这样 EtherStore 就会执行合约的 行[18]和 行[19]（每次调用 ` withdrawFunds() ` 函数之后都会执行这两行）。
11. EtherStore.sol - 行[18]和[19] -  ` balances ` 和 ` lastWithdrawTime ` 映射将被设置并且执行将结束。

最终的结果是，攻击者只用一笔交易，便立即从 EtherStore 合约中取出了（除去 1 个 Ether 以外）所有的 Ether。

### 预防技术

有许多常用技术可以帮助避免智能合约中潜在的重入漏洞。首先是（在可能的情况下）在将 Ether 发送给外部合约时使用内置的 [transfer() 函数](http://solidity.readthedocs.io/en/latest/units-and-global-variables.html#address-related)。转账功能只发送 ` 2300 gas ` 不足以使目的地址/合约调用另一份合约（即重入发送合约）。

第二种技术是确保所有改变状态变量的逻辑发生在 Ether 被发送出合约（或任何外部调用）之前。在这个 EtherStore 例子中，EtherStore.sol - 行[18]和行[19] 应放在 行[17] 之前。将任何对未知地址执行外部调用的代码，放置在本地化函数或代码执行中作为最后一个操作，是一种很好的做法。这被称为[检查效果交互（checks-effects-interactions）](http://solidity.readthedocs.io/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)模式。

第三种技术是引入互斥锁。也就是说，要添加一个在代码执行过程中锁定合约的状态变量，阻止重入调用。

给 EtherStore.sol 应用所有这些技术（同时使用全部三种技术是没必要的，只是为了演示目的而已）会出现如下的防重入合约：

```solidity
contract EtherStore {

    // initialise the mutex
    bool reEntrancyMutex = false;
    uint256 public withdrawalLimit = 1 ether;
    mapping(address => uint256) public lastWithdrawTime;
    mapping(address => uint256) public balances;
    
    function depositFunds() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdrawFunds (uint256 _weiToWithdraw) public {
        require(!reEntrancyMutex);
        require(balances[msg.sender] >= _weiToWithdraw);
        // limit the withdrawal
        require(_weiToWithdraw <= withdrawalLimit);
        // limit the time allowed to withdraw
        require(now >= lastWithdrawTime[msg.sender] + 1 weeks);
        balances[msg.sender] -= _weiToWithdraw;
        lastWithdrawTime[msg.sender] = now;
        // set the reEntrancy mutex before the external call
        reEntrancyMutex = true;
        msg.sender.transfer(_weiToWithdraw);
        // release the mutex after the external call
        reEntrancyMutex = false; 
    }
 }
```

### 真实的例子：The DAO

[The DAO](https://en.wikipedia.org/wiki/The_DAO_(organization))（分散式自治组织）是以太坊早期发展的主要黑客之一。当时，该合约持有1.5亿美元以上。重入在这次攻击中发挥了重要作用，最终导致了 Ethereum Classic（ETC）的分叉。有关The DAO 漏洞的详细分析，请参阅 [Phil Daian 的文章](http://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/)。

## 算法上下溢出

以太坊虚拟机（EVM）为整数指定固定大小的数据类型。这意味着一个整型变量只能有一定范围的数字表示。例如，一个 ` uint8 ` ，只能存储在范围 [0,255] 的数字。试图存储 256 到一个 ` uint8 ` 将变成 0。不加注意的话，只要没有检查用户输入又执行计算，导致数字超出存储它们的数据类型允许的范围，Solidity 中的变量就可以被用来组织攻击。

要进一步阅读算法上下溢出，请参阅[如何保护您的智能合约](https://medium.com/loom-network/how-to-secure-your-smart-contracts-6-solidity-vulnerabilities-and-how-to-avoid-them-part-1-c33048d4d17d)，[以太坊智能合约最佳实践](https://consensys.github.io/smart-contract-best-practices/known_attacks/#integer-overflow-and-underflow)和[以太坊，Solidity 和整数溢出：像身处1970 年那样为区块链编程](https://randomoracle.wordpress.com/2018/04/27/ethereum-solidity-and-integer-overflows-programming-blockchains-like-1970/)

### 漏洞

当执行操作需要固定大小的变量来存储超出变量数据类型范围的数字（或数据）时，会发生数据上溢/下溢。

例如，从一个存储 0 的 ` uint8 ` （无符号的 8 位整数，即只有正数）变量中减去 1，将导致该变量的值变为 255。这是一个下溢。我们明明为该 ` uint8 ` 分配了一个低于其储存范围的值，结果却是 *绕回来* 变成了 ` uint8 ` 所能储存的最大值。同样，给一个 ` uint8 ` 加上  ` 2^8=256 ` 会使变量保持不变，因为我们已经绕过了 ` uint ` 的整个值域又回到原值（对于数学家来说，这类似于将三角函数的角度加上 2pi ，sin(x) = sin(x + 2pi)）。添加大于数据类型范围的数字称为上溢。为了清楚起见，添加 257 到一个目前仅有 0 值的 ` uint8 ` 变量将变成数字 1。将固定类型变量视为循环有时很有启发意义，如果我们加入的数字超出最大可存储数字，等于是从零开始加上超出额，反之也是从零开始（从零中减去一定数额，等同于从最大数字往下减该数额）。

这些类型的漏洞允许攻击者滥用代码并创建意外的逻辑流程。例如，请考虑下面的时间锁定合约。

TimeLock.sol：

```solidity
contract TimeLock {
    
    mapping(address => uint) public balances;
    mapping(address => uint) public lockTime;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        lockTime[msg.sender] = now + 1 weeks;
    }
    
    function increaseLockTime(uint _secondsToIncrease) public {
        lockTime[msg.sender] += _secondsToIncrease;
    }
    
    function withdraw() public {
        require(balances[msg.sender] > 0);
        require(now > lockTime[msg.sender]);
        balances[msg.sender] = 0;
        msg.sender.transfer(balances[msg.sender]);
    }
}
```

这份合约的设计就像是一个时间保险库，用户可以将 Ether 存入合约，并在那里锁定至少一周。如果用户选择的话，用户可以延长超过1周的时间，但是一旦存放，用户可以确信他们的 Ether 会被安全锁定至少一周。有没有别的可能性？...

如果用户被迫交出他们的私钥（考虑绑票的情形），像这样的合约可能很方便，以确保在短时间内无法获得 Ether。但是，如果用户已经锁定了 100Ether 合约并将其密钥交给了攻击者，那么攻击者可以使用溢出来接收 Ether，无视 ` lockTime ` 的限制。

攻击者可以确定他们所持密钥的地址的 ` lockTime ` （它是一个公共变量）。我们称之为 ` userLockTime ` 。然后他们可以调用该 ` increaseLockTime ` 函数并将数字 ` 2^256 - userLockTime ` 作为参数传入。该数字将被添加到当前的 ` userLockTime ` 并导致溢出，重置 ` lockTime[msg.sender] ` 为0。攻击者然后可以简单地调用 ` withdraw ` 函数来获得他们的奖励。

我们来看另一个例子，来自 [Ethernaut Challanges](https://github.com/OpenZeppelin/ethernaut) 的这个例子。

SPOILER ALERT： 如果你还没有完成 Ethernaut 的挑战，这可以解决其中一个难题。

```solidity
pragma solidity ^0.4.18;

contract Token {

  mapping(address => uint) balances;
  uint public totalSupply;

  function Token(uint _initialSupply) {
    balances[msg.sender] = totalSupply = _initialSupply;
  }

  function transfer(address _to, uint _value) public returns (bool) {
    require(balances[msg.sender] - _value >= 0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    return true;
  }

  function balanceOf(address _owner) public constant returns (uint balance) {
    return balances[_owner];
  }
}
```

这是一个简单的 Token 合约，它使用一个 ` transfer() ` 函数，允许参与者转移他们的 Token。你能看出这份合约中的错误吗？

缺陷出现在 ` transfer() ` 功能中。行[13]上的 require 语句可以使用下溢来绕过。考虑一个没有余额的用户。他们可以用任何非零值 ` _value ` 调用 ` transfer() ` 函数，并将 ` _value ` 传入 行[13] 上的 require 语句。因为 ` balances[msg.sender] ` 为零（也即是 ` uint256 ` ），减去任何正数（不包括 ` 2^256 ` ）都将导致正数（由于我们上面描述的下溢）。对于 行[14] 也是如此，我们的余额将记入正数。因此，在这个例子中，我们由于下溢漏洞得到了免费的 Token。

### 预防技术

防止溢出漏洞的（当前）常规技术是使用或建立取代标准数学运算符的数学库; 加法，减法和乘法（除法被排除在外，因为它不会导致上溢/下溢，并且 EVM 除以 0 时会丢出错误）。

[OppenZepplin](https://github.com/OpenZeppelin/zeppelin-solidity) 在构建和审计 Ethereum 社区可以利用的安全库方面做得非常出色。特别是，他们的 [SafeMath](https://github.com/OpenZeppelin/zeppelin-solidity/blob/master/contracts/math/SafeMath.sol) 是一个用来避免上溢/下溢漏洞的参考或库。

为了演示如何在 Solidity 中使用这些库，让我们使用 Open Zepplin 的 SafeMath 库更正合约 TimeLock。防溢出的合约长这样：

```solidity
library SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b); 
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b; 
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract TimeLock {
    using SafeMath for uint; // use the library for uint type
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lockTime;
    
    function deposit() public payable {
        balances[msg.sender] = balances[msg.sender].add(msg.value);
        lockTime[msg.sender] = now.add(1 weeks);
    }
    
    function increaseLockTime(uint256 _secondsToIncrease) public {
        lockTime[msg.sender] = lockTime[msg.sender].add(_secondsToIncrease);
    }
    
    function withdraw() public {
        require(balances[msg.sender] > 0);
        require(now > lockTime[msg.sender]);
        balances[msg.sender] = 0;
        msg.sender.transfer(balances[msg.sender]);
    }
}
```

请注意，所有标准的数学运算已被 SafeMath 库中定义的数学运算所取代。该 TimeLock 合约不会再执行任何能够导致下溢/上溢的操作。


### 实际示例：PoWHC 和批量传输溢出（[CVE-2018-10299](https://nvd.nist.gov/vuln/detail/CVE-2018-10299)）

一个 4chan 小组认为，用 Solidity 在 Ethereum上 构建一个庞氏骗局是个好主意。他们称它为弱手硬币证明（PoWHC）。不幸的是，似乎合约的作者之前没有看到上溢/下溢问题，因此，866Ether 从合约中解放出来。[Eric Banisadar 的文章](https://blog.goodaudience.com/how-800k-evaporated-from-the-powh-coin-ponzi-scheme-overnight-1b025c33b530)对下溢是如何发生的作出了很好的概述（这与上面的 Ethernaut 挑战不太相似）。

一些开发人员还为一些 [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) Token 合约实施了一项 ` batchTransfer() ` 函数。该实现包含溢出。[这篇文章](https://medium.com/@peckshield/alert-new-batchoverflow-bug-in-multiple-erc20-smart-contracts-cve-2018-10299-511067db6536)对此进行了解释，但是我认为标题有误导性，因为它与 ERC20 标准无关，而是一些 ERC20 Token 合约实现了易受攻击的 ` batchTransfer() ` 。

## 不期而至的 Ether

通常，当 Ether 发送到合约时，它必须执行回退功能或合约中描述的其他功能。这里有两个例外，合约可能会收到了 Ether 但并不会执行任何函数。通过收到以太币来触发代码的合约，对强制将以太币发送到某个合约这类攻击是非常脆弱的。

关于这方面的进一步阅读，请参阅[如何保护您的智能合约：6](https://medium.com/loom-network/how-to-secure-your-smart-contracts-6-solidity-vulnerabilities-and-how-to-avoid-them-part-2-730db0aa4834) 和 [Solidity security patterns - forcing ether to a contract](http://danielszego.blogspot.com.au/2018/03/solidity-security-patterns-forcing.html)

### 漏洞

一种常用的防御性编程技术对于执行正确的状态转换或验证操作很有用，它是不变量检查（Invariant-checking）。该技术涉及定义一组不变量（不应改变的度量或参数），并且在单个（或多个）操作之后检查这些不变量保持不变。这基本上是很好的设计，保证受到检查的不变量在实际上保持不变。不变量的一个例子是发行量固定的 [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md) 代币合约的 ` totalSupply ` 。不应该有函数能修改此不变量，因此可以在该 ` transfer() ` 函数中添加一个检查以确保 ` totalSupply ` 保持未修改状态，确保函数按预期工作。

不管智能合约中规定的规则如何，有一个量，特别容易诱导开发人员将其当作明显的“不变量”来使用，但它在事实上是可以由外部用户来操纵的，那便是合约中存储的 Ether 数量。通常，开发人员刚开始学习 Solidity 时，他们有一种误解，认为合约只能通过 ` payable ` 函数接受或获得 Ether。这种误解可能会导致合约对其内部的 ETH 余额有错误的假设，进而导致一系列的漏洞。此漏洞的明显信号是（不正确地）使用 ` this.balance ` 。正如我们将看到的，错误地使用 ` this.balance ` 会导致这种类型的严重漏洞。

有两种方式可以将 Ether（强制）发送给合约，而无需使用 ` payable ` 函数或执行合约中的任何代码。这些在下面列出。

**自毁**

任何合约都能够实现该 [` selfdestruct(address) `](http://solidity.readthedocs.io/en/latest/introduction-to-smart-contracts.html#self-destruct) 功能，该功能从合约地址中删除所有字节码，并将所有存储在那里的 Ether 发送到参数指定的地址。如果此指定的地址也是合约，则不会调用任何功能（包括故障预置）。因此，使用 ` selfdestruct() ` 函数可以无视目标合约中存在的任何代码，强制将 Ether 发送给任一目标合约，包括没有任何可支付函数的合约。这意味着，任何攻击者都可以创建带有 ` selfdestruct() ` 函数的合约，向其发送 Ether，调用 ` selfdestruct(target) ` 并强制将 Ether 发送至 ` target ` 合约。Martin Swende 有一篇出色的[博客文章](http://martin.swende.se/blog/Ethereum_quirks_and_vulns.html)描述了自毁操作码（Quirk＃2）的一些诡异操作，并描述了客户端节点如何检查不正确的不变量，这可能会导致相当灾难性的客户端问题。

**预先发送的 Ether**

合约不使用 ` selfdestruct() ` 函数或调用任何 payable 函数仍可以接收到 Ether 的第二种方式是把 Ether 预装进合约地址。合约地址是确定性的，实际上地址是根据创建合约的地址及创建合约的交易 Nonce 的哈希值计算得出的，即下述形式： ` address = sha3(rlp.encode([account_address,transaction_nonce]) ` 请参阅 [Keyless Ether](https://github.com/sigp/solidity-security-blog#keyless-eth) 在这一点上的一些有趣用例）。这意味着，任何人都可以在创建合约之前计算出合约地址，并将 Ether 发送到该地址。当合约确实创建时，它将具有非零的 Ether 余额。

根据上述知识，我们来探讨一些可能出现的缺陷。
考虑过于简单的合约，

EtherGame.sol：

```solidity
contract EtherGame {
    
    uint public payoutMileStone1 = 3 ether;
    uint public mileStone1Reward = 2 ether;
    uint public payoutMileStone2 = 5 ether;
    uint public mileStone2Reward = 3 ether; 
    uint public finalMileStone = 10 ether; 
    uint public finalReward = 5 ether; 
    
    mapping(address => uint) redeemableEther;
    // users pay 0.5 ether. At specific milestones, credit their accounts
    function play() public payable {
        require(msg.value == 0.5 ether); // each play is 0.5 ether
        uint currentBalance = this.balance + msg.value;
        // ensure no players after the game as finished
        require(currentBalance <= finalMileStone);
        // if at a milestone credit the players account
        if (currentBalance == payoutMileStone1) {
            redeemableEther[msg.sender] += mileStone1Reward;
        }
        else if (currentBalance == payoutMileStone2) {
            redeemableEther[msg.sender] += mileStone2Reward;
        }
        else if (currentBalance == finalMileStone ) {
            redeemableEther[msg.sender] += finalReward;
        }
        return;
    }
    
    function claimReward() public {
        // ensure the game is complete
        require(this.balance == finalMileStone);
        // ensure there is a reward to give
        require(redeemableEther[msg.sender] > 0); 
        redeemableEther[msg.sender] = 0;
        msg.sender.transfer(redeemableEther[msg.sender]);
    }
 }    
```

这个合约代表一个简单的游戏（自然会引起[条件竞争（Race-conditions）](#条件竞争非法预先交易)），玩家可以将 ` 0.5 ether ` 发送给合约，希望成为第一个达到三个里程碑之一的玩家。里程碑以 Ether 计价。当游戏结束时，第一个达到里程碑的人可以获得合约的部分 Ether。当达到最后的里程碑（10 Ether）时，游戏结束，用户可以申请奖励。

EtherGame 合约的问题出自在 [14] 行（以及相关的 [16] 行）和 [32] 行中对 ` this.balance ` 的错误使用。一个调皮的攻击者可以通过（上面讨论过的） ` selfdestruct() ` 函数强行发送少量的以太，比如 ` 0.1 ether `，以防止未来的玩家达到一个里程碑。由于所有合法玩家只能发送 ` 0.5 ether ` 增量，而合约收到了 ` 0.1 ether ` ，合约的 ` this.balance ` 不再是半个整数。这会阻止 [18]、[21]和[24] 行的所有条件成立。

更糟糕的是，一个因错过了里程碑而复仇心切的攻击者可能会强行发送 ` 10 ether ` （或者会将合约的余额推到高出 ` finalMileStone ` 的数量），这将永久锁定合约中的所有奖励。这是因为 ` claimReward() ` 函数总是会回弹，因为 [32] 行中的要求（即 ` this.balance ` 大于 ` finalMileStone ` ）。

### 预防技术

这个漏洞通常是由于错误运用 ` this.balance ` 而产生的。如果可能，合约逻辑应该避免依赖于合约余额的确切值，因为它可以被人为地操纵。如果应用基于 ` this.balance ` 函数的逻辑语句，请确保考虑到了飞来横 Ether。

如果需要存储 Ether 的确定值，则应使用自定义变量来获得通过可支付函数获得的增量，以安全地追踪储存 Ether 的值。这个变量不应受到通过调用 ` selfdestruct() ` 强制发送的 Ether 的影响。

考虑到这一点，修正后的EtherGame合约版本可能如下所示：

```solidity
contract EtherGame {
    
    uint public payoutMileStone1 = 3 ether;
    uint public mileStone1Reward = 2 ether;
    uint public payoutMileStone2 = 5 ether;
    uint public mileStone2Reward = 3 ether; 
    uint public finalMileStone = 10 ether; 
    uint public finalReward = 5 ether; 
    uint public depositedWei;
    
    mapping (address => uint) redeemableEther;
    
    function play() public payable {
        require(msg.value == 0.5 ether);
        uint currentBalance = depositedWei + msg.value;
        // ensure no players after the game as finished
        require(currentBalance <= finalMileStone);
        if (currentBalance == payoutMileStone1) {
            redeemableEther[msg.sender] += mileStone1Reward;
        }
        else if (currentBalance == payoutMileStone2) {
            redeemableEther[msg.sender] += mileStone2Reward;
        }
        else if (currentBalance == finalMileStone ) {
            redeemableEther[msg.sender] += finalReward;
        }
        depositedWei += msg.value;
        return;
    }
    
    function claimReward() public {
        // ensure the game is complete
        require(depositedWei == finalMileStone);
        // ensure there is a reward to give
        require(redeemableEther[msg.sender] > 0); 
        redeemableEther[msg.sender] = 0;
        msg.sender.transfer(redeemableEther[msg.sender]);
    }
 }    
```

在这里，我们刚刚创建了一个新变量， ` depositedEther `，它跟踪已知的 Ether 存储量，并且这也是我们执行需求和测试时用到的变量。请注意，我们不再参考 ` this.balance `。

### 真实世界的例子：未知

我还没有找到该漏洞在真实世界中被利用的例子。然而，在 [Underhanded Solidity 竞赛](https://github.com/Arachnid/uscc/tree/master/submissions-2017/)中出现了一些可利用该漏洞的合约的例子。

## Delegatecall

 ` CALL ` 与 ` DELEGATECALL ` 操作码是非常有用的，它们让 Ethereum 开发者将他们的代码模块化（Modularise）。用 ` CALL ` 操作码来处理对合约的外部标准信息调用（Standard Message Call）时，代码在外部合约/功能的环境中运行。 ` DELEGATECALL ` 操作码也是标准消息调用，但在目标地址中的代码会在调用合约的环境下运行，也就是说，保持 ` msg.sender ` 和 ` msg.value ` 不变。该功能支持实现库，开发人员可以为未来的合约创建可重用的代码。 

虽然这两个操作码之间的区别很简单直观，但是使用 ` DELEGATECALL ` 可能会导致意外的代码执行。

有关进一步阅读，请参阅 [Stake Exchange上关于以太坊的这篇提问](https://ethereum.stackexchange.com/questions/3667/difference-between-call-callcode-and-delegatecall)，[Solidity 官方文档](http://solidity.readthedocs.io/en/latest/introduction-to-smart-contracts.html#delegatecall-callcode-and-libraries)以及[如何保护您的智能合约：6](https://medium.com/loom-network/how-to-secure-your-smart-contracts-6-solidity-vulnerabilities-and-how-to-avoid-them-part-1-c33048d4d17d)。

### 漏洞

 ` DELEGATECALL ` 会保持调用环境不变的属性表明，构建无漏洞的定制库并不像人们想象的那么容易。库中的代码本身可以是安全的，无漏洞的，但是当在另一个应用的环境中运行时，可能会出现新的漏洞。让我们看一个相当复杂的例子，使用斐波那契数字。

考虑下面的可以生成斐波那契数列和相似形式序列的库：FibonacciLib.sol[^ 1]

```solidity
// library contract - calculates fibonacci-like numbers;
contract FibonacciLib {
    // initializing the standard fibonacci sequence;
    uint public start;
    uint public calculatedFibNumber;

    // modify the zeroth number in the sequence
    function setStart(uint _start) public {
        start = _start;
    }

    function setFibonacci(uint n) public {
        calculatedFibNumber = fibonacci(n);
    }

    function fibonacci(uint n) internal returns (uint) {
        if (n == 0) return start;
        else if (n == 1) return start + 1;
        else return fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

该库提供了一个函数，可以在序列中生成第 n 个斐波那契数。它允许用户更改第 0 个 ` start ` 数字并计算这个新序列中的第 n 个斐波那契数字。

现在我们来考虑一个利用这个库的合约。

FibonacciBalance.sol：

```solidity
contract FibonacciBalance {

    address public fibonacciLibrary;
    // the current fibonacci number to withdraw
    uint public calculatedFibNumber;
    // the starting fibonacci sequence number
    uint public start = 3;    
    uint public withdrawalCounter;
    // the fibonancci function selector
    bytes4 constant fibSig = bytes4(sha3("setFibonacci(uint256)"));
    
    // constructor - loads the contract with ether
    constructor(address _fibonacciLibrary) public payable {
        fibonacciLibrary = _fibonacciLibrary;
    }

    function withdraw() {
        withdrawalCounter += 1;
        // calculate the fibonacci number for the current withdrawal user
        // this sets calculatedFibNumber
        require(fibonacciLibrary.delegatecall(fibSig, withdrawalCounter));
        msg.sender.transfer(calculatedFibNumber * 1 ether);
    }
    
    // allow users to call fibonacci library functions
    function() public {
        require(fibonacciLibrary.delegatecall(msg.data));
    }
}
```

该合约允许参与者从合约中提取 ether，金额等于参与者提款订单对应的斐波纳契数字；即第一个参与者获得 1 ether，第二个参与者获得 1，第三个获得 2，第四个获得 3，第五个获得 5 等等（直到合约的余额小于被取出的斐波纳契数）。

本合约中的许多要素可能需要一些解释。首先，有一个看起来很有趣的变量， ` fibSig `。这包含字符串“fibonacci（uint256）”的 Keccak（SHA-3） 哈希值的前4个字节。这被称为[函数选择器](https://solidity.readthedocs.io/en/latest/abi-spec.html#function-selector)，它被放入 ` calldata ` 中以指定调用智能合约的哪个函数。在 [21] 行的 ` delegatecall ` 函数中，它被用来指出：我们希望运行 ` fibonacci(uint256) ` 函数。 ` delegatecall ` 的第二个参数是我们传递给函数的参数。其次，我们假设 FibonacciLib 库的地址在构造函数中正确引用（[部署攻击向量](https://github.com/sigp/solidity-security-blog#deployment)部分会讨论与合约参考初始化相关的潜在漏洞）。

你能发现这份合约中的错误吗？如果你把它放到 Remix 里面编译，存入 Ether 并调用 ` withdraw() ` ，它可能会回滚状态。（Revert）

您可能已经注意到，在库和主调用合约中都使用了状态变量 ` start `。在库合约中， ` start ` 用于指定斐波纳契数列的起点，它被设置为 0，而 FibonacciBalance 合约中它被设置为 3。你可能还注意到，FibonacciBalance 合约中的回退函数允许将所有调用传递给库合约，因此也允许调用库合约的 ` setStart() ` 函数。回想一下，我们会保留合约状态，那么看起来你就可以据此改变本地 FibonnacciBalance 合约中 ` start ` 变量的状态。如果是这样，一个用户可以取出更多的 Ether，因为最终的 ` calculatedFibNumber ` 依赖于 ` start ` 变量（如库合约中所见）。实际上，该 ` setStart() ` 函数不会（也不能）修改 FibonacciBalance 合约中的 ` start ` 变量。这个合约中的潜在弱点比仅仅修改 ` start ` 变量要糟糕得多。

在讨论实际问题之前，我们先快速绕道了解状态变量（ ` storage ` 变量）实际上是如何存储在合约中的。状态或 ` storage ` 变量（贯穿单个交易、始终都存在的变量）在合约中引入时，是按顺序放置在 ` slots ` 中的。（这里有一些复杂的东西，我鼓励读者阅读[存储中状态变量的布局](http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage)以便更透彻地理解）。

作为一个例子，让我们看看库合约。它有两个状态变量， ` start ` 和 ` calculatedFibNumber `。第一个变量是 ` start ` ，因此它被存储在合约的存储位置 ` slot[0] ` （即第一个 slot）。第二个变量 ` calculatedFibNumber ` 放在下一个可用的存储位置中，也就是 ` slot[1] ` 。如果我们看看 ` setStart() ` 这个函数，它可以接收一个输入并依据输入来设置 ` start `。因此， ` setStart() ` 函数可以将 ` slot[0] ` 设置为我们在该函数中提供的任何输入。同样， ` setFibonacci() ` 函数也可以将 ` calculatedFibNumber ` 设置为 ` fibonacci(n) ` 的结果。再说一遍，这只是将存储位置 ` slot[1] ` 设置为 ` fibonacci(n) ` 的值。

现在让我们看看 FibonacciBalance 合约。存储位置 ` slot[0] ` 现在对应于 fibonacciLibrary 的地址， ` slot[1] ` 对应于 ` calculatedFibNumber ` 。这就是漏洞所在。 ` delegatecall ` 会保留合约环境。这意味着通过 ` delegatecall ` 执行的代码将作用于调用合约的状态（即存储）。

现在，请注意在 [21] 行上的 ` withdraw() `， ` fibonacciLibrary.delegatecall(fibSig,withdrawalCounter) ` 。这会调用 ` setFibonacci() ` ，正如我们讨论的那样，会修改存储位置 ` slot[1] ` ，在我们当前的环境中就是 ` calculatedFibNumber ` 。我们预期是这样的（即执行后， ` calculatedFibNumber ` 会得到调整）。但是，请记住，FibonacciLib 合约中，位于存储位置 ` slot[0] ` 中的是 ` start ` 变量，而在当前（FibonacciBalance）合约中就是 fibonacciLibrary 的地址。这意味着 ` fibonacci() ` 函数会带来意想不到的结果。这是因为它引用 ` start ` （ ` slot[0] ` ），而该位置在当前调用环境中是 fibonacciLibrary 的地址（如果用 ` uint ` 来表达的话，该值会非常大）。因此，调用 ` withdraw() ` 函数很可能会导致状态回滚（Revert），因为 ` calcultedFibNumber ` 会返回  ` uint(fibonacciLibrary) `，而合约却没有那么多数量的 Ether。

更糟糕的是，FibonacciBalance 合约允许用户通过 [26] 行上的回退（Fallback）函数调用 fibonacciLibrary 的所有函数。正如我们前面所讨论的那样，这包括 ` setStart() ` 函数。我们讨论过这个功能允许任何人修改或设置 ` slot[0] ` 的值。在当前合约中，存储位置 ` slot[0] ` 是 fibonacciLibrary 地址。因此，攻击者可以创建一个恶意合约（下面是一个例子），将恶意合约地址转换为一个 ` uint ` 数据（在 python 中可以使用 ` int('<address>',16) ` 轻松完成），然后调用 ` setStart(<attack_contract_address_as_uint>) ` ，这会将 ` fibonacciLibrary ` 转变为攻击合约的地址。然后，无论何时用户调用 ` withdraw() ` 或回退函数，恶意合约都会运行（它可以窃取合约的全部余额），因为我们修改了 ` fibonacciLibrary ` 指向的实际地址。这种攻击合约的一个例子是，

```solidity
contract Attack {
    uint storageSlot0; // corresponds to fibonacciLibrary
    uint storageSlot1; // corresponds to calculatedFibNumber
   
    // fallback - this will run if a specified function is not found
    function() public {
        storageSlot1 = 0; // we set calculatedFibNumber to 0, so that if withdraw
        // is called we don't send out any ether. 
        <attacker_address>.transfer(this.balance); // we take all the ether
    }
 }
```

请注意，此攻击合约可以通过更改存储位置 ` slot[1] ` 来修改 ` calculatedFibNumber ` 。原则上，攻击者可以修改他们选择的任何其他存储位置来对本合约执行各种攻击。我鼓励所有读者将这些合约放入 [Remix](https://remix.ethereum.org/)，并通过这些 ` delegatecall ` 函数尝试不同的攻击合约和状态更改。

同样重要的是要注意，当我们说 ` delegatecall ` 会保留状态，我们说的并不是合约中不同名称下的变量，而是这些名称指向的实际存储位置。从这个例子中可以看出，一个简单的错误，可能导致攻击者劫持整个合约及其 Ether。

### 预防技术

Solidity 为实现库合约提供了关键字 ` library ` （参见 [Solidity Docs](http://solidity.readthedocs.io/en/latest/contracts.html?highlight=library#libraries) 了解更多详情)。这确保了库合约是无状态（Stateless）且不可自毁的。强制让 library 成为无状态的，可以缓解本节所述的存储环境的复杂性。无状态库也可以防止攻击者直接修改库状态的攻击，以实现依赖库代码的合约。作为一般的经验法则，在使用时 ` DELEGATECALL ` 时要特别注意库合约和调用合约的可能调用上下文，并且尽可能构建无状态库。

### 真实世界示例：Parity Multisig Wallet（Second Hack）

Parity 多签名钱包第二次被黑事件是一个例子，说明了如果在非预期的环境中运行，良好的库代码也可以被利用。关于这次被黑事件，有很多很好的解释，比如这个概述：Anthony Akentiev 写的 [再一次解释 Parity 多签名钱包被黑事件](https://medium.com/chain-cloud-company-blog/parity-multisig-hack-again-b46771eaa838)，这个[stack exchange 上的问答](https://ethereum.stackexchange.com/questions/30128/explanation-of-parity-library-suicide/30130)和[深入了解Parity Multisig Bug](http://hackingdistributed.com/2017/07/22/deep-dive-parity-bug/)。

要深入理解这些参考资料，我们要探究一下被攻击的合约。受攻击的库合约和钱包合约可以在 [Parity 的 github](https://github.com/paritytech/parity/blob/b640df8fbb964da7538eef268dffc125b081a82f/js/src/contracts/snippets/enhanced-wallet.sol) 上找到。

我们来看看这个合约的相关方面。这里有两个包含利益的合约，库合约和钱包合约。

先看 library 合约， 

```solidity
contract WalletLibrary is WalletEvents {
  
  ...
  
  // throw unless the contract is not yet initialized.
  modifier only_uninitialized { if (m_numOwners > 0) throw; _; }

  // constructor - just pass on the owner array to the multiowned and
  // the limit to daylimit
  function initWallet(address[] _owners, uint _required, uint _daylimit) only_uninitialized {
    initDaylimit(_daylimit);
    initMultiowned(_owners, _required);
  }

  // kills the contract sending everything to  ` _to ` .
  function kill(address _to) onlymanyowners(sha3(msg.data)) external {
    suicide(_to);
  }
  
  ...
  
}
```

再看钱包合约，

```solidity
contract Wallet is WalletEvents {

  ...

  // METHODS

  // gets called when no other function matches
  function() payable {
    // just being sent some cash?
    if (msg.value > 0)
      Deposit(msg.sender, msg.value);
    else if (msg.data.length > 0)
      _walletLibrary.delegatecall(msg.data);
  }
  
  ...  

  // FIELDS
  address constant _walletLibrary = 0xcafecafecafecafecafecafecafecafecafecafe;
}
```

请注意，Wallet 合约基本上会通过 delegate call 将所有调用传递给 WalletLibrary。此代码段中的常量地址 ` _walletLibrary `，即是实际部署的 WalletLibrary 合约的占位符（位于 ` 0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4 ` ）。

这些合约的预期运作是生成一个简单的可低成本部署的 Wallet 合约，合约的代码基础和主要功能都在 WalletLibrary 合约中。不幸的是，WalletLibrary 合约本身就是一个合约，并保持它自己的状态。你能能不能看出为什么这会是一个问题？

因为有可能向 WalletLibrary 合约本身发送调用请求。具体来说，WalletLibrary 合约可以初始化，并被用户拥有。一个用户通过调用 WalletLibrary 中的 ` initWallet() ` 函数，成为了 Library 合约的所有者。同一个用户，随后调用 ` kill() ` 功能。因为用户是 Library 合约的所有者，所以修改传入、Library 合约自毁。因为所有现存的 Wallet 合约都引用该 Library 合约，并且不包含更改引用的方法，因此其所有功能（包括取回 Ether 的功能）都会随 WalletLibrary 合约一起丢失。更直接地说，这种类型的 Parity 多签名钱包中的所有以太都会立即丢失或者说永久不可恢复。

## 默认可见性（Visibility）

Solidity 中的函数具有可见性说明符，它们会指定我们可以如何调用函数。可见性决定一个函数是否可以由用户或其他派生契约在外部调用、只允许内部调用或只允许外部调用。有四个可见性说明符，详情请参阅 [Solidity 文档](http://solidity.readthedocs.io/en/latest/contracts.html?highlight=library#visibility-and-getters)。为允许用户从外部调用函数，函数的可见性默认为 ` public `。正如本节将要讨论的，可见性说明符的不正确使用可能会导致智能合约中的一些资金流失。

### 漏洞

函数的可见性默认是 ` public `。因此，不指定任何可见性的函数就可以由用户在外部调用。当开发人员错误地忽略应该是私有的功能（或只能在合约本身内调用）的可见性说明符时，问题就出现了。
让我们快速浏览一个简单的例子。

```solidity
contract HashForEther {
    
    function withdrawWinnings() {
        // Winner if the last 8 hex characters of the address are 0. 
        require(uint32(msg.sender) == 0);
        _sendWinnings();
     }
     
     function _sendWinnings() {
         msg.sender.transfer(this.balance);
     }
}
```

这个简单的合约被设计为充当赏金猜测游戏的地址。要赢得该合约的余额，用户必须生成一个以太坊地址，其最后 8 个十六进制字符为0。一旦获得，他们可以调用 ` WithdrawWinnings() ` 函数来获得赏金。
不幸的是，这些功能的可见性没有得到指定。特别是，因为 ` _sendWinnings() ` 函数的可见性是 ` public `，任何地址都可以调用该函数来窃取赏金。

### 预防技术

总是指定合约中所有功能的可见性、即便这些函数的可见性本就有意设计成 ` public `，这是一种很好的做法。最近版本的 Solidity 将在编译过程中为没有明确设置可见性的函数显示警告，以鼓励这种做法。

### 真实世界示例：Parity MultiSig Wallet（First Hack）

在 Parity 多签名钱包遭受的第一次黑客攻击中，约值 3100 万美元的 Ether 被盗，主要是三个钱包。Haseeb Qureshi 在[这篇文章](https://medium.freecodecamp.org/a-hacker-stole-31m-of-ether-how-it-happened-and-what-it-means-for-ethereum-9e5dc29e33ce)中给出了一个很好的回顾。

实质上，这些多签名钱包（可以在[这里](https://github.com/paritytech/parity/blob/4d08e7b0aec46443bf26547b17d10cb302672835/js/src/contracts/snippets/enhanced-wallet.sol)找到）是从一个基础的 ` Wallet ` 合约构建出来的，该基础合约调用包含核心功能的库合约（如[真实世界中的例子：Parity Multisig（Second Hack）](#真实世界示例parity-multisig-walletsecond-hack)中所述)。库合约包含初始化钱包的代码，如以下代码片段所示

```solidity
contract WalletLibrary is WalletEvents {
  
  ... 
  
  // METHODS

  ...
  
  // constructor is given number of sigs required to do protected "onlymanyowners" transactions
  // as well as the selection of addresses capable of confirming them.
  function initMultiowned(address[] _owners, uint _required) {
    m_numOwners = _owners.length + 1;
    m_owners[1] = uint(msg.sender);
    m_ownerIndex[uint(msg.sender)] = 1;
    for (uint i = 0; i < _owners.length; ++i)
    {
      m_owners[2 + i] = uint(_owners[i]);
      m_ownerIndex[uint(_owners[i])] = 2 + i;
    }
    m_required = _required;
  }

  ...

  // constructor - just pass on the owner array to the multiowned and
  // the limit to daylimit
  function initWallet(address[] _owners, uint _required, uint _daylimit) {
    initDaylimit(_daylimit);
    initMultiowned(_owners, _required);
  }
}
```

请注意，这两个函数都没有明确指定可见性。两个函数的可见性都默认为 ` public ` 。钱包构造函数会调用 ` initWallet() ` 函数，并设置多签名钱包的所有者，如 ` initMultiowned() ` 函数中所示。由于这些函数意外地设置为 ` public `，攻击者可以在部署的合约上调用这些功能，并将所有权重置为攻击者地址。作为主人，袭击者随后取走钱包中所有的 Ether，损失高达 3100 万美元。


## 随机数误区

以太坊区块链上的所有交易都是确定性的状态转换操作。这意味着每笔交易都会改变以太坊生态系统的全球状态，并且它以可计算的方式进行，没有不确定性。这最终意味着在区块链生态系统内不存在熵或随机性的来源。Solidity 中没有 ` rand() ` 功能。实现区中心化的熵源（随机性）是一个由来已久的问题，人们提出了很多想法来解决这个问题（例如，[RanDAO](https://github.com/randao/randao)，或是如 Vitalik 在[这篇帖子](https://vitalik.ca/files/randomness.html)中说的那样，使用哈希链）。

### 漏洞

以太坊平台上建立的首批合约中，有一些是围绕博彩的。从根本上讲，博彩需要不确定性（可以下注），这使得在区块链（一个确定性系统）上构建博彩系统变得相当困难。很明显，不确定性只能来自于区块链外部的来源。朋友之间怡情还是可以的（例如参见[承诺揭示技术](https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract)），然而，要让合约成为**赌场**（比如玩 21 点或是轮盘赌），则困难得多。一个常见的误区是使用未来的块变量，如区块哈希值，时间戳，区块高低或是 Gas 上限。与这些设计有关的问题是，这些量都是由挖矿的矿工控制的，因此并不是真正随机的。例如，考虑一个轮盘赌智能合约，其逻辑是如果下一个块哈希值以偶数结尾，则返回一个黑色数字。一个矿工（或矿池）可以在黑色上下注 100 万美元。如果他们挖出下一个块并发现块哈希值以奇数结尾，他们会高兴地不发布他们的块、继续挖矿、直到他们挖出一个块哈希值为偶数的块（假设区块奖励和费用低于 100 万美元）。Martin Swende 在其优秀的[博客文章](http://martin.swende.se/blog/Breaking_the_house.html)中指出，使用过去或现在的区块变量可能会更具破坏性。此外，仅使用块变量意味着伪随机数对于一个块中的所有交易都是相同的，所以攻击者可以通过在一个块内进行多次交易来使收益倍增（如果赌注有上限的话）。

### 预防技术

熵（随机性）的来源只能在区块链之外。在熟人之间，这可以通过使用诸如 [commit-reveal](https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract)之类的系统来解决，或通过将信任模型更改为一组参与者（例如 [RanDAO](https://github.com/randao/randao)）。这也可以通过一个中心化的实体来完成，这个实体充当一个随机性的预言机（Oracle）。区块变量（一般来说，有一些例外）不应该被用来提供熵，因为它们可以被矿工操纵。

### 真实世界示例：PRNG 合约

Arseny Reutov 分析了 3649 份使用某种伪随机数发生器（PRNG）的已上线智能合约，在发现 43 份可被利用的合约之后写了一篇[博文](https://blog.positive.com/predicting-random-numbers-in-ethereum-smart-contracts-e5358c6b8620)。该文详细讨论了使用区块变量作为熵源的缺陷。

## 外部合约引用

以太坊全球计算机的好处之一是能够重复使用代码、与已部署在网络上的合约进行交互。因此，大量合约引用外部合约，并且在一般运营中使用外部消息调用（External Message Call）来与这些合约交互。恶意行为者的意图可以隐藏在这些不起眼的外部消息调用之下，下面我们就来探讨这些瞒天过海的方法。

### 漏洞

在 Solidity 中，任何地址都可以被当作合约，无论地址上的代码是否表示需要用到合约类型。这可能是骗人的，特别是当合约的作者试图隐藏恶意代码时。让我们以一个例子来说明这一点：

考虑一段代码，它初步地实现了 [Rot13](https://blog.sigmaprime.io/www.wikipedia.com/rot13) 密码。

 ` Rot13Encryption.sol ` ：

```solidity
//encryption contract
contract Rot13Encryption {
     
   event Result(string convertedString);
   
    //rot13 encrypt a string
    function rot13Encrypt (string text) public {
        uint256 length = bytes(text).length;
        for (var i = 0; i < length; i++) {
            byte char = bytes(text)[i];
            //inline assembly to modify the string
            assembly {
                char := byte(0,char) // get the first byte
                if and(gt(char,0x6D), lt(char,0x7B)) // if the character is in [n,z], i.e. wrapping. 
                { char:= sub(0x60, sub(0x7A,char)) } // subtract from the ascii number a by the difference char is from z. 
                if iszero(eq(char, 0x20)) // ignore spaces
                {mstore8(add(add(text,0x20), mul(i,1)), add(char,13))} // add 13 to char. 
            }
        }
        emit Result(text);
    }
    
    // rot13 decrypt a string
    function rot13Decrypt (string text) public {
        uint256 length = bytes(text).length;
        for (var i = 0; i < length; i++) {
            byte char = bytes(text)[i];
            assembly {
                char := byte(0,char)
                if and(gt(char,0x60), lt(char,0x6E))
                { char:= add(0x7B, sub(char,0x61)) }
                if iszero(eq(char, 0x20))
                {mstore8(add(add(text,0x20), mul(i,1)), sub(char,13))}
            }
        }
        emit Result(text);
    }
}
```

得到一串字符（字母 a-z，没有验证）之后，上述代码通过将每个字符向右移动 13 个位置（围绕 'z'）来加密该字符串；即 'a' 转换为 'n'，'x' 转换为 'k'。这里的集合并不重要，所以如果在这个阶段看不出问题，不必焦躁。

考虑以下使用此代码进行加密的合约，

```solidity
import "Rot13Encryption.sol";

// encrypt your top secret info
contract EncryptionContract {
    // library for encryption
    Rot13Encryption encryptionLibrary;
        
    // constructor - initialise the library
    constructor(Rot13Encryption _encryptionLibrary) {
        encryptionLibrary = _encryptionLibrary;
    }
    
    function encryptPrivateData(string privateInfo) {
        // potentially do some operations here
        encryptionLibrary.rot13Encrypt(privateInfo);
     }
 }
```

这个合约的问题是， ` encryptionLibrary ` 地址并不是公开的或保证不变的。因此，合约的配置人员可以在指向该合约的构造函数中给出一个地址：

```solidity
//encryption contract
contract Rot26Encryption {
     
   event Result(string convertedString);
   
    //rot13 encrypt a string
    function rot13Encrypt (string text) public {
        uint256 length = bytes(text).length;
        for (var i = 0; i < length; i++) {
            byte char = bytes(text)[i];
            //inline assembly to modify the string
            assembly {
                char := byte(0,char) // get the first byte
                if and(gt(char,0x6D), lt(char,0x7B)) // if the character is in [n,z], i.e. wrapping. 
                { char:= sub(0x60, sub(0x7A,char)) } // subtract from the ascii number a by the difference char is from z. 
                if iszero(eq(char, 0x20)) // ignore spaces
                {mstore8(add(add(text,0x20), mul(i,1)), add(char,26))} // add 13 to char. 
            }
        }
        emit Result(text);
    }
    
    // rot13 decrypt a string
    function rot13Decrypt (string text) public {
        uint256 length = bytes(text).length;
        for (var i = 0; i < length; i++) {
            byte char = bytes(text)[i];
            assembly {
                char := byte(0,char)
                if and(gt(char,0x60), lt(char,0x6E))
                { char:= add(0x7B, sub(char,0x61)) }
                if iszero(eq(char, 0x20))
                {mstore8(add(add(text,0x20), mul(i,1)), sub(char,26))}
            }
        }
        emit Result(text);
    }
}
```

它实现了 rot26 密码（每个字母移动 26 个位置，明白了吗（微笑脸））。再次强调，你不需要了解本合约中的程序集。部署人员也可以链接下列合约：

```solidity
contract Print{
    event Print(string text);
    
    function rot13Encrypt(string text) public {
        emit Print(text);
    }
 }
```

如果这些合约中的任何一个的地址在构造函数中给出，那么 ` encryptPrivateData() ` 函数只会产生一个打印出未加密私有数据的事件（Event）。尽管在这个例子中，在构造函数中设置了类似库的合约，但是特权用户（例如 ` owner ` ）可以更改库合约地址。如果被链接的合约不包含被调用的函数，则将执行回退函数。例如，对于行 ` encryptionLibrary.rot13Encrypt() ` ，如果指定的合约 ` encryptionLibrary ` 是：

```solidity
 contract Blank {
     event Print(string text);
     function () {
         emit Print("Here");
         //put malicious code here and it will run
     }
 }
```

那么会发出一个带有“Here”文字的事件。因此，如果用户可以更改合约库，原则上可以让用户在不知不觉中运行任意代码。

注意：不要使用这些加密合约，因为智能合约的输入参数在区块链上可见。另外，Rot密码并不是推荐的加密技术：p

### 预防技术

如上所示，无漏洞合约可以（在某些情况下）以恶意行为的方式部署。审计人员可以公开验证合约并让其所有者以恶意方式进行部署，从而产生具有漏洞或恶意的公开审计合约。

有许多技术可以防止这些情况发生。

一种技术是使用 ` new ` 关键词来创建合约。在上面的例子中，构造函数可以写成：

```solidity
    constructor（）{
        encryptionLibrary =  new  Rot13Encryption（）;
    }
```

这样，引用合约的一个实例就会在部署时创建，并且部署者无法在不修改智能合约的情况下用其他任何东西替换 ` Rot13Encryption ` 合约。

另一个解决方案是如果已知外部合约地址的话，对所有外部合约地址进行硬编码。

一般来说，应该仔细查看调用外部合约的代码。作为开发人员，在定义外部合约时，最好将合约地址公开（在 Honey-pot 的例子中就不是这样），以便用户轻松查看合约引用了哪些代码。反过来说，如果合约具有私人变量合约地址，则它可能是某人恶意行为的标志（如现实示例中所示）。如果特权（或任何）用户能够更改用于调用外部函数的合约地址，（在去中心化系统的情境中）实现时间锁定或投票机制就变得很重要，为要允许用户查看哪些代码正在改变，或让参与者有机会选择加入/退出新的合约地址。

### 真实世界的例子：可重入钓鱼合约

最近主网上出现了一些钓鱼合约（Honey Pot）。这些合约试图打败那些想要利用合约漏洞的黑客，让他们反过来在想要利用的合约中损失 Ether。一个例子是通过在构造函数中用恶意合约代替期望的合约来发动上述攻击。代码可以在这里找到：

```solidity
pragma solidity ^0.4.19;

contract Private_Bank
{
    mapping (address => uint) public balances;
    uint public MinDeposit = 1 ether;
    Log TransferLog;
    
    function Private_Bank(address _log)
    {
        TransferLog = Log(_log);
    }
    
    function Deposit()
    public
    payable
    {
        if(msg.value >= MinDeposit)
        {
            balances[msg.sender]+=msg.value;
            TransferLog.AddMessage(msg.sender,msg.value,"Deposit");
        }
    }
    
    function CashOut(uint _am)
    {
        if(_am<=balances[msg.sender])
        {
            if(msg.sender.call.value(_am)())
            {
                balances[msg.sender]-=_am;
                TransferLog.AddMessage(msg.sender,_am,"CashOut");
            }
        }
    }
    
    function() public payable{}    
    
}

contract Log 
{
    struct Message
    {
        address Sender;
        string  Data;
        uint Val;
        uint  Time;
    }
    
    Message[] public History;
    Message LastMsg;
    
    function AddMessage(address _adr,uint _val,string _data)
    public
    {
        LastMsg.Sender = _adr;
        LastMsg.Time = now;
        LastMsg.Val = _val;
        LastMsg.Data = _data;
        History.push(LastMsg);
    }
}
```

一位 reddit 用户发布了[这篇文章](https://www.reddit.com/r/ethdev/comments/7x5rwr/tricked_by_a_honeypot_contract_or_beaten_by/)，解释他们如何在他们想利用可重入漏洞的合约中失去 1 Ether。

## 短地址/参数攻击

这种攻击并不是专门针对 Solidity 合约执行的，而是针对可能与之交互的第三方应用程序执行的。为了完整性，我添加了这个攻击，然后意识到了参数可以在合约中被操纵。

有关进一步阅读，请参阅 [ERC20 短地址攻击说明](https://vessenes.com/the-erc20-short-address-attack-explained/)，[ICO智能合约漏洞：短地址攻击](https://medium.com/huzzle/ico-smart-contract-vulnerability-short-address-attack-31ac9177eb6b)或[这个 Reddit 帖子](https://www.reddit.com/r/ethereum/comments/6r9nhj/cant_understand_the_erc20_short_address_attack/)。

### 漏洞

将参数传递给智能合约时，参数将根据 [ABI 规范](https://solidity.readthedocs.io/en/latest/abi-spec.html)进行编码。可以发送比预期参数长度短的编码参数（例如，发送只有 38 个十六进制字符（19 个字节）的地址而不是标准的 40 个十六进制字符（20 个字节））。在这种情况下，EVM 会将 0 填到编码参数的末尾以补成预期的长度。

当第三方应用程序不验证输入时，这会成为问题。最明显的例子是当用户请求提款时，交易所不验证 [ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md0) Token 的地址。Peter Venesses 的文章 “[ERC20 短地址攻击解释](http://vessenes.com/the-erc20-short-address-attack-explained/)”中详细介绍了这个例子。

考虑一下标准的 ERC20 传输函数接口，注意参数的顺序，

```
function transfer(address to, uint tokens) public returns (bool success);
```

现在考虑一下，一个交易所持有大量代（比方说 ` REP ` ），并且，某用户希望取回他们存储的100个代币。用户将提交他们的地址， ` 0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead ` 以及代币的数量 ` 100 ` 。交易所将根据 ` transfer() ` 函数指定的顺序对这些参数进行编码，即先是 ` address ` 然后是 ` tokens ` 。编码结果将是 ` a9059cbb000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead0000000000000000000000000000000000000000000000056bc75e2d63100000 ` 。前四个字节（a9059cbb）是 ` transfer() `  [函数签名/选择器](https://solidity.readthedocs.io/en/latest/abi-spec.html#function-selector)，第二个 32 字节是地址，最后 32 个字节是表示代币数量的 ` uint256 ` 。请注意，最后的十六进制数 ` 56bc75e2d63100000 ` 对应于 100 个代币（包含 18 个小数位，这是由 REP 代币合约指定的）。

好的，现在让我们看看如果我们发送一个丢失 1 个字节（2 个十六进制数字）的地址会发生什么。具体而言，假设攻击者以 ` 0xdeaddeaddeaddeaddeaddeaddeaddeaddeadde ` 作为地址发送（缺少最后两位数字），并取回相同的 ` 100 ` 个代币。如果交易所没有验证这个输入，它将被编码为 ` a9059cbb000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeadde0000000000000000000000000000000000000000000000056bc75e2d6310000000 ` 。差别是微妙的。请注意， ` 00 ` 已被填充到编码的末尾，以补完发送的短地址。当它被发送到智能合约时， ` address ` 参数将被读为 ` 0xdeaddeaddeaddeaddeaddeaddeaddeaddeadde00 ` 并且值将被读为 ` 56bc75e2d6310000000 ` （注意两个额外的 0）。此值现在是 ` 25600 ` 个代币（值已被乘以 ` 256 ` ）。在这个例子中，如果交易所持有这么多的代币，用户会取出 25600 个代币（而交换所认为用户只是取出 100）到修改后的地址。很显然，在这个例子中攻击者不会拥有修改后的地址，但是如果攻击者产生了以 0 结尾的地址（很容易强制产生）并且使用了这个生成的地址，他们很容易从毫无防备的交易所中窃取 Token。

### 预防技术

我想很明显，在将所有输入发送到区块链之前对其进行验证可以防止这些类型的攻击。还应该指出的是参数排序在这里起着重要的作用。由于填充只发生在字符串末尾，智能合约中参数的缜密排序可能会缓解此攻击的某些形式。

### 真实世界的例子：未知

我尚不知道真实世界中发生的此类攻击的公开例子。

## 不检查 CALL 返回值

Solidity 中有很多方法可以执行外部调用。向外部账户发送 Ether 通常通过 ` transfer() ` 方法完成。不过，也可以使用 ` send() ` 功能，而且，对于更多功能的外部调用，在 Solidity 中可以直接使用 ` CALL ` 操作码。 ` call() ` 和 ` send() ` 函数会返回一个布尔值，显示调用是成功还是失败。因此，这些功能有一个简单的警告作用，如果（由 ` call() ` 或 ` send() ` 初始化的）外部调用失败，执行这些函数的交易将不会回滚，反而 ` call() ` 或 ` send() ` 将简单地返回 ` false ` 。当没有检查返回值时，会出现一个常见的错误，并不是开发人员希望的那样发生回滚。

有关进一步阅读，请参阅 [DASP Top 10](http://www.dasp.co/#item-4) 和[剖析以太坊线上合约中的“Unchecked-Send”错误](http://hackingdistributed.com/2016/06/16/scanning-live-ethereum-contracts-for-bugs/)。

### 漏洞

考虑下面的例子：

```solidity
contract Lotto {

    bool public payedOut = false;
    address public winner;
    uint public winAmount;
    
    // ... extra functionality here 

    function sendToWinner() public {
        require(!payedOut);
        winner.send(winAmount);
        payedOut = true;
    }
    
    function withdrawLeftOver() public {
        require(payedOut);
        msg.sender.send(this.balance);
    }
}
```

这份合约代表了一个类似于大乐透的合约，在这种合约中， ` winner ` 会收到 ` winAmount ` 个 Ether，通常只剩下一点让其他人取出。

错误存在于第 [11] 行，其中使用 ` send() ` 而不检查响应值。在这个微不足道的例子中， ` winner ` 的交易失败（无论是通过耗尽 Gas、通过故意抛出回退函数的合约，还是调用[堆栈深度攻击](https://github.com/ethereum/wiki/wiki/Safety#call-depth-attack-deprecated)）可以使得 ` payedOut ` 被设置为 ` true ` （无论是否发送了 Ether） 。在这种情况下，公众可以通过 ` withdrawLeftOver() ` 函数取出属于 ` winner ` 的奖金。

### 预防技术

只要有可能，使用 ` transfer() ` 功能，而不是 ` send() ` ，因为，如果外部交易回滚， ` transfer() ` 会触发回滚。如果需要使用 ` send() ` ，请务必检查返回值。

一种更强大的[推荐用法](http://solidity.readthedocs.io/en/latest/common-patterns.html#withdrawal-from-contracts)是采取 *withdrawel（取出）模式*。在这个解决方案中，每个用户都得调用相互隔离的函数（即 *withdrawel* 函数），这一函数会处理将 Ether 发送到合约以外的交易，因此，它会分别处理发送失败的交易结果。这个想法是将外部发送功能与代码库的其余部分进行逻辑隔离，并将可能失败的交易负担交给正在调用 *withdrawel* 函数的最终用户。

### 真实的例子：Etherpot 和 King of Ether

[Etherpot](https://github.com/etherpot) 是一个彩票智能合约，与上面提到的示例合约不太相似。Etherpot 的 Soloidity 代码可以在这里找到：[lotto.sol](https://github.com/etherpot/contract/blob/master/app/contracts/lotto.sol)。这个合约的主要缺点是对块哈希的不当使用（只有最后 256 个块的哈希值是可用的，请参阅 Aakil Fernandes 关于 Etherpot 如何正确实现的[帖子](http://aakilfernandes.github.io/blockhashes-are-only-good-for-256-blocks)。然而，这份合约也受到未经检查的 Call 返回值的影响。注意lotto.sol 的 行[80] 上的函数 ` cash() ` ：

```solidity
  function cash(uint roundIndex, uint subpotIndex){

        var subpotsCount = getSubpotsCount(roundIndex);

        if(subpotIndex>=subpotsCount)
            return;

        var decisionBlockNumber = getDecisionBlockNumber(roundIndex,subpotIndex);

        if(decisionBlockNumber>block.number)
            return;

        if(rounds[roundIndex].isCashed[subpotIndex])
            return;
        //Subpots can only be cashed once. This is to prevent double payouts

        var winner = calculateWinner(roundIndex,subpotIndex);    
        var subpot = getSubpot(roundIndex);

        winner.send(subpot);

        rounds[roundIndex].isCashed[subpotIndex] = true;
        //Mark the round as cashed
}
```

请注意，在 行[21]，发送函数的返回值没有被检查，然后下一行设置了一个布尔值，表示已经向赢家发送了属于他们的奖金。这个错误可能引发一种状态，即赢家没有收到他们的 Ether，但是合约状态表明赢家已经得到了支付。

这个错误的更严重的版本发生在 [King of the Ether](https://www.kingoftheether.com/thrones/kingoftheether/index.html)。已经有人写出一篇优秀的[事后检验报告](https://www.kingoftheether.com/postmortem.html)，详细介绍了一个未经检查的 ` send() ` 失败交易可以如何用于攻击合约。

## 条件竞争/抢先提交

将对其它合约的外部调用以及底层区块链的多用户特性结合在一起，会在 Solidity 中产生各种潜在的缺陷，用户可能会 *争用（race）* 代码产生意外状态。[可重入漏洞](https://ethfans.org/posts/comprehensive-list-of-common-attacks-and-defense-part-1)是这种条件竞争（Race Conditions）的一个例子。在本节中，我们将更一般地讨论以太坊区块链上可能发生的各种竞态条件。在这个领域有很多不错的帖子，其中一些是：[以太坊Wiki - 安全](https://github.com/ethereum/wiki/wiki/Safety#race-conditions)，[DASP - 前台运行和共识](http://www.dasp.co/#item-7)以及[智能合约最佳实践](https://consensys.github.io/smart-contract-best-practices/known_attacks/#race-conditions)。

### 漏洞

与大多数区块链一样，以太坊节点汇集交易并将其打包成块。一旦矿工获得了共识机制（目前以太坊上实行的是 [ETHASH](https://github.com/ethereum/wiki/wiki/Ethash) 工作量证明算法）的一个解，这些交易就被认为是有效的。挖出该区块的矿工同时也选择将交易池中的哪些交易包含在该区块中，一般来说是根据交易的 ` gasPrice ` 来排序。在这里有一个潜在的攻击媒介。攻击者可以监测交易池，看看其中是否存在问题的解决方案（如下合约所示）、修改或撤销攻击者的权限、或更改合约中状态的交易；这些交易对攻击者来说都是阻碍。然后攻击者可以从该中获取数据，并创建一个 ` gasPrice ` 更高的交易，（让自己的交易）抢在原始交易之前被打包到一个区块中。

让我们看看这可以如何用一个简单的例子。考虑合约 ` FindThisHash.sol ` ：

```solidity
contract FindThisHash {
    bytes32 constant public hash = 0xb5b5b97fafd9855eec9b41f74dfb6c38f5951141f9a3ecd7f44d5479b630ee0a;
    
    constructor() public payable {} // load with ether
    
    function solve(string solution) public {
        // If you can find the pre image of the hash, receive 1000 ether
        require(hash == sha3(solution)); 
        msg.sender.transfer(1000 ether);
    }
}
```

想象一下，这个合约包含 1000 个 Ether。可以找到 sha3 哈希值为 ` 0xb5b5b97fafd9855eec9b41f74dfb6c38f5951141f9a3ecd7f44d5479b630ee0a ` 的原象（Pre-image）的用户可以提交解决方案，然后取得 1000 Ether。让我们假设，一个用户找到了答案 ` Ethereum! ` 。他们可以调用 ` solve() ` 并将 ` Ethereum! ` 作为参数。不幸的是，攻击者非常聪明，他监测交易池看看有没有人提交解决方案。他们看到这个解决方案，检查它的有效性，然后提交一个 ` gasPrice ` 远高于原始交易的相同交易。挖出当前块的矿工可能会因更高的 ` gasPrice ` 而偏爱攻击者发出的交易，并在打包原始交易之前接受他们的交易。攻击者将获得1000 Ether，解决问题的用户将不会得到任何东西（因为合约中没有剩余的 Ether）。

未来 Casper 实现的设计中会出现更现实的问题。Casper 权益证明合约涉及罚没条件，在这些条件下，注意到验证者双重投票或行为不当的用户被激励提交验证者已经这样做的证据。验证者将受到惩罚、用户会得到奖励。在这种情况下，可以预期，矿工和用户会抢先提交（Front-run）所有这样的证据（以获得奖励），这个问题必须在最终发布之前解决。

### 预防技术

有两类用户可以执行这种抢先提交攻击。用户（他们可以修改他们交易的 ` gasPrice ` ）和矿工自己（他可以依自己的意愿安排包含在块中的交易）。易受第一类（用户）攻击的合约比易受第二类（矿工）影响的合约明显更差，因为矿工只能在挖出某个块时执行攻击，对任何单个矿工来说都不太可能针对特定区块发动攻击（译者注：因为他们不一定能挖出特定高度的区块）。在这里，我将列出一些与他们可能阻止的攻击者类别有关的缓解措施。

可以采用的一种方法是在合约中创建逻辑，设置 ` gasPrice ` 的上限。这可以防止用户增加 ` gasPrice ` 并因超出上限而获得优先的交易排序。这种预防措施只能缓解第一类攻击者（任意用户）。在这种情况下，矿工仍然可以攻击合约，因为无论 Gas价格如何，他们都可以安排包含在他们的块中的交易。

一个更强大的方法是尽可能使用 [承诺-公开（commit-reveal）](https://ethereum.stackexchange.com/questions/191/how-can-i-securely-generate-a-random-number-in-my-smart-contract ) 方案。这种方案规定用户使用隐藏信息（通常是哈希值）发送交易。在交易已包含在块中后，用户将发送一个交易来显示已发送的数据（reveal 阶段）。这种方法可以防止矿工和用户从事抢先交易，因为他们无法确定交易的内容。然而，这种方法不能隐藏交易价值（在某些情况下，这是需要隐藏的有价值的信息）。[ENS](https://ens.domains/) 智能合约允许用户发送交易，其承诺数据包括他们愿意花费的金额。用户可以发送任意值的交易。在披露阶段，用户可以取出交易中发送的金额与他们愿意花费的金额之间的差额。

Lorenz、Phil、Ari 以及 Florian 的进一步建议是使用 [Submarine Sends](http://hackingdistributed.com/2017/08/28/submarine-sends/)。这个想法的有效实现需要 ` CREATE2 ` 操作码，目前还没有被采用，但可能出现在即将到来的硬分叉上。

### 真实世界的例子：ERC20 和 Bancor

[ERC20](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md)是相当知名的在以太坊上开发代币的标准。这个标准有一个潜在的抢先提交漏洞，这个漏洞是由于 ` approve() ` 功能而产生的。这个漏洞的一个很好的解释可以在[这里](https://docs.google.com/document/d/1YLPtQxZu1UAvO9cZ1O2RPXBbT0mooh4DYKjA_jp-RLM/edit)找到。

该标准规定的 ` approve() ` 功能如下：

``` 
function approve(address _spender, uint256 _value) returns (bool success)
```

该功能让用户可以授权其他用户代表他们转移代币。当用户Alice *批准（Approve）* 她的朋友 Bob 花费 ` 100 tokens ` 时，这种先发制人的漏洞就会出现。Alice 后来决定，她想撤销对 Bob 花费 ` 100 tokens ` 的批准，所以她创建了一个交易，设置 Bob 的份额为 ` 50 tokens ` 。Bob 一直在仔细监测链上数据，看到这笔交易之后他建立了一笔他自己的交易，花费了 ` 100 tokens ` 。他给自己的交易设置了比 Alice 交易更高的 ` gasPrice ` ，让自己的交易优先于她的交易。一些 ` approve() ` 的实现允许 Bob 转移他的 ` 100 tokens ` ，然后当 Alice 的交易被提交时，重置 Bob 的批准份额为 ` 50 tokens ` ，实际上允许 Bob 调动 ` 150 tokens ` 。上面链接到的[文档](https://docs.google.com/document/d/1YLPtQxZu1UAvO9cZ1O2RPXBbT0mooh4DYKjA_jp-RLM/edit)给出了针对这一攻击的缓解策略。

另一个突出的现实世界的例子是 [Bancor](https://www.bancor.network/)。Ivan Bogatty 和他的团队记录了对 Bancor 初始实现的有利可图的攻击。他的[博客文章](https://hackernoon.com/front-running-bancor-in-150-lines-of-python-with-ethereum-api-d5e2bfd0d798)和[Devcon 3 演讲](https://www.youtube.com/watch?v=RL2nE3huNiI)详细讨论了这是如何完成的。基本上，代币的价格是根据交易价值确定的，用户可以观测 Bancor 交易的交易池，并抢先提交它们以从价格差异中获利。Bancor 团队已经解决了这种攻击。

## 拒绝服务（DOS）

这个类别非常广泛，但其基本攻击形式都是让用户短暂地（在某些情形下，是永久）推出不可操作的合约。这种攻击可以把 Ether 永远锁在被攻击的合约中，正如 [Parity 多签名钱包第二次被黑](#真实世界示例parity-multisig-walletsecond-hack)中的情形一样。

### 漏洞

有很多办法可以让合约变得不可操作。这里我只强调一些微妙的区块链 Solidity 编码模式，虽然看不太出来，但可能留下让攻击者执行 DOS 攻击的空间。

**1.通过外部操纵映射或数组（Array）循环** ——在我的经历中，我看过此种模式的各种形式。通常情况下，它出现在 ` owner ` 希望在其投资者之间分配代币的情况下，以及，在合约中可以看到类似于 ` distribute() ` 函数的情况下：

```solidity
contract DistributeTokens {
    address public owner; // gets set somewhere
    address[] investors; // array of investors
    uint[] investorTokens; // the amount of tokens each investor gets
    
    // ... extra functionality, including transfertoken()
    
    function invest() public payable {
        investors.push(msg.sender);
        investorTokens.push(msg.value * 5); // 5 times the wei sent
        }
    
    function distribute() public {
        require(msg.sender == owner); // only owner
        for(uint i = 0; i < investors.length; i++) { 
            // here transferToken(to,amount) transfers "amount" of tokens to the address "to"
            transferToken(investors[i],investorTokens[i]); 
        }
    }
}
```

请注意，此合约中的循环遍历的数组可以被人为扩充。攻击者可以创建许多用户帐户，让 ` investor ` 数据变得更大。原则上来说，可以让执行 for 循环所需的 Gas 超过区块 Gas 上限，这会使 ` distribute() ` 函数变得无法操作。

**2.所有者操作**——另一种常见模式是所有者在合约中具有特定权限，并且必须执行一些任务才能使合约进入下一个状态。例如，ICO 合约要求所有者 ` finalize() ` 签订合约，然后才可以转让代币，即

```solidity
bool public isFinalized = false;
address public owner; // gets set somewhere

function finalize() public {
    require(msg.sender == owner);
    isFinalized == true;
}

// ... extra ICO functionality

// overloaded transfer function
function transfer(address _to, uint _value) returns (bool) {
    require(isFinalized);
    super.transfer(_to,_value)
}
```

在这种情况下，如果权限用户丢失其私钥或变为非活动状态，则整个代币合约就变得无法操作。在这种情况下，如果 ` owner ` 无法调用 ` finalize() ` 则代币不可转让；即代币系统的全部运作都取决于一个地址。

**3.基于外部调用的进展状态**——有时候，合约被编写成为了进入新的状态需要将 Ether 发送到某个地址，或者等待来自外部来源的某些输入。这些模式也可能导致 DOS 攻击：当外部调用失败时，或由于外部原因而被阻止时。在发送 Ether 的例子中，用户可以创建一个不接受 Ether 的合约。如果合约需要将 Ether 发送到这个地址才能进入新的状态，那么合约将永远不会达到新的状态，因为 Ether 永远不会被发送到合约。

### 预防技术

在第一个例子中，合约不应该遍历可以被外部用户人为操纵的数据结构。建议使用 withdrawal 模式，每个投资者都会调用取出函数独立取出代币。

在第二个例子中，改变合约的状态需要权限用户参与。在这样的例子中（只要有可能），如果 ` owner ` 已经瘫痪，可以使用自动防故障模式。一种解决方案是将 ` owner ` 设为一个多签名合约。另一种解决方案是使用一个时间锁，其中 [13]行 上的需求可以包括在基于时间的机制中，例如 ` require(msg.sender == owner || now > unlockTime) ` ，那么在由 ` unlockTime ` 指定的一段时间后，任何用户都可以调用函数，完成合约。这种缓解技术也可以在第三个例子中使用。如果需要进行外部调用才能进入新状态，请考虑其可能的失败情况；并添加基于时间的状态进度，防止所需外部调用迟迟不到来。

*注意：当然，这些建议都有中心化的替代方案，比如，可以添加 ` maintenanceUser ` ，它可以在有需要时出来解决基于 DOS 攻击向量的问题。通常，这类合约包含对这类权力实体的信任问题；不过这不是本节要探讨的内容*。

### 真实的例子：GovernMental

[GovernMental](http://governmental.github.io/GovernMental/)是一个古老的庞氏骗局，积累了相当多的 Ether。实际上，它曾经积累起 1100 个以太。不幸的是，它很容易受到本节提到的 DOS 漏洞的影响。[这篇 Reddit  帖子](https://www.reddit.com/r/ethereum/comments/4ghzhv/governmentals_1100_eth_jackpot_payout_is_stuck/)描述了合约需要删除一个大的映射来取出以太。删除映射的 Gas 消耗量超过了当时的区块 Gas 上限，因此不可能撤回那 1100 个 Ether。合约地址为 [` 0xF45717552f12Ef7cb65e95476F217Ea008167Ae3 `](https://etherscan.io/address/0xf45717552f12ef7cb65e95476f217ea008167ae3)，您可以从交易[` 0x0d80d67202bd9cb6773df8dd2020e7190a1b0793e8ec4fc105257e8128f0506b `](https://etherscan.io/tx/0x0d80d67202bd9cb6773df8dd2020e7190a1b0793e8ec4fc105257e8128f0506b)中看到，最后有人通过使用 250 万 Gas的交易取出了 1100 Ether 。

## 操纵区块时间戳

区块时间戳历来被用于各种应用，例如随机数的函数（请参阅[随机数误区](#随机数误区)以获取更多详细信息）、锁定一段时间的资金、以及各种基于时间变更状态的条件语句。矿工有能力稍微调整时间戳，如果在智能合约中错误地使用区块时间戳，可以证明这是相当危险的。

一些有用的参考资料是：[Solidity Docs](http://solidity.readthedocs.io/en/latest/units-and-global-variables.html#block-and-transaction-properties)，以及这个 [Stack Exchange 上的问题](https://ethereum.stackexchange.com/questions/413/can-a-contract-safely-rely-on-block-timestamp?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa)。

### 漏洞

 ` block.timestamp ` 或者别名 ` now ` 可以由矿工操纵，如果他们有这样做的激励的话。让我们构建一个简单的、容易受到矿工的剥削的游戏，

 ` roulette.sol ` ：

```solidity
contract Roulette {
    uint public pastBlockTime; // Forces one bet per block
    
    constructor() public payable {} // initially fund contract
    
    // fallback function used to make a bet
    function () public payable {
        require(msg.value == 10 ether); // must send 10 ether to play
        require(now != pastBlockTime); // only 1 transaction per block
        pastBlockTime = now;
        if(now % 15 == 0) { // winner
            msg.sender.transfer(this.balance);
        }
    }
}
```

这份合约是一个简单的彩票。每个区块都有一笔交易可以下注 10 Ether，获得机会赢取合约中的全部余额。这里的假设是， ` block.timestamp ` 的最后两位数字是均匀分布的。如果是这样，那么将有 1/15 的机会赢得这个彩票。

但是，正如我们所知，矿工可以根据自己的意愿调整时间戳。在这种特殊情况下，如果合约中有足够的 Ether，挖出某个区块的矿工将被激励选择一个 ` block.timestamp ` 或 ` now ` 对 15 取余为 ` 0 ` 的时间戳。在这样做的时候，他们可能会赢得这个合约中的 Ether 以及区块奖励。由于每个区块只允许一个人下注，所以这也容易受到[抢先提交攻击](#条件竞争/抢先提交)。

在实践中，区块时间戳是单调递增的，所以矿工不能选择任意块时间戳（它们必须大于其祖先块）。区块时间也不能是未来值，因为这些块可能会被网络拒绝（节点不会验证其时间戳指向未来的块）。

### 预防技术

区块时间戳不应该用于熵源或产生随机数——也就是说，它们不应该是游戏判定胜负或改变重要状态（如果假定为随机）的决定性因素（无论是直接还是通过某些推导）。

时效性强的逻辑有时是必需的；即解锁合约（时间锁定），几周后完成 ICO 或到期强制执行。有时建议使用 ` block.number `（参见 [Solidity 文档](http://solidity.readthedocs.io/en/latest/units-and-global-variables.html#block-and-transaction-properties)）和平均区块时间来估计时间；即，10 秒的区块时间运行 1 周，约等于，60480 个区块。因此，指定区块编号来更改合约状态可能更安全，因为矿工无法轻松操纵区块编号。[BAT ICO合约](https://etherscan.io/address/0x0d8775f648430679a709e98d2b0cb6250d2887ef#code)就采用这种策略。

如果合约不是特别关心矿工对区块时间戳的操纵，这可能是不必要的，但是在开发合约时应该注意这一点。

### 真实的例子：GovernMental

[GovernMental](http://governmental.github.io/GovernMental/) 是一个古老的庞氏骗局，积累了相当多的 Ether。它也容易受到基于时间戳的攻击。合约会在一轮内支付给最后一个加入合约的玩家（需要加入至少一分钟）。因此，作为玩家的矿工可以调整时间戳（未来的时间，使其看起来像是一分钟过去了），以显示玩家加入已经超过一分钟（尽管现实中并非如此）。关于这方面的更多细节可以在 Tanya Bahrynovska 的 [*以太坊安全漏洞史*](https://applicature.com/blog/history-of-ethereum-security-vulnerabilities-hacks-and-their-fixes) 中找到。

## 谨慎构造函数

构造函数是特殊函数，在初始化合约时经常执行关键的特权任务。在solidity v0.4.22构造函数被定义为与包含它们的合约名称相同的函数之前。因此，如果合约名称在开发过程中发生变化，如果构造函数名称没有更改，它将变成正常的可调用函数。正如你可以想象的，这可以（并且）导致一些有趣的合约黑客。
为了进一步阅读，我建议读者尝试Ethernaught挑战（特别是辐射水平）。

### 漏洞

如果合约名称被修改，或者在构造函数名称中存在拼写错误以致它不再与合约名称匹配，则构造函数的行为将与普通函数类似。这可能会导致可怕的后果，特别是如果构造函数正在执行特权操作。考虑以下合约：

```solidity
contract OwnerWallet {
    address public owner;

    //constructor
    function ownerWallet(address _owner) public {
        owner = _owner;
    }
    
    // fallback. Collect ether.
    function () payable {} 
    
    function withdraw() public {
        require(msg.sender == owner); 
        msg.sender.transfer(this.balance);
    }
}
```

该合约收集以太，并只允许所有者通过调用该withdraw()函数来撤销所有以太。这个问题是由于构造函数没有完全以合约名称命名的。具体来说，ownerWallet是不一样的OwnerWallet。因此，任何用户都可以调用该ownerWallet()函数，将自己设置为所有者，然后通过调用将合约中的所有内容都取出来withdraw()。

### 预防技术

这个问题已经在Solidity编译器的版本中得到了主要解决0.4.22。该版本引入了一个constructor指定构造函数的关键字，而不是要求函数的名称与契约名称匹配。建议使用此关键字来指定构造函数，以防止上面突出显示的命名问题。

### 真实世界的例子：Rubixi

Rubixi（合约代码）是另一个展现这种脆弱性的传销方案。它最初被调用，DynamicPyramid但合约名称在部署之前已更改Rubixi。构造函数的名字没有改变，允许任何用户成为creator。关于这个bug的一些有趣的讨论可以在这个比特币线程中找到。最终，它允许用户争取creator地位，从金字塔计划中支付费用。关于这个特定bug的更多细节可以在这里找到。

## 虚拟化存储指针

EVM将数据存储为storage或作为memory。开发合约时强烈建议如何完成这项工作，并强烈建议函数局部变量的默认类型。这是因为可能通过不恰当地初始化变量来产生易受攻击的合约。
要了解更多关于storage和memory的EVM，看到Solidity Docs: Data Location，Solidity Docs: Layout of State Variables in Storage，Solidity Docs: Layout in Memory。
本节以Stefan Beyer出色的文章为基础。关于这个话题的进一步阅读可以从Sefan的灵感中找到，这是这个reddit思路。

### 漏洞

函数内的局部变量默认为storage或memory取决于它们的类型。未初始化的本地storage变量可能会指向合约中的其他意外存储变量，从而导致故意（即，开发人员故意将它们放在那里进行攻击）或无意的漏洞。
我们来考虑以下相对简单的名称注册商合约：

```solidity
// A Locked Name Registrar
contract NameRegistrar {

    bool public unlocked = false;  // registrar locked, no name updates
    
    struct NameRecord { // map hashes to addresses
        bytes32 name;  
        address mappedAddress;
    }

    mapping(address => NameRecord) public registeredNameRecord; // records who registered names 
    mapping(bytes32 => address) public resolve; // resolves hashes to addresses
    
    function register(bytes32 _name, address _mappedAddress) public {
        // set up the new NameRecord
        NameRecord newRecord;
        newRecord.name = _name;
        newRecord.mappedAddress = _mappedAddress; 

        resolve[_name] = _mappedAddress;
        registeredNameRecord[msg.sender] = newRecord; 

        require(unlocked); // only allow registrations if contract is unlocked
    }
}
```

这个简单的名称注册商只有一个功能。当合约是unlocked，它允许任何人注册一个名称（作为bytes32散列）并将该名称映射到地址。不幸的是，此注册商最初被锁定，并且require在线[23]禁止register()添加姓名记录。然而，在这个合约中存在一个漏洞，它允许名称注册而不管unlocked变量。

为了讨论这个漏洞，首先我们需要了解存储在Solidity中的工作方式。作为一个高层次的概述（没有任何适当的技术细节 - 我建议阅读Solidity文档以进行适当的审查），状态变量按顺序存储在合约中出现的插槽中（它们可以组合在一起，但在本例中不可以，所以我们不用担心）。因此，unlocked存在于slot 0，registeredNameRecord在存在slot 1和resolve在slot 2等。这些槽是字节大小32（有与我们忽略现在映射添加的复杂性）。布尔unlocked将看起来像0x000...0（64 0，不包括0x）for false或0x000...1（63 0's）true。正如你所看到的，在这个特殊的例子中，存储会有很大的浪费。

下一个资料，我们需要的，是Solidity违约复杂数据类型，例如structs，以storage初始化它们作为局部变量时。因此，newRecord在行[16]上默认为storage。该漏洞是由newRecord未初始化的事实引起的。由于它默认为存储，因此它成为存储指针，并且由于它未初始化，它指向插槽0（即unlocked存储位置）。请注意，上线[17]和[18]我们然后设置nameRecord.name到_name和nameRecord.mappedAddress到_mappedAddress，这实际上改变了时隙0和时隙1的存储位置用于修改都unlocked和与之相关联的存储槽registeredNameRecord。

这意味着unlocked可以直接通过函数的bytes32 _name参数进行修改register()。因此，如果最后一个字节为_name非零，它将修改存储的最后一个字节slot 0并直接转换unlocked为true。这样_name的值将通过require()线[23]，因为我们正在设置unlocked到true。在Remix中试试这个。注意如果你使用下面_name的形式，函数会通过：0x0000000000000000000000000000000000000000000000000000000000000001

### 预防技术

Solidity编译器会提出未经初始化的存储变量作为警告，因此开发人员在构建智能合约时应小心注意这些警告。当前版本的mist（0.10）不允许编译这些合约。在处理复杂类型时明确使用memory或storage确定它们的行为如预期一般是很好的做法。

### 真实世界的例子：蜜罐：OpenAddressLottery和CryptoRoulette

一个名为OpenAddressLottery（合约代码）的蜜罐被部署，它使用这个未初始化的存储变量querk从一些可能的黑客收集ether。合约是相当深入的，所以我会把讨论留在这个reddit思路中，这个攻击很清楚地解释了。

另一个蜜罐，CryptoRoulette（合约代码）也利用这个技巧尝试并收集一些以太。如果您无法弄清楚攻击是如何进行的，请参阅对以太坊蜜罐合约的分析以获得对此合约和其他内容的概述。

## 浮点和精度

在撰写本文时（Solidity v0.4.24），不支持定点或浮点数。这意味着浮点表示必须用Solidity中的整数类型进行表示。如果没有正确实施，这可能会导致错误/漏洞。

如需进一步阅读，请参阅以太坊合约安全技术和提示 - 使用整数部分舍入，

### 漏洞

由于Solidity中没有固定点类型，因此开发人员需要使用标准整数数据类型来实现它们自己的类型。在这个过程中，开发人员可能遇到一些陷阱。我将尝试在本节中重点介绍其中的一些内容。

让我们从一个代码示例开始（为简单起见，忽略任何over / under流问题）。

```solidity
contract FunWithNumbers {
    uint constant public tokensPerEth = 10; 
    uint constant public weiPerEth = 1e18;
    mapping(address => uint) public balances;

    function buyTokens() public payable {
        uint tokens = msg.value/weiPerEth*tokensPerEth; // convert wei to eth, then multiply by token rate
        balances[msg.sender] += tokens; 
    }
    
    function sellTokens(uint tokens) public {
        require(balances[msg.sender] >= tokens);
        uint eth = tokens/tokensPerEth; 
        balances[msg.sender] -= tokens;
        msg.sender.transfer(eth*weiPerEth); //
    }
}
```

这个简单的令牌买/卖合约在代币的买卖中存在一些明显的问题。虽然买卖令牌的数学计算是正确的，但浮点数的缺乏会给出错误的结果。例如，当在线[7]上购买令牌时，如果该值小于1 ether最初的除法将导致0最后的乘法0（即200 wei除以1e18weiPerEth等于0）。同样，当销售代币时，任何代币10都不会产生0 ether。事实上，这里四舍五入总是下降，所以销售29 tokens，将导致2 ether。

这个合约的问题是精度只能到最近的ether（即1e18 wei）。当您需要更高的精度时，decimals在处理ERC20令牌时，这有时会变得棘手。

### 预防技术

保持智能合约的正确精确度非常重要，尤其是在处理反映经济决策的比率和比率时。
您应该确保您使用的任何比率或比率都允许分数中的大分子。例如，我们tokensPerEth在示例中使用了费率。使用weiPerTokens这将是一个很大的数字会更好。解决我们可以做的令牌数量问题msg.sender/weiPerTokens。这会给出更精确的结果。

要记住的另一个策略是注意操作的顺序。在上面的例子中，购买令牌的计算是msg.value/weiPerEth *tokenPerEth。请注意，除法发生在乘法之前。如果计算首先进行乘法，然后再进行除法，那么这个例子会达到更高的精度msg.value* tokenPerEth/weiPerEth。

最后，当为数字定义任意精度时，将变量转换为更高精度，执行所有数学运算，然后最后在需要时将其转换回输出精度可能是一个好主意。通常uint256使用它们（因为它们对于gas使用来说是最佳的），它们的范围约为60个数量级，其中一些可用于数学运算的精确度。可能会出现这样的情况：最好将所有变量高精度地保持稳定并在外部应用程序中转换回较低的精度（这实际上是ERC20令牌合约中decimals变量的工作原理）。要查看如何完成此操作的示例以及要执行此操作的库，我建议查看Maker DAO DSMath。他们使用一些时髦的命名WAD的和RAY的，但这个概念是非常有用的。


### 真实世界的例子：Ethstick

我无法找到一个很好的例子，说明四舍五入导致合约中出现严重问题，但我相信这里有很多。如果你有一个好的想法，请随时更新。

由于缺乏一个很好的例子，我想引起您对Ethstick的关注，主要是因为我喜欢合约中的酷命名。但是，这个合约并没有使用任何扩展的精确度wei。所以这个合约会有四舍五入的问题，但只是在wei精确度方面。它有一些更严重的缺陷，但这些都与区块链上的函数有关（见Entropty Illusion）。关于Ethstick合约的进一步讨论，我会把你推荐给Peter Venesses的另一篇文章，以太坊合约对于黑客来说就是糖果。

## Tx.Origin身份验证

Solidity具有一个全局变量，tx.origin它遍历整个调用栈并返回最初发送调用（或事务）的帐户的地址。在智能合约中使用此变量进行身份验证会使合约容易受到类似网络钓鱼的攻击。
有关进一步阅读，请参阅Stack Exchange Question，Peter Venesses博客和Solidity - Tx.Origin攻击。

### 漏洞

授权用户使用该tx.origin变量的合约通常容易受到网络钓鱼攻击的攻击，这可能会诱使用户对易受攻击的合约执行身份验证操作。
考虑简单的合约，

```solidity
contract Phishable {
    address public owner;
    
    constructor (address _owner) {
        owner = _owner; 
    }
    
    function () public payable {} // collect ether

    function withdrawAll(address _recipient) public {
        require(tx.origin == owner);
        _recipient.transfer(this.balance); 
    }
}
```

请注意，在[11]行中，此合约授权withdrawAll()使用该功能tx.origin。该合约允许攻击者创建表单的攻击合约，

```solidity
import "Phishable.sol";

contract AttackContract { 
    
    Phishable phishableContract; 
    address attacker; // The attackers address to receive funds.

    constructor (Phishable _phishableContract, address _attackerAddress) { 
        phishableContract = _phishableContract; 
        attacker = _attackerAddress;
    }
    
    function () { 
        phishableContract.withdrawAll(attacker); 
    }
}
```

为了利用这个合约，攻击者会部署它，然后说服Phishable合约的所有者发送一定数量的合约。攻击者可能把这个合约伪装成他们自己的私人地址，社工受害人发送某种形式的交易到地址。受害者除非注意，否则可能不会注意到攻击者地址上有代码，或者攻击者可能将其作为多重签名钱包或某些高级存储钱包传递。

在任何情况下，如果受害者向AttackContract地址发送了一个事务（有足够的天然气），它将调用fallback功能，后者又调用该参数withdrawAll()的Phishable合约功能attacker。这将导致所有资金从Phishable合约中撤回到attacker地址。这是因为，首先初始化呼叫的地址是受害者（即owner中的Phishable合约）。因此，tx.origin将等于owner和require所述的上线[11] Phishable合约会通过。

### 预防技术

tx.origin不应该用于智能合约授权。这并不是说该tx.origin变量不应该被使用。它确实在智能合约中有一些合法用例。例如，如果有人想要拒绝外部合约调用当前合约，他们可以实现一个requirefrom require(tx.origin == msg.sender)。这可以防止用于调用当前合约的中间合约，将合约限制为常规无代码地址。

### 真实世界的例子：未知

我不知道这种形式在野的任何公开的利用。

## 以太坊怪异模式

我打算用社区发现的各种有趣怪癖填充本节。这些都保存在这个博客中，因为如果在实践中使用这些怪癖，它们可能有助于智能合约开发。

### 无键ether

合约地址是确定性的，这意味着它们可以在实际创建地址之前进行计算。创建合约的地址和产生其他合约的合约都是这种情况。实际上，创建的合约地址取决于：

 ` keccak256(rlp.encode([<account_address>, <transaction_nonce>]) ` 

从本质上讲，合约的地址就是keccak256创建它与账户事务随机数[^ 2]连接的账户的哈希值。合约也是如此，除了合约nonce的开始1地址的交易nonce的开始0。

这意味着给定一个以太坊地址，我们可以计算出该地址可以产生的所有可能的合约地址。例如，如果地址0x123000...000是在其第100次交易中创建合约keccak256(rlp.encode[0x123...000, 100])，则会创建合约地址，该地址将提供合约地址0xed4cafc88a13f5d58a163e61591b9385b6fe6d1a。

这是什么意思呢？这意味着您可以将ether发送到预先确定的地址（您不拥有私钥的地址，但知道您的某个帐户可以创建合约）。您可以将ether发送到该地址，然后通过稍后创建在同一地址上生成的合约来检索以太网。构造函数可用于返回所有预先发送的以太。因此，如果有人在哪里获得你的以太坊私钥，攻击者很难发现你的以太坊地址也可以访问这个隐藏的以太网。事实上，如果攻击者花费太多事务处理，以致需要访问您的以太网的随机数，则不可能恢复您的隐藏以太网。
让我用合约澄清一下。

```solidity
contract KeylessHiddenEthCreator { 
    uint public currentContractNonce = 1; // keep track of this contracts nonce publicly (it's also found in the contracts state)

    // determine future addresses which can hide ether. 
    function futureAddresses(uint8 nonce) public view returns (address) {
        if(nonce == 0) {
            return address(keccak256(0xd6, 0x94, this, 0x80));
        }
        return address(keccak256(0xd6, 0x94, this, nonce));
    // need to implement rlp encoding properly for a full range of nonces
    }
    
    // increment the contract nonce or retrieve ether from a hidden/key-less account
    // provided the nonce is correct
    function retrieveHiddenEther(address beneficiary) public returns (address) {
    currentContractNonce +=1;
       return new RecoverContract(beneficiary);
    }
    
    function () payable {} // Allow ether transfers (helps for playing in remix)
}

contract RecoverContract { 
    constructor(address beneficiary) {
        selfdestruct(beneficiary); // don't deploy code. Return the ether stored here to the beneficiary. 
    }
 }
```

这个合约允许你存储无密钥的以太（相对安全，从某种意义上说你不能错误地忽略随机数）[^ 3]。该futureAddresses()功能可用于计算此合约可产生的前127个合约地址，方法是指定nonce。如果您将ether发送到其中一个地址，则可以稍后通过调用retrieveHiddenEther()足够的时间来恢复。例如，如果您选择nonce=4（并将ether发送到关联的地址），则需要调用retrieveHiddenEther()四次，然后将以太网恢复到该beneficiary地址。

这可以在没有合约的情况下完成。您可以将ether发送到可以从您的一个标准以太坊帐户创建的地址，并在以后以正确的随机数恢复。但是要小心，如果你不小心超过了恢复你的以太币所需的交易随机数，你的资金将永远丢失。

有关一些更高级的技巧，你可以用这个怪癖做更多的信息，我推荐阅读Martin Swende的文章。

### 一次性地址

以太坊交易签名使用椭圆曲线数字签名算法（ECDSA）。通常，为了在以太坊上发送经过验证的交易，您需要使用您的以太坊私钥签署一条消息，该私钥授权从您的账户中支出。在稍微更详细，您注册的消息是复仇交易的组成部分，具体而言，to，value，gas，gasPrice，nonce和data领域。以太坊签名的结果是三个数字v，r和s。我不会详细说明这些代表的内容，而是将感兴趣的读者引至ECDSA wiki页面（描述r和s）以及Ethereum Yellow Paper（附录F--描述v），最后EIP155为当前使用v。

所以我们知道以太坊交易签名包含一条消息和数字v，r并且s。我们可以通过使用消息（即交易细节）来检查签名是否有效，r并s派生出以太坊地址。如果派生的以太坊地址匹配from事务的字段，那么我们知道r并且s由拥有（或有权访问）该from字段的私钥的人创建，因此签名是有效的。

现在考虑一下，我们并不拥有一个私钥，而是为任意事务构建值r和值s。考虑我们有一个交易，参数为：
{to ： “ 0xa9e ”，value ： 10e18，nonce ： 0 }

我忽略了其他参数。该交易将发送10位以太网到该0xa9e地址。现在让我们说我们做了一些数字r和s（这些有特定的范围）和v。如果我们推导出与这些编号相关的以太坊地址，我们将得到一个随机的以太坊地址，让我们来调用它0x54321。知道这个地址，我们可以向地址发送10个ether 0x54321（不需要拥有该地址的私钥）。在将来的任何时候，我们都可以发送交易，
{to ： “ 0xa9e ”，value ： 10e18，nonce ： 0，from ： “ 0x54321 ” }

以及签名，即v，r和s我们组成。这将是一个有效的交易，因为派生地址将匹配我们的from字段。这使我们可以将我们的钱从这个随机地址（0x54321）中分配到我们选择的地址0xa9e。因此，我们设法将ether存储在我们没有私钥的地址中，并使用一次性事务来恢复以太。

这个怪癖还可以用来以无可信赖的方式向许多人发送ether，正如尼克约翰逊在“ 如何将ether发送给11,440人”中所描述的那样。

## 有趣的加密相关的hacks/bugs列表

* [CoinDash](https://www.theregister.co.uk/2017/07/18/coindash_hack/)
* [SmartBillions](https://www.reddit.com/r/ethereum/comments/74d3dc/smartbillions_lottery_contract_just_got_hacked/)
* [Exchange Didn't add "0x" to payload](https://steemit.com/cryptocurrency/@barrydutton/breaking-the-biggest-canadian-coin-exchange-quadrigacx-loses-67-000-usdeth-due-to-coding-error-funds-locked-in-an-executable)

[^ 1]: 此代码已从web3j修改过
[^ 2]: 事务随机数就像一个事务计数器。从您的账户发送交易时，它会增加您的交易时间。
[^ 3]: 不要部署此合约来存储任何真实的以太网。仅用于演示目的。它没有固有的特权，任何人都可以在部署和使用它时恢复以太网。

## 致谢

* [yudan](https://github.com/infinityhacker)
* [阿剑@EthFans](https://github.com/editor-Ajian)

