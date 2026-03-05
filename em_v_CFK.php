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
