<?php
//connection to DB
include "config.php";
	
	$conn = new PDO("mysql:host=$adress;dbname=$database", $user, $pass);
	$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  	
?>