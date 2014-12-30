<html>
<head>	
<style>
table#content {
	position: absolute;
	top:20px;
	left:50%;
	width:900px;
	background-color:#EEEEEE;
	margin-left:-450px;
	word-break:break-all; 
	word-wrap:break-all;
}

</style>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
</head>
<body>
<?php
session_start();
$hostname = $_SESSION["hostname"];
$username = $_SESSION["username"]; 
$password = $_SESSION["password"];
$database = $_SESSION["database"];

$link = mysql_connect($hostname, $username, $password);
$select = mysql_select_db($database, $link);

$id=$_GET['id']; 
$sql = "select * from web where id=$id;";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
?>

<table id="content">
	<caption bgcolor="#99bbbb" >
		<h2>Web请求信息</h2>
	</caption>

	<tr>
	<td>源IP地址 : <?= $row[srcip]?></td>
	<td>目的IP地址 : <?= $row[dstip]?></td>
	</tr>
	<tr>
	<td colspan="2">时间 : <?= $row[time]?></td>
	</tr>
	<tr>
	<td colspan="2">Host : <?= $row[host]?></td>
	</tr>
	<tr>
	<td colspan="2">Url : <?= $row[url]?></td>
	</tr>
	<tr>
	<td colspan="2">Reference : <?= $row[referer]?></td>
	</tr>
	<tr>
	<td colspan="2"><?= $row[postdata]?></td>
	</tr>
</table>
<br/>


</body></html>
