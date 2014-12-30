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
	word-wrap:break-all;
	text-align: left;
	padding: 10px;
}
div#content {
	font-size:18px;
	text-indent: 50;
	vertical-align: middle;
	white-space: normal;
	padding: 20px;
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
$sql = "select * from email where id=$id;";
$result = mysql_query($sql);
$row = mysql_fetch_array($result);
?>

<table id="content">
<caption bgcolor="#99bbbb" >
		<h2>主题 ：<?= $row[subject]?></h2>
  </caption>

	<tr>
	<td width="10%">发件人 : <?= $row[emailfrom]?></td>
	<td width="10%">收件人 : <?= $row[emailto]?></td>
	</tr>
	<tr>
	<td width="10%">时间 : <?= $row[time]?></td>
	</tr>
	<tr>
	<td colspan="2">&nbsp;</td>
	</tr>
	<tr>
	<td colspan="2">
    	<div id="content">
			<?= $row[content]?>
    	</div></td>
	</tr>
</table>
<br/>


</body></html>
