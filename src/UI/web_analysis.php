<html>
<head>
<style type="text/css">
div#container {
  position: absolute;
  width:800px;
  left:50%;
  margin-left:-400px;
  margin-top:20px;
}

div#title {
  width:100%;
  text-align: center;
}

form#search {
	position:relative;
	left:33%;
}

table{
    font-family: verdana,arial,sans-serif;
    font-size:15px;
    color:#000000;
    border-width: 1px;
    border-color: #333333;
    border-collapse: collapse;
    width:800px;
    word-break:break-all; 
		word-wrap:break-all;
}

td {
    border-width: 1px;
    padding: 4px;
    border-style: solid;
    border-color: #666666;
}
</style>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">

</head>
<body>

<div id = "title">
<h1>Web监控<h1>
</div>

<div id = "container">

	<form id = "search" action="web_analysis.php" method="post">
		关键字:
		<input type="text" name="keyword" />
		<input type="radio" name="type" value="srcip" checked="checked" /> IP地址 
		<input type="radio" name="type" value="postdata"/> 请求内容 
		<input type="submit" value="提交"/>
	</form>
<hr />

<?php
session_start();
$hostname = $_SESSION["hostname"];
$username = $_SESSION["username"]; 
$password = $_SESSION["password"];
$database = $_SESSION["database"];

$link = mysql_connect($hostname, $username, $password);	
$result = mysql_select_db($database, $link);

$keyword = $_POST['keyword'];
$type       = $_POST['type'];


if($keyword) { 
	switch ( $type  ) {
	case "srcip":
		$sql = "select * from web where srcip like '%" .$keyword. "%';"; 
		break;
	case "postdata":
		$sql = "select * from web where content like '%" .$keyword. "%';"; 
		break;
	default:
		$sql = "select * from web;";
	}
} 
else 
	$sql = "select * from web;"; 
	

$result = mysql_query($sql, $link);
$amount = mysql_num_rows($result);
echo '<p>共有'.$amount.'条结果</p>';

?>

<table style = "content-align:center"  bgcolor="#EEEEEE">
<tr>
	<td width="15%">序号</td>
	<td width="15%">源IP地址</td>
	<td width="60%">URL</td>
	<td width="10%">时间</td>
</tr>

<?php
#$sql .= " limit 0, 100"; 
#$result = mysql_query($sql, $link);
while($row = mysql_fetch_array($result)){
?>


<tr>
	<td width="15%">
		<a style="text-decoration:none" target="_blank" href="web_show.php?id=<? echo $row[id];?>"><?= $row[id]?></a>
	</td>
	<td width="15%"><?= $row[srcip]?></td>
	<td width="60%">
		<?php  //<a href="http://www.baidu.com">
			echo "<a style=\"text-decoration:none\" target=\"_blank\" href=\"http://" . $row[host] . $row[url] . "\">"
		?>
			http://<?= $row[host]?><?= substr($row[url], 0, 40)?> </a></td>
	<td width="10%"><?= $row[time]?></td>
</tr>

<?php
}
?> 
</table>
</div>
</body></html>


