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

div#choice {
  position: absolute;
  width:100%;
  height:100%;
  background-color:#EEEEEE;
}

p#normal {font-size:20px;}

</style>

<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<link rel="Shortcut Icon" href="/xtu.ico">
<title>[GNP3C]千兆网络的数据包捕获及内容监控</title>
</head>
<body>
<?php 
session_start();
$_SESSION["hostname"]  = $hostname	= $_POST["hostname"];
$_SESSION["username"]  = $username  = $_POST["username"];
$_SESSION["password"]  = $password  = $_POST["password"];
$_SESSION["database"]  = $database  = $_POST["database"];

$link = mysql_connect($hostname, $username, $password);	
if ( !$link )
{
  echo('<strong>Could not connect to MySQL! </strong><br/><br/>');
  echo mysql_error();
  echo('<br/><br/>');
  echo('<a href="login.php">Return Login</a>');
  exit();
}

$db_selected = mysql_select_db($database, $link);
if ( !$db_selected )
{
  echo('<strong>MySQL selects database error! </strong><br/><br/>');
  echo mysql_error();
  echo('<br/><br/>');
  echo('<a href="login.php">Return Login</a>');
  exit();
}
?>

<div id="container">
	<h2>千兆网络数据包解析及内容监控<br />
			应用列表
	</h2> 
<hr />
	<div id = "choice">
	<ul>
		<li> 
		<p id = "normal" style = "font-size: 12px">
			<a style= "text-decoration:none; font-size: 22px;" target="_blank" href = "email_list.php">邮件监控<a> 
			&nbsp;
			&nbsp;
			&nbsp;
			&nbsp;
			根据用户所给关键词,对邮件主题或者邮件内容进行索引，获取与用户所给关键词相匹配的邮件列表
		</p>
		</li>
		<li>
		<p id = "normal" style = "font-size: 12px">
			<a style= "text-decoration:none; font-size: 22px;" target="_blank" href = "web_analysis.php">Web监控<a> 
			&nbsp;
			&nbsp;
			&nbsp;
			追踪用户给定IP地址的上网过程
		</p>
		</li>
	</ul>
	</div>
</div>

</body>
<html>
