<?php 
session_start();
$hostname = $_SESSION["hostname"];
$username = $_SESSION["username"]; 
$password = $_SESSION["password"];
$database = $_SESSION["database"];

$link = mysql_connect($hostname, $username, $password);	
$result = mysql_select_db($database, $link);
?>

<html>
<head>
<style type="text/css">
div#container {
	position: absolute;
	width:800px;
	left:50%;
	margin-left:-400px;
	margin-top:20px;
	visibility: visible;
}

div#title {
	position:relative;
	width:100%;
	font-size:36px;
	font-weight:bolder;
	text-align: center;
	font-style: normal;
	height: 50px;
	vertical-align: middle;
	visibility: visible;
	color: #000;
}

form#search {
	position:relative;
	width: 400px;
	left:100%;
	margin-left:-400px;
	visibility: visible;
	text-align: right;
}

table{
	font-family: verdana,arial,sans-serif;
	font-size:10px;
	color:#000000;
	border-width: 1px;
	border-color: #333333;
	border-collapse: collapse;
	word-break:break-all;
	word-wrap:break-all;
}

table td {
	border-width: 1px;
	padding: 4px;
	border-style: solid;
	border-color: #666666;
}

select#pages {
	position:relative;
	visibility: visible;
	vertical-align: middle;
}

div#select_page {
	font-size:14px;
	position: relative;
	height: 40px;
	visibility: visible;
	vertical-align: middle;
	text-align: center;
}

</style>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
</head>
  
<body>
<div id = "container">
  <div id = "title">
		邮件监控
	</div>
	<form id = "search" action="email_list.php" method="GET">
<?php 
	if ( $_GET['keyword'] )
		echo '<input type="text" name="keyword" value="'. $_GET['keyword']. '" />';
	else 
		echo '<input type="text" name="keyword" />';
	if ( $_GET['S'] == 'content' ) {
		echo '<input type="radio" name="S" value="subject" /> 主题';
		echo '<input type="radio" name="S" value="content" checked="checked" /> 内容';	
	} else {
		echo '<input type="radio" name="S" value="subject" checked="checked" /> 主题';
		echo '<input type="radio" name="S" value="content" /> 内容';
	}
?>	
		<input type="submit" value="搜索"/>
  </form>
	<hr />
<table width="100%"  style = "content-align:center"  bgcolor="#EEEEEE"><tr>
<td width="10%">序号</td>
<td width="20%">主题</td>
<td width="15%">发件人</td>
<td width="15%">收件人</td>
<td width="29%">内容</td>
<td width="11%">时间</td></tr>

<?php

$keyword = $_GET['keyword'];
$S       = $_GET['S'];

if( $_GET["page"] ) 
	$page = $_GET["page"];
else 
	$page = 1;
$page_size = 15;

if($keyword) { 
	if($S == "subject")
		$sql = "select * from email where subject like '%" .$keyword. "%'" ; 
	else 
		$sql = "select * from email where content like '%" .$keyword. "%'"; 
} 
else 
	$sql = "select * from email "; 
	

$result = mysql_query($sql, $link);
$amount = mysql_num_rows($result);
// 记算总共有多少页
if( $amount ){
   if( $amount < $page_size ){ $page_count = 1; }               
   if( $amount % $page_size ){                                  
       $page_count = (int)($amount / $page_size) + 1;           
   }else{
       $page_count = $amount / $page_size;                      
   }
}
else{
   $page_count = 0;
}
?>
<?php
$sql.= " order by id desc limit ".($page-1)*$page_size.", ".$page_size;
$result = mysql_query($sql);
$num = 1;
while($row = mysql_fetch_array($result)){
?>
<tr>
	<td width="10%"><a target="_blank" href="email_show.php?id=<? echo $row[id];?>"><?= ($page - 1 ) * $page_size + $num?></a></td>
	<td width="20%"><?= substr($row[subject], 0, 10)?></td>	
	<td width="15%"><?= $row[emailfrom]?></td>
	<td width="15%"><?= $row[emailto]?></td>
	<td width="29%"><?= substr($row[content], 0, 20)?></td>
	<td width="11%"><?= $row[time]?></td>
</tr>
<?php
$num = $num + 1;
}
?>
</table>
<hr/>

<div id="select_page">
<form id = "select" action="email_list.php" method="get">
<?php
// 翻页链接
$prev_page = '';
if( $page == 1 ){
   $prev_page .= '首页|上一页|';
}
else{
   $prev_page .= '<a href=?page=1&keyword='.$keyword.'&S='.$S.'>首页</a>|<a href=?page=';
   $prev_page .= ($page-1).'&keyword='.$keyword.'&S='.$S.'>上一页</a>|';
}
echo $prev_page;
?>

  <select name="page" id="pages">
<?php 
	$i = 1;
	while( $i <= $page_count ) {
		$opt = '';
		$opt .= '<option value="' . $i . '"';
		if ( $i == $page )
			$opt .= 'selected="selected"';
		$opt .= '>第'.$i.'页</option>';
		echo $opt;
		$i = $i + 1;
	}
	echo '<input type="hidden" name="keyword" value="'.$keyword.'" />';
	echo '<input type="hidden" name="S" value="'.$S.'" />';
?>  
  </select>
  <input type="submit" value="GO" />
<?php
$next_page = '';
if( ($page == $page_count) || ($page_count == 0) ){
   $next_page .= '|下一页|尾页';
}
else{
   $next_page .= '|<a href=?page='.($page+1).'&keyword='.$keyword.'&S='.$S;
   $next_page .= '>下一页</a>|<a href=?page='.$page_count.'&keyword='.$keyword.'&S='.$S.'>尾页</a>';
}
echo $next_page;
?>
 </form>
</div>

<?php
$page = $page +1;

?> 
</div>
</body></html>


