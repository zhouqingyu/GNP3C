<html>
<head>
<style type="text/css">
div#container {
  position: absolute;
  width:500px;
  height:220px;
  left:50%;
  top:50%;
  margin-left:-250px;
  margin-top:-200px;
}
div#header {
	background-color:#99bbbb;
	text-align: center;
}
div#login {
	background-color:#EEEEEE;
	width:100%;
	float:left;
	text-align: center;
}
h1 {margin-bottom:0;}
address#author {font-size:13px; text-align:right}
</style>
<link rel="Shortcut Icon" href="/xtu.ico">
</head>

<body>

<div id="container" >

<div id="header">
<h1>GNP3C Login</h1>
</div>

<div id="login">
<form action="gnp3c.php" method="POST">
<p> <strong>Hostname:</strong>
	<input type="text", name="hostname", value="localhost" /> 
</p>
<p> <strong>Username:</strong>
	<input type="text" name="username", value="root"> </input>
</p>
<p> <strong>Database:</strong>
	<input type="text" name="database", value="network_monitor"> </input>
</p>
<p> <strong>Password:</strong>
	<input type="password" name="password"> </input>
</p>
<p>
	<input type="submit" value="login">
</p>
</form>
</div>
<address id = "author">
	Author: Zhou Qingyu<br />
  Xiangtan University<br />
</address>
</div>

</body>
</html>

