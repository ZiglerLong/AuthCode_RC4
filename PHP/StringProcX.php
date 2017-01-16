<?php   

function StringProcX($string, $operation = 'DECODE', $expiry = 0){
    $secret_key = '#*Merg^QaNy'; //加密key
    $ckey_length = 4;
    $key = md5(md5($secret_key)); //经过两轮MD5，防止彩虹表
    $keya = md5(substr($key, 0, 16));
    $keyb = md5(substr($key, 16, 16));
    $string = str_replace(array("[a]","[d]","[s]"), array("+","/","="), $string);
    
    $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)/*"long"*/) : '';
    
    $cryptkey = $keya.md5($keya.$keyc);
    $key_length = strlen($cryptkey);

    $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
    
    $string_length = strlen($string);
    $result = '';
    $box = range(0, 255);
    $rndkey = array();

    for($i = 0; $i <= 255; $i++) {
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
    }
    for($j = $i = 0; $i < 256; $i++) {
        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
    }
    for($a = $j = $i = 0; $i < $string_length; $i++) {
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    }
    if($operation == 'DECODE') {
        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {
            return substr($result, 26);
        } else {
            return '';
        }
    } else {
        $result = base64_encode($result);
        $result = str_replace(array("+","/","="), array("[a]","[d]","[s]"), $result);
        return $keyc.$result;
    }
}

header("Content-type: text/html; charset=utf-8");

if(isset($_GET["src"])){
	$str_original = strval($_GET["src"]);
	$str_encrypt = StringProcX($str_original,"ENCODE",0);
	$str_decrypt = StringProcX($str_encrypt);
	echo "<br/>原始字符串：",$str_original,'<br/>加密字符串：',$str_encrypt,'<br/>解密字符串：',$str_decrypt,'<br/>';
}elseif(isset($_GET['str'])){
    $str = StringProcX(strval($_GET['str']));
    echo '<br/>密文:'.$_GET['str'];
    echo '<br/>解密：<font color="red">',$str,'</font><br/>';
}


?>