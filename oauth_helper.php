<?php

function _nonce()
{
    return md5(mt_rand());
}

function sign_hash_hmac($method,$raw_payload,$key,$raw_output = true)
{
    return hash_hmac($method, $raw_payload, $key, $raw_output );
}

function convertToOAuth1SignatureBaseString($method,$url,array $parameter)
{
    $method = strtoupper($method);

    $signature_base_string = $method.'&'.urlencode($url).'&';

    var_dump('signature base string incomplete',$signature_base_string );

    $params_string = urlencode(concatArrayParameterOAuth1Format($parameter));

    var_dump($params_string);

    $signature_base_string = $signature_base_string.$params_string;

    var_dump('signature base string',$signature_base_string,$params_string);

    return $signature_base_string;
}

function concatArrayParameterOAuth1Format($parameter)
{
    $params_string = '';

    foreach($parameter as $key => $value)
    {
        $params_string .= $key.'='.$value.'&';
    }

    return substr($params_string,0,-1);
}

//OAuth Lexicographical (Ordinal) Byte Value Ordering.

function ordByteSort($params, $delimiter="&"){

    // Delimit params: key1=value1,key2=value2...OR key1=value1&key2=value2 etc.
    $params = explode($delimiter, $params);
    $array = array();

    foreach($params as $index => $param){

        $keyval = explode("=", $param);

        // URL Encode params.
        array_push($array, array( 'key' => rawurlencode(trim($keyval[0])),'val' => rawurlencode(trim($keyval[1]) )));
    }

    // Unsorted array of strings to hold ASCII byte encodings.
    $ordBytes = array();

    foreach($array as $param) {

        $bytes_str ="";

        // Concatenate key+val pairs and expand to array of char bytes.
        $chars = str_split($param['key'].$param['value'],1);

        // Convert chars to string of ASCII in hex format.
        foreach($chars as $chr) {

            $bytes_str .= dechex(ord($chr));
        }

        // Now holds string of key+value in ASCII hex.
        array_push($ordBytes, $bytes_str);
    }

    // Sort hex strings, keep index.
    asort($ordBytes ,SORT_STRING);

    $retval = "";
    $len = count($array)-1;

    foreach($ordBytes as $index=>$value){

        // Build return string using the reordered index.
        $retval .= $array[$index]['key']."=".$array[$index]['val'];
        if($len--) $retval .= "&";
    }

    // Return key/value pairs with amazingly fresh indexing.
    return $retval;
}


