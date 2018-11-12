<?php
require "vendor/autoload.php";

//use BayGroup\OAuth1\OAuth;
//  $data = new OAuth('ZVM0N2HSTIV8VSGK6IOKWRBUBQXOPH','BW1MOKHIEKCXIVPHQQYLFZU4HF3JML');
//  $data->setRequestTokenUrl('https://api.xero.com/oauth/RequestToken');
//  $data->test();
//  var_dump($data);

     /*$data = new \BayGroup\OAuth1\OAuth("ZVM0N2HSTIV8VSGK6IOKWRBUBQXOPH","BW1MOKHIEKCXIVPHQQYLFZU4HF3JML");
     $data->to("https://api.xero.com/oauth/RequestToken");*/
     $data = new \BayGroup\OAuth1\OAuth1("OZIBU1YYBNGYSHKMSKCW47PYXWN6Q8","GOGZJLQ7DNHSL0XFDJ5DQA2X7W0XDM");
     $data->getRequestToken("https://api.xero.com/oauth/RequestToken","http://oauth1.local/test");
     //var_dump($data->oauth_token);
    //$data->getAuthorize('https://api.xero.com/oauth/Authorize');
exit();


  $parameters =
    [ //"oauth_callback" => "http://syncserver.capitalbay.local/xero/xero-import",
        "oauth_consumer_key" => "ZVM0N2HSTIV8VSGK6IOKWRBUBQXOPH",//$this->oauth_consumer_key,
        "oauth_signature_method" => "HMAC-SHA1",//$this->oauth_signature_method,
        "oauth_timestamp" => time(),//$this->timestamp,
        "oauth_nonce" => md5(mt_rand()),//$this->nonce2,
        "oauth_version" => "1.0",//$this->timestamp2
            // ---------------------------------------
         "oauth_token" => "PC1CAVDGGERBW85RYH6P8NJXT5POKB",
        //fromDate=2018-10-31&toDate=2018-10-01
        // "fromDate" => "2018-10-01",
         //"toDate" => "2018-10-31"
         "oauth_verifier" => "3557740"//oauth_verifier=5565322
    ];

     $parameters = array_flip($parameters);
     //var_dump($parameters );
     asort($parameters );
     $parameters = array_flip($parameters);

     $parameter_string = '';
     foreach($parameters as $key => $value)
     {
         $value = utf8_encode($value);
         if($key == "oauth_callback")
             $value = urlencode($value);
         $parameter_string .= urlencode(utf8_encode($key.'=')).urlencode($value).urlencode(utf8_encode('&'));
     }

     $parameter_string = substr($parameter_string,0,-3);
     var_dump('parameter string',$parameters,$parameter_string);

    //$url = "https://api.xero.com/oauth/RequestToken";
    $url = "https://api.xero.com/oauth/AccessToken";
    //$url = "https://api.xero.com/api.xro/2.0/Invoices";
    //$url = "https://api.xero.com/api.xro/2.0/Reports/ProfitAndLoss";

     $signature_base_string = "GET&".urlencode($url).'&'.$parameter_string;
     var_dump('signature base string',$signature_base_string);
     $key2 = urlencode('BW1MOKHIEKCXIVPHQQYLFZU4HF3JML').'&'.urlencode('ZMBA8RQKBGPFMCRB8P2HGAXT0QQJNJ');
     $signature = urlencode(base64_encode(hash_hmac('sha1',$signature_base_string,$key2 ,true)));

$parameters['oauth_signature'] = $signature;


     $parameters = array_flip($parameters);
     asort($parameters);
     $parameters = array_flip($parameters);
     var_dump('hehe array',$parameters);
     $url_full = $url.'?';
     $headers = 'OAuth ';
     foreach($parameters as $key => $value)
     {
         if($key == "oauth_callback")
             $url_full .= $key.'='.urlencode($value).'&';
         else{
             $url_full .= $key.'='.$value.'&';
         }

         $headers .= $key.'="'.$value.'",';
     }

     $url_full = substr($url_full,0,-1);
     $headers = substr($headers,0,-1);

     var_dump('url_full',$url_full,'headers',$headers);

     var_dump($signature );
     var_dump($key2,"haha");
     exit();
