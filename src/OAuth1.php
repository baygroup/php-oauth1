<?php

namespace BayGroup\OAuth1;

use \Curl\Curl;

class OAuth1{

    protected $oauth_callback;

    protected $oauth_consumer_key;

    protected $oauth_consumer_secret;

    public $oauth_token;

    protected $oauth_token_secret;

    protected $oauth_version;

    protected $oauth_nonce;

    protected $oauth_timestamp;

    protected $combined_secret;

    protected $signature_base_string;

    protected $oauth_signature;

    protected $oauth_verifier;

    protected $request_token_url;

    protected $authorize_url;

    protected $access_token_url;

    protected $url;

    protected $authorization_header;

    protected $parameter;

    protected $oauth_expires_in;

    public function __construct($oauth_consumer_key,$oauth_consumer_secret,$oauth_signature_method = 'HMAC-SHA1',$oauth_version = '1.0')
    {
        $this->oauth_consumer_key = $oauth_consumer_key;
        $this->oauth_consumer_secret = $oauth_consumer_secret;
        $this->oauth_signature_method = strtoupper($oauth_signature_method);
        $this->oauth_version = $oauth_version;
        $this->combined_secret = urlencode(utf8_encode($this->oauth_consumer_secret)).'&';
    }

    public function setNewNonce()
    {
        $this->oauth_nonce =  md5(mt_rand());
        return $this;
    }

    public function setNewTime()
    {
        $this->oauth_timestamp = time();
    }

    public function setRequesTokenUrl($url)
    {
        $this->request_token_url = $url;
        return $this;
    }

    public function setAuthorizeUrl($url)
    {
        $this->authorize_url = $url;
        return $this;
    }

    public function setAccessTokenUrl($url)
    {
        $this->access_token_url = $url;
        return $this;
    }

    public function setUrl($url)
    {
        $this->url = $url;
        return $this;
    }

    public function setToken($value)
    {
        $this->oauth_token = $value;
        return $this;
    }

    public function setTokenSecret($value)
    {
        $this->oauth_token_secret = $value;
        $string = explode("&",$this->combined_secret);
        $this->combined_secret = $string[0].'&'.urlencode(utf8_encode($this->oauth_token_secret));
        return $this;
    }

    public function setOAuthVerifier($value)
    {
        $this->oauth_verifier = $value;
        return $this;
    }

    public function oauth_list_value_parameter()
    {
        return
            [
                "oauth_callback" => $this->oauth_callback,
                "oauth_consumer_key" => $this->oauth_consumer_key,
                'oauth_token' => $this->oauth_token,
                "oauth_signature_method" => $this->oauth_signature_method,
                'oauth_signature' => '',
                "oauth_timestamp" => $this->oauth_timestamp,
                "oauth_nonce" => $this->oauth_nonce,
                "oauth_version" => $this->oauth_version,
                "oauth_verifier" => $this->oauth_verifier
            ];

    }

    public function oauth_parameter()
    {
        return
            [
                "oauth_callback",
                "oauth_consumer_key",
                'oauth_token',
                "oauth_signature_method",
                'oauth_signature',
                "oauth_timestamp",
                "oauth_nonce",
                "oauth_version",
                //"oauth_verifier"
            ];
    }

    public function orderByLexicographicalOrderingArray(array $array)
    {
        $array = array_filter($array);
        $array = array_flip($array);
        asort($array );
        $array = array_flip($array);

        return $array;
    }

    public function concatParameter(array $array)
    {
        $parameter_string = '';
        foreach($array as $key => $value)
        {
            $value = utf8_encode($value);
            if($key == "oauth_callback")
                $value = urlencode($value);
            $parameter_string .= urlencode(utf8_encode($key.'=')).urlencode($value).urlencode(utf8_encode('&'));
        }

        $parameter_string = substr($parameter_string,0,-3);

        return $parameter_string;
    }

    public function generateSignatureBaseString($method,$url_without_parameter,$concat_parameter)
    {
        return $signature_base_string = $method."&".urlencode(utf8_encode($url_without_parameter)).'&'.$concat_parameter;
    }

    public function generateSignature($signature_method,$signature_base_string,$combined_secret)
    {
        $signature_method == null || $signature_method == "HMAC-SHA1"? $signature_method = 'sha1' : true ;
        return urlencode(base64_encode(hash_hmac($signature_method,$signature_base_string,$combined_secret ,true)));
    }

    public function generateAuthorizationHeader($parameters)
    {
        $parameters = array_flip($parameters);
        asort($parameters);
        $parameters = array_flip($parameters);
        $headers = 'OAuth ';

        foreach($parameters as $key => $value)
        {
            if(!in_array($key,$this->oauth_parameter()))
            {

                unset($parameters[$key]);
                continue;
            }
            $headers .= $key.'="'.$value.'",';
        }

        $headers = substr($headers,0,-1);

        return $headers;
    }

    public function processRequest($url,array $parameters = [],$request_type = "GET")
    {
        $this->setNewTime();
        $this->setNewNonce();
        $this->setUrl($url);

        $oauth_list_parameter =  $this->oauth_list_value_parameter();
        $parameters = $parameters  +  $oauth_list_parameter;
        $parameters = $this->orderByLexicographicalOrderingArray($parameters);
        $concat_parameters = $this->concatParameter($parameters);
        $this->signature_base_string = $this->generateSignatureBaseString($request_type,$this->url,$concat_parameters);
        $signature = $this->generateSignature($this->oauth_signature_method,$this->signature_base_string,$this->combined_secret);
        $parameters['oauth_signature'] = $signature;
        $authorization_header = $this->generateAuthorizationHeader($parameters);

        return $authorization_header;
    }

    public function getRequestToken($request_token_url,$callback_url)
    {

        $this->oauth_callback = $callback_url;
        $auth_header = $this->processRequest($request_token_url);
        $this->setRequesTokenUrl($request_token_url);

        $curl = $this->surf($request_token_url,$auth_header);
        parse_str($curl->response,$output);

        if(isset($output['oauth_problem']))
        {
            throw new OAuthException($output['oauth_problem'].','.$output['oauth_problem_advice']);
        }

        $this->setToken($output['oauth_token']);
        $this->setTokenSecret($output['oauth_token_secret']);
    }

    public function getAccessToken($access_token_url,$parameter = [])
    {
        $parameters = ["oauth_verifier" => $this->oauth_verifier] + $parameter;
        $this->authorization_header = $this->processRequest($access_token_url,$parameters);

        $query_string = $this->arrayToQueryString($parameters);
        $this->url = $this->url.'?'.$query_string;
        $curl = $this->surf($this->url ,$this->authorization_header);

        parse_str($curl->response, $output);

        if(isset($output['oauth_problem']))
        {
            throw new OAuthException($output['oauth_problem'].', '.$output['oauth_problem_advice']);
        }

        $this->setToken($output["oauth_token"]);
        $this->setTokenSecret($output["oauth_token_secret"]);
        $this->oauth_expires_in = $output["oauth_expires_in"];

    }

    public function getAuthorize($url)
    {
        $url = $url."?oauth_token=".$this->oauth_token;

        header("Location: ".$url);
        exit();
    }

    public function getOauthToken()
    {
        return $this->oauth_token;
    }

    public function getOAuthTokenSecret()
    {
        return $this->oauth_token_secret;
    }

    public function to($url,array $parameter = [])
    {

        $this->authorization_header = $this->processRequest($url,$parameter);
        $query_string_parameter = $this->arrayToQueryString($parameter);
        if(count($parameter))
            $this->url = $url.'?'.$query_string_parameter;
        else
            $this->url = $url;

        $curl = $this->surf($this->url,$this->authorization_header);

        return $curl;

    }

    public function surf($url,$auth_header)
    {
        $curl = new Curl();
        $curl->setHeader("Accept","application/json");
        $curl->setHeader("Authorization",$auth_header);
        $curl->get($url);

        return $curl;
    }

    public function arrayToQueryString(array $array)
    {
        $string = "";
        foreach($array as $key => $value)
        {
            $string .= $key.'='.urlencode($value).'&';
        }

        $string = substr($string,0,-1);

        return $string;
    }



}
