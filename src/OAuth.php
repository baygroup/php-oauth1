<?php
namespace BayGroup\OAuth1;

class OAuth{

    protected $oauth_consumer_key;

    protected $oauth_consumer_secret;

    protected $oauth_token;

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

    protected $parameter;


    /**
     * OAuth constructor.
     *
     * @param $oauth_consumer_key
     * @param $oauth_consumer_secret
     * @param string $oauth_signature_method
     * @param string $oauth_version
     */
    public function __construct($oauth_consumer_key,$oauth_consumer_secret,$oauth_signature_method = 'HMAC-SHA1',$oauth_version = '1.0')
    {
        $this->oauth_consumer_key = $oauth_consumer_key;
        $this->oauth_consumer_secret = $oauth_consumer_secret;
        $this->oauth_signature_method = strtoupper($oauth_signature_method);
        $this->oauth_version = $oauth_version;
        $this->combined_consumer_key = urlencode(utf8_encode($this->oauth_consumer_secret)).'&';

    }

    public function oauth_list_parameter()
    {
        return [
            'oauth_consumer_key',
            'oauth_token',
            'oauth_signature_method',
            'oauth_signature',
            'oauth_timestamp',
            'oauth_nonce',
            'oauth_version'
        ];
    }

    public function oauth_list_value_parameter()
    {
        return [
            'oauth_consumer_key' => $this->oauth_consumer_key,
            'oauth_token' => $this->oauth_token,
            'oauth_signature_method' => $this->oauth_signature_method,
            'oauth_signature' => '',
            'oauth_timestamp' => $this->oauth_timestamp,
            'oauth_nonce' => $this->oauth_nonce,
            'oauth_version' => $this->oauth_version
        ];
    }

    public function setRequesToken($url)
    {
        $this->request_token_url = $url;
        return $this;
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

    public function setParameter(array $parameter)
    {
        $this->parameter = $parameter;
        return $this;
    }

    public function orderByLexicographicalOrderingArray(array $array)
    {
        $array = array_filter($array);
        $this->isAssociativeArray($array);
        $array = array_flip($array);
        asort($array);
        $array = array_flip($array);

        return $array;
    }

    public function to($url,array $parameter = [])
    {
        var_dump($url);
        $base_string_signature = $this->generateSignatureBaseString("GET",$url);
        $signature = $this->generateSignature("sha1",$base_string_signature,$this->combined_secret);
        $this->parameter = $this->orderByLexicographicalOrderingArray($this->parameter);
        $authorization_header = $this->generateAuthorizationHeader($this->parameter);
        var_dump($base_string_signature, $this->parameter,$signature,$authorization_header);

    }

    public function get()
    {

    }

    public function generateSignatureBaseString($method,$url_without_parameter,array $request_parameter = [])
    {
        $this->setNewNonce()->setNewTime();

        $request_parameter = $request_parameter + $this->oauth_list_value_parameter();
        $request_parameter = $this->orderByLexicographicalOrderingArray($request_parameter);
        $this->parameter = $request_parameter;
        $request_parameter = $this->concatParameter($request_parameter);
        $signature_base_string = urlencode(utf8_encode($method)).'&'.urlencode(utf8_encode($url_without_parameter)).'&'.$request_parameter;
        return $this->signature_base_string = $signature_base_string;
    }

    public function generateSignature($signature_method,$signature_base_string,$combined_secret)
    {
        $this->oauth_signature = urlencode(base64_encode(hash_hmac($signature_method,$signature_base_string,$combined_secret,true)));
        $this->parameter['oauth_signature'] = $this->oauth_signature ;
        return $this->oauth_signature;
    }

    public function generateAuthorizationHeader(array $oauth_parameter)
    {
        $oauth_parameter = $this->onlyAuthorizationArray($oauth_parameter);
        $normalized_parameter =  $this->normalizeHeaderParameter($oauth_parameter);

        return $authorization_header = "OAuth ".$normalized_parameter;

    }

    public function onlyAuthorizationArray(array $array)
    {
        $array = array_filter($array);
        $array = array_flip($array);
        $oauth_parameter = $this->oauth_list_parameter();

        foreach($array as $key => $value)
        {
            if(!in_array($value,$oauth_parameter))
            {
                unset($array[$key]);
                continue;
            }
        }
        asort($array);
        $array = array_flip($array);

        return $array;
    }

    public function normalizeHeaderParameter(array $array)
    {
        $auth_header  = "";

        foreach($array as $key => $value)
        {
            $auth_header .= $key."=".'"'.$value.'"'.',';
        }

         return $auth_header = substr($auth_header,0,-1);
    }

    public function concatParameter(array $array)
    {
        $concat_string = "";

        foreach ($array as $key => $value)
        {
            $concat_string .= urlencode(utf8_encode($key)).urlencode('=').urlencode(utf8_encode($value)).urlencode('&');
        }

        $concat_string = substr($concat_string,0,-1);

        return $concat_string;
    }

}
