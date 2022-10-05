<?php

declare(strict_types=1);

include_once __DIR__ . '/../libs/constants.php';
include_once __DIR__ . '/../libs/WebOAuthModule.php';

class BionyxCloud extends WebOAuthModule
{
    public function __construct($InstanceID)
    {
        parent::__construct($InstanceID, BIONYX_OAUTH_IDENTIFIER);
    }

    public function Create()
    {
        parent::Create();

        $this->RegisterPropertyString('SocketIP', (count(Sys_GetNetworkInfo()) > 0) ? Sys_GetNetworkInfo()[0]['IP'] : '');
        $this->RegisterPropertyInteger('SocketPort', 3777);

        $this->RegisterAttributeString('Token', '');
    }

    public function ApplyChanges()
    {
        //Never delete this line!
        parent::ApplyChanges();

        $this->CheckStatus();
    }

    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        $this->SendDebug(__FUNCTION__, $TimeStamp . ', SenderID: ' . $SenderID . ', Message: ' . $Message . ', Data: ' . print_r($Data, true), 0);
        if (!empty($Data)) {
            foreach ($Data as $key => $value) {
                $this->SendDebug(__FUNCTION__, 'Data[' . $key . '] = ' . json_encode($value), 0);
            }
        }
        switch ($Message) {
            case IPS_KERNELSTARTED:
                $this->KernelReady();
                break;

        }
    }

    public function GetConfigurationForm()
    {
        $form = json_decode(file_get_contents(__DIR__ . '/form.json'));
        $form->elements[0]->image = BIONYX_IMAGE;

        $options = [];
        $networkInfo = Sys_GetNetworkInfo();
        for ($i = 0; $i < count($networkInfo); $i++) {
            $options[] = [
                'caption' => $networkInfo[$i]['IP'],
                'value'   => $networkInfo[$i]['IP']
            ];
        }
        $form->elements[3]->options = $options;
        return json_encode($form);
    }

    public function Authorize()
    {
        return 'https://' . BIONYX_OAUTH_SERVER . '/authorize/' . BIONYX_OAUTH_IDENTIFIER . '?username=' . urlencode(IPS_GetLicensee());
    }

    public function RequestStatus()
    {
        echo $this->FetchData('https://' . BIONYX_OAUTH_SERVER . '/forward');
    }

    public function Sync()
    {
        $this->FetchSystems();
        return 'Done';
    }

    public function FetchSystems()
    {
        $data = '[
            {
                "systemName": "Mein Zuhause 1",
                "systemId": "70346146-A211-53C5-9604-6C79173CE18B",
                "ownSystem": true
            },
            {
                "systemName": "Mein Zuhause 2",
                "systemId": "AF3FE5DD-3EC6-AB73-6365-71B57E4C0053",
                "ownSystem": true
            },
            {
                "systemName": "Mein Zuhause 3",
                "systemId": "AF3FE5DDD-3EC6-AB73-6365-71B57E4C0053",
                "ownSystem": false
            }
        ]';

        $systems = json_decode($data);
        foreach ($systems as $system) {
            $data = [
                'DataID'     => BIONYX_SYSTEM_DATA_GUID,
                'SystemID'   => (string) $system->systemId,
                'SystemName' => (string) $system->systemName,
                'OwnSystem'  => (string) $system->ownSystem
            ];
            $this->SendDataToChildren(json_encode($data));
        }
        return $systems;
    }

    public function ForwardData($JSONString)
    {
        $this->SendDebug(__FUNCTION__, $JSONString, 0);
        $data = json_decode($JSONString);
        switch ($data->Endpoint) {
            case 'systems':
                $result = $this->FetchSystems();
                break;

            default:
                $this->SendDebug(__FUNCTION__, 'Invalid endpoint: ' . $data->Endpoint, 0);
                $result = '';
                break;
        }
        $this->SendDebug(__FUNCTION__, json_encode($result), 0);
        return json_encode($result);
    }

    /**
     * This function will be called by the OAuth control. Visibility should be protected!
     */
    protected function ProcessOAuthData()
    {

        //Lets assume requests via GET are for code exchange. This might not fit your needs!
        if ($_SERVER['REQUEST_METHOD'] == 'GET') {
            if (!isset($_GET['code'])) {
                die('Authorization Code expected');
            }

            $token = $this->FetchRefreshToken($_GET['code']);

            $this->SendDebug('ProcessOAuthData', "OK! Let's save the Refresh Token permanently", 0);

            $this->WriteAttributeString('Token', $token);
            $this->CheckStatus();
        } else {

            //Just print raw post data!
            echo file_get_contents('php://input');
        }
    }

    private function FetchRefreshToken($code)
    {
        $this->SendDebug('FetchRefreshToken', 'Use Authentication Code to get our precious Refresh Token!', 0);

        //Exchange our Authentication Code for a permanent Refresh Token and a temporary Access Token
        $options = [
            'http' => [
                'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
                'method'  => 'POST',
                'content' => http_build_query(['code' => $code])
            ]
        ];
        $context = stream_context_create($options);
        $result = file_get_contents('https://' . BIONYX_OAUTH_SERVER . '/access_token/' . BIONYX_OAUTH_IDENTIFIER, false, $context);

        $data = json_decode($result);

        if (!isset($data->token_type) || $data->token_type != 'Bearer') {
            die('Bearer Token expected');
        }

        //Save temporary access token
        $this->FetchAccessToken($data->access_token, time() + $data->expires_in);

        //Return RefreshToken
        return $data->refresh_token;
    }

    public function PseudoToken()
    {
        $this->SetBuffer('AccessToken', json_encode(['Token' => 'PseudoToken', 'Expires' => 0]));
        $this->WriteAttributeString('Token', 'PseudoToken');
        $this->CheckStatus();
        return 'PseudoToken';
    }

    public function ResetToken()
    {
        $this->WriteAttributeString('Token', '');
        $this->CheckStatus();
        return 'ResetToken';
    }

    private function FetchAccessToken($Token = '', $Expires = 0)
    {

        //Exchange our Refresh Token for a temporary Access Token
        if ($Token == '' && $ $Expires == 0) {

            //Check if we already have a valid Token in cache
            $data = $this->GetBuffer('AccessToken');
            if ($data != '') {
                $data = json_decode($data);
                if (time() < $data->Expires) {
                    $this->SendDebug('FetchAccessToken', 'OK! Access Token is valid until ' . date('d.m.y H:i:s', $data->Expires), 0);
                    return $data->Token;
                }
            }

            $this->SendDebug('FetchAccessToken', 'Use Refresh Token to get new Access Token!', 0);

            //If we slipped here we need to fetch the access token
            $options = [
                'http' => [
                    'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
                    'method'  => 'POST',
                    'content' => http_build_query(['refresh_token' => $this->ReadAttributeString('Token')])
                ]
            ];
            $context = stream_context_create($options);
            $result = file_get_contents('https://' . $this->oauthServer . '/access_token/' . $this->oauthIdentifer, false, $context);

            $data = json_decode($result);

            if (!isset($data->token_type) || $data->token_type != 'Bearer') {
                die('Bearer Token expected');
            }

            //Update parameters to properly cache it in the next step
            $Token = $data->access_token;
            $Expires = time() + $data->expires_in;

            //Update Refresh Token if we received one! (This is optional)
            if (isset($data->refresh_token)) {
                $this->SendDebug('FetchAccessToken', "NEW! Let's save the updated Refresh Token permanently", 0);

                $this->WriteAttributeString('Token', $data->refresh_token);
            }
        }

        $this->SendDebug('FetchAccessToken', 'CACHE! New Access Token is valid until ' . date('d.m.y H:i:s', $Expires), 0);

        //Save current Token
        $this->SetBuffer('AccessToken', json_encode(['Token' => $Token, 'Expires' => $Expires]));
        
        //Return current Token
        return $Token;
    }

    private function CheckStatus() {
        if ($this->ReadAttributeString('Token') != '') {
            $this->UpdateFormField('Status', 'caption', $this->Translate('Authorized'));
            $this->SetStatus(102);
        } else {
            $this->UpdateFormField('Status', 'caption', $this->Translate('Unauthorized'));
            $this->SetStatus(104);
        }
    }

    private function FetchData($url)
    {
        $opts = [
            'http'=> [
                'method'        => 'POST',
                'header'        => 'Authorization: Bearer ' . $this->FetchAccessToken() . "\r\n" . 'Content-Type: application/json' . "\r\n",
                'content'       => '{"JSON-KEY":"THIS WILL BE LOOPED BACK AS RESPONSE!"}',
                'ignore_errors' => true
            ]
        ];
        $context = stream_context_create($opts);

        $result = file_get_contents($url, false, $context);

        if ((strpos($http_response_header[0], '200') === false)) {
            echo $http_response_header[0] . PHP_EOL . $result;
            return false;
        }

        return $result;
    }
}