<?php

declare(strict_types=1);

include_once __DIR__ . '/../libs/constants.php';

class BionyxSystem extends IPSModule
{
    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyString('systemID', '');
        $this->RegisterPropertyString('hooks', '');
        $this->ConnectParent(BIONYX_CLOUD_GUID);
        $this->RegisterMessage(0, IPS_KERNELMESSAGE);
    }

    public function Destroy()
    {
        if (!IPS_InstanceExists($this->InstanceID)) {
            $systemId = $this->ReadPropertyString('systemID');
            $this->UnregisterHook('/hook/ekey/' . $this->InstanceID);
        }
        parent::Destroy();
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();

        $systemId = $this->ReadPropertyString('systemID');
        $this->SetReceiveDataFilter('.*' . $systemId . '.*');
        $this->RegisterVariableString('Name', 'Name');

        if (IPS_GetKernelRunlevel() == KR_READY) {
            $this->RegisterHook('/hook/ekey/system/' . $this->InstanceID);
        }
    }

    public function GetConfigurationForm()
    {
        $form = json_decode(file_get_contents(__DIR__ . '/form.json'));
        $form->elements[0]->image = BIONYX_IMAGE;
        return json_encode($form);
    }

    public function MessageSink($TimeStamp, $SenderID, $Message, $Data)
    {
        parent::MessageSink($TimeStamp, $SenderID, $Message, $Data);

        if ($Message == IPS_KERNELMESSAGE && $Data[0] == KR_READY) {
            $this->RegisterHook('/hook/ekey/system/' . $this->InstanceID);
        }
    }

    public function ReceiveData($JSONString)
    {
        $this->SendDebug('ReceiveData', $JSONString, 0);

        $data = json_decode($JSONString);
        if ($data->DataID == BIONYX_SYSTEM_DATA_GUID) {
            SetValueString($this->GetIDForIdent('Name'), $data->SystemName);
        }
    }

    protected function Test()
    {
    }

    protected function ProcessHookData()
    {
        $this->SendDebug(__FUNCTION__ . ' Incoming Data: ', print_r($_SERVER, true), 0);
        // Get content
        $data = file_get_contents('php://input');
        $this->SendDebug(__FUNCTION__ . ' Data: ', $data, 0);

        $response = [
            'status'  => true,
            '_env'    => $_ENV,
            '_get'    => $_GET,
            '_post'   => $_POST,
            '_server' => $_SERVER
        ];
        header('Content-Type: application/json');
        http_response_code(200);
        echo json_encode($response);
    }

    /**
     * Registers a WebHook to the WebHook control instance.
     *
     * @param $WebHook
     */
    private function RegisterHook($WebHook)
    {
        $ids = IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');
        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], 'Hooks'), true);
            $found = false;
            foreach ($hooks as $index => $hook) {
                if ($hook['Hook'] == $WebHook) {
                    if ($hook['TargetID'] == $this->InstanceID) {
                        return;
                    }
                    $hooks[$index]['TargetID'] = $this->InstanceID;
                    $found = true;
                }
            }
            if (!$found) {
                $hooks[] = ['Hook' => $WebHook, 'TargetID' => $this->InstanceID];
                $this->SendDebug(__FUNCTION__, 'WebHook was successfully registered', 0);
            }
            IPS_SetProperty($ids[0], 'Hooks', json_encode($hooks));
            IPS_ApplyChanges($ids[0]);
        }
    }

    private function UnregisterHook($WebHook)
    {
        $ids = IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B496-0D3F77AE9FE1}');
        if (count($ids) > 0) {
            $hooks = json_decode(IPS_GetProperty($ids[0], 'Hooks'), true);
            $found = false;
            $index = null;
            foreach ($hooks as $key => $hook) {
                if ($hook['Hook'] == $WebHook) {
                    $found = true;
                    $index = $key;
                    break;
                }
            }
            if ($found === true && !is_null($index)) {
                array_splice($hooks, $index, 1);
                IPS_SetProperty($ids[0], 'Hooks', json_encode($hooks));
                IPS_ApplyChanges($ids[0]);
                $this->SendDebug(__FUNCTION__, 'WebHook was successfully unregistered', 0);
            }
        }
    }
}