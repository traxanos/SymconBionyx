<?php

declare(strict_types=1);

include_once __DIR__ . '/../libs/constants.php';

class BionyxConfigurator extends IPSModule
{
    public function Create()
    {
        parent::Create();
        $this->RegisterPropertyInteger('CategoryID', 0);
        $this->ConnectParent(BIONYX_CLOUD_GUID);
    }

    public function Destroy()
    {
        parent::Destroy();
    }

    public function ApplyChanges()
    {
        $this->RegisterMessage(0, IPS_KERNELSTARTED);

        parent::ApplyChanges();

        if (IPS_GetKernelRunlevel() != KR_READY) {
            return;
        }
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
        if (!$this->HasActiveParent()) {
            return json_encode($form);
        }

        $location = $this->GetCategoryPath($this->ReadPropertyInteger('CategoryID'));
        $systems = $this->getSystems();
        $values = [];
        foreach ($systems as $system) {
            if (!$system->ownSystem) {
                continue;
            }
            $instanceID = $this->GetSystemInstance($system->systemId);
            $values[] = [
                'systemID'   => $system->systemId,
                'name'       => $system->systemName,
                'instanceID' => $instanceID,
                'create'     => [
                    'moduleID'      => BIONYX_SYSTEM_GUID,
                    'configuration' => [
                        'systemID' => $system->systemId
                    ],
                    'location' => $location
                ]
            ];
        }
        $form->actions[0]->values = $values;
        return json_encode($form);
    }

    private function KernelReady()
    {
        $this->ApplyChanges();
    }

    private function GetCategoryPath(int $CategoryID): array
    {
        if ($CategoryID === 0) {
            return [];
        }
        $path[] = IPS_GetName($CategoryID);
        $parentID = IPS_GetObject($CategoryID)['ParentID'];
        while ($parentID > 0) {
            $path[] = IPS_GetName($parentID);
            $parentID = IPS_GetObject($parentID)['ParentID'];
        }
        return array_reverse($path);
    }

    private function GetSystemInstance($systenID)
    {
        $instanceID = 0;
        $instanceIDs = IPS_GetInstanceListByModuleID(BIONYX_SYSTEM_GUID);
        foreach ($instanceIDs as $id) {
            if (IPS_GetProperty($id, 'systemID') == (string) $systenID) {
                $instanceID = $id;
            }
        }
        return $instanceID;
    }

    private function requestDataFromParent($endpoint)
    {
        return $this->SendDataToParent(json_encode(
            [
                'DataID'   => BIONYX_CLOUD_DATA_GUID,
                'Endpoint' => $endpoint
            ]
        ));
    }

    private function getSystems(): array
    {
        $result = json_decode($this->requestDataFromParent('systems'));
        if (!$result) {
            return [];
        }
        return $result;
    }
}