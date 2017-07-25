

function Get-AuthToken {
    [CmdletBinding(DefaultParameterSetName="insecure")]
    param (
        [parameter(Mandatory,Position=0,ValueFromPipeLine,ParameterSetName="PSCredential")]
        [pscredential]$Credential,
        [parameter(Mandatory,position=0,ValueFromPipelineByPropertyName,ParameterSetName="secure")]
        [parameter(Mandatory,position=0,ValueFromPipelineByPropertyName,ParameterSetName="insecure")]
        [string]$Username,
        [parameter(Mandatory,Position=1,ValueFromPipelineByPropertyName,ParameterSetName="secure")]
        [securestring]$SecurePassword,
        [parameter(Mandatory,Position=1,ValueFromPipelineByPropertyName,ParameterSetName="insecure")]
        [string]$Password,
        [parameter()]
        [switch]$AuthToken
    )
    
    begin {}
    process {
        if ($PSCmdlet.ParameterSetName -ne "PSCredential") {
            if ($PSCmdlet.ParameterSetName -eq "insecure") {
                $SecurePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
            }

            $Credential = New-Object System.Management.Automation.PSCredential $Username, $SecurePassword
        }

        if ($AuthToken) {
           $bytestream = [System.Text.Encoding]::UTF8.GetBytes(("{0}:{1}" -f $Username, $Credential.GetNetworkCredential().Password))                
            $encoded = [System.Convert]::ToBase64String($bytestream)
            return $encoded
        } else {
            return $Credential
        }
    }
    end {}
}


function Get-RequestParameters {
    param()

    begin {}
    process {
        return @{
            Method = "Get"
            ContentType = "application/json"
            Headers = @{
                Accept = "application/json;charset=UTF-8"
                'X-Stream' = $true
            }
        }

    }
    end {}
}


function Connect-Neo4jServer {
    [CmdletBinding(DefaultParameterSetName="insecure")]
    param(
        [parameter(Mandatory,Position=0,ValueFromPipelineByPropertyName,ParameterSetName="PSCredential",DontShow)]
        [pscredential]$Credential=[pscredential]::Empty,
        [parameter(Mandatory,Position=0,ParameterSetName="insecure")]
        [parameter(Mandatory,Position=0,ParameterSetName="secure")]
        [string]$Username,
        [parameter(Mandatory,Position=1,ParameterSetName="insecure")]
        [string]$Password,
        [parameter(Mandatory,Position=1,ParameterSetName="secure")]
        [securestring]$SecurePassword,
        [parameter(ValueFromPipelineByPropertyName)]
        $Server="localhost",
        [Parameter(ValueFromPipelineByPropertyName)]
        $Port=7474
    )
    begin {
        if ($PSCmdlet.ParameterSetName -ne "PSCredential") {
            if ($PSCmdlet.ParameterSetName -eq "Secure") {
                $Credential = New-Object System.Management.Automation.PSCredential($Username,$SecurePassword)
            } else {
                $Credential = New-Object System.Management.Automation.PSCredential($Username,(ConvertTo-SecureString $Password -AsPlainText -Force))
            }
        }
        $authToken = Get-AuthToken $Credential -AuthToken
        $request = Get-RequestParameters
        $request.Add("Credential", $Credential)
        $request.Headers.Add("Authorized", ("Basic {0}" -f $authToken))
    }

    process {
        $result = Invoke-RestMethod  -Uri ("http://{0}:{1}/db/data/" -f $Server,$Port) @request -SessionVariable session
        $result | Add-Member NoteProperty Session $session
        $result | Add-Member NoteProperty AuthToken $authToken
        return $result
    }
    end {}
}


function Merge-NodeData {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,Position=0,ValueFromPipeline)]
        [string]$json,
        [parameter(Mandatory,Position=1)]
        $Connection
    )
    begin {
        $params = Get-RequestParameters
        $params.Method = "Post"
        $params.Headers.Add("Authorization",("Basic {0}" -f $Connection.AuthToken))
        $params.Add("WebSession",$connection.Session)
        $params.Add("Uri",$Connection.node)
    }
    process {
        $result = Invoke-RestMethod @params -Body $json
        return $result
    }
    end {}
}


function Set-NodeData {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,Position=0,ValueFromPipeline)]
        [string]$json,
        [parameter(Position=1)]
        [string]$Uri,
        [parameter(Position=2)]
        [string]$Method="Post",
        [parameter(Mandatory,Position=3)]
        $Connection        
    )
    begin {
        $params = Get-RequestParameters
        $params.Method = $Method
        $params.Headers.Add("Authorization",("Basic {0}" -f $Connection.AuthToken))
        $params.Add("Uri",$Uri)
        $params.Add("WebSession",$Connection.Session)     
    }
    process {
        return Invoke-RestMethod @params -Body $json
    }
    end {}
}


function main {
    $Connection = Connect-Neo4jServer -Username neo4j -Password neo4jtest 
    $Session = $Connection.Session

    #   

}


function New-Node {
    [CmdletBinding(DefaultParameterSetName="FileInfo")]
    param(
        [parameter(Mandatory,ValueFromPipeLine,ParameterSetName="DriveInfo")]
        [System.IO.DriveInfo]$Drive,
        [parameter(Mandatory,ValueFromPipeLine,ParameterSetName="FileInfo")]
        [System.IO.FileInfo]$File,
        [parameter(Mandatory,ValueFromPipeLine,ParameterSetName="DirectoryInfo")]
        [System.IO.DirectoryInfo]$Directory,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [int]$ParentId,
        [parameter(Mandatory)]
        $Connection
    )
    begin {}
    process {
        Switch ($PSCmdlet.ParameterSetName) {
            "DirectoryInfo" {
                $fsInfo = $Directory
            }
            "FileInfo" {
                $fsInfo = $File
            }
            "DriveInfo" {
                $fsInfo = $Drive
            }
        }

        $attributes = $fsInfo.PSObject.Properties.Where({$_.IsInstance}) | Get-ObjectProperty | ConvertTo-Serialized

        #$cypher = "MERGE (n:{0} {1})" -f $PSCmdlet.ParameterSetName, $attributes
        $response = Merge-NodeData -json $attributes -Connection $Connection
        $n = Set-NodeData -Uri $response.Labels -Method Post -json ('"{0}"' -f $PSCmdlet.ParameterSetName) -Connection $Connection

        $nodeId = $response.metadata.id

        return [PSCustomObject]@{
            NodeId = $nodeId
            ParentId = $ParentId
            Uri = $response.create_relationship
            Connection = $Connection
            Response = $response
        }

    }
    end {}
}


function New-Edge {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,Position=0,ValueFromPipelineByPropertyName)]
        [int]$NodeId,
        [parameter(Mandatory,Position=1,ValueFromPipelineByPropertyName)]
        [int]$ParentId,
        [parameter(Mandatory,Position=2,ValueFromPipelineByPropertyName)]
        [string]$Uri,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]
        $Connection,
        [parameter(Position=3)]
        [string]$Relationship="CHILD_OF"
    )
    begin {        
        $params = @{
            Method = "Post"
            Uri = ""
            Connection = ""
        }
    }
    process {
        $params.Uri = $uri
        $params.Connection = $Connection
        
        $json = @{
            to = ("{0}node/{1}" -f ($uri -split "node")[0],$ParentId)
            type = $Relationship
        } | ConvertTo-Json

        $response = Set-NodeData @params -json $json

        return [PSCustomObject]@{
            NodeId = $nodeId
            ParentId = $ParentId
            Connection = $Connection
            Respone = $response 
        }
    }
    end {}
}


function Get-Drives {
    [CmdletBinding()]
    param(
        [parameter(Position=0,ValueFromPipeLine,ValueFromPipelineByPropertyName)]
        [string]$Hostname=($env:COMPUTERNAME),
        [parameter(Mandatory)]
        $Connection
    )
    begin {
        $params = @{
            Connection = $Connection
            ParentId = 0
        }
    }
    process {
        $drives = [System.IO.DriveInfo]::GetDrives() 

        # update params with new DriveInfo node's id
        $params.ParentId = ($drives[1] | New-Node @params).NodeId
        $driveId = $params.ParentId

        $response = $drives[1].RootDirectory | New-Node @params
        # update params with new DirectoryInfo node's id
        $params.ParentId = $response.NodeId

        New-Edge -Relationship "IS" -NodeId $params.ParentId -ParentId $driveId -Uri $response.Response.create_relationship -Connection $Connection
        
        $drives[1].RootDirectory | Get-Folders @params

    }
    end {}
}


function Get-Folders {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,Position=0,ValueFromPipeline)]
        [Alias("RootDirectory")]
        [System.IO.DirectoryInfo]$Parent,
        [parameter(Mandatory,Position=1)]
        [int]$ParentId,
        [parameter(Mandatory)]
        $Connection
    )
    begin {
        $params = @{
            Connection = $Connection
            ParentId = $ParentId
        }
    }
    process {
        if (-Not $Parent.NodeId) {
            $Parent | Add-Member NoteProperty NodeId ($Parent | Get-NodeId)
        }
        #$Parent | Get-Files @params
        $Parent.GetDirectories().Where({$_.Mode -notlike "*s*"}).Foreach({
            $result = $_ | New-Node @params | New-Edge
            
            $_ | Get-Folders -Connection $Connection -ParentId $result.NodeId
        })
    }
    end {}
}


function Get-Files {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,Position=0,ValueFromPipeLine,ValueFromPipelineByPropertyName)]
        [System.IO.DirectoryInfo]$Parent,
        [parameter(Mandatory,Position=1,ValueFromPipelineByPropertyName)]
        [int]$ParentID,
        [parameter(Mandatory)]
        $Connection
    )
    begin {
        $params = @{
            Connection = $Connection
            ParentId = $ParentId
        }
    }
    process {
        if (-Not $Parent.NodeId) {
            $Parent | Add-Member NoteProperty NodeId ($Parent | Get-NodeId)
        }
        $files = $Parent.GetFiles()
        $NodeId = ($files | New-Node @params).NodeId
    }
    end {}
}

function Get-ObjectProperty {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]
        $Name,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]
        $Value=[string]::Empty,
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]
        $TypeNameOfValue
    )
    begin {}
    process {
        if ($Name -like "PS*") { return }
        switch -Wildcard ($TypeNameOfValue)  {
            'System.DateTime' {
               $Value = (([System.DateTimeOffset]($Value)).ToUnixTimeMilliseconds() / 1000).ToString()
            }            
            'System.Management.Automation.*' {
                return
            }
            default {
                $Value = $Value.ToString()
            }
        }
        return [PSCustomObject]@{
            Name = $Name
            Value = if([string]::IsNullOrEmpty($Value)) { [string]::Empty } else { $Value }            
        }
    }
    end {}
}

function ConvertTo-Serialized {
    [CmdletBinding()]
    param(
        [parameter(Mandatory,Position=0,ValueFromPipelineByPropertyName)]
        [string]$Name,
        [parameter(Position=1,ValueFromPipelineByPropertyName)]
        [string]$Value = [string]::Empty
    )
    begin {
        $properties = @{}
    }
    process {
        $properties.Add($Name,$Value)
    }
    end {
        return $properties | ConvertTo-Json
    }
}


<#
    Get drive/root folder (am I a drive?)

--> create node
|   get files 
|       create nodes
|       create relationships
|   get folders
|------       

#>